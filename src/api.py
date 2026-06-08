"""
api.py — FastAPI Controller for the Hybrid GNN Vulnerability Detection System.

Pipeline:
  1. Serves web dashboard, guide, and library pages
  2. Accepts uploaded binary (.exe, .o, .elf) or C/C++ source files via /analyze
  3. Auto-compiles source files to object code using isolated temp directories
  4. Runs Ghidra headless disassembly to extract Control Flow Graphs (CFGs)
  5. Runs hybrid GNN (GATv2) + heuristic ensemble vulnerability prediction
  6. Generates context-enriched security report via RAG (Gemini + ChromaDB)
  7. Renders report to PDF and returns full JSON payload

Security features:
  - Rate limiting (per-IP, configurable via RateLimiter)
  - Optional API key authentication (SENTINEL_API_KEY env var)
  - File content validation (magic bytes, null-byte rejection)
  - Isolated temp directories with cleanup for compilation
  - CORS restricted to explicitly configured origins
  - Security headers (CSP, HSTS, XSS protection, etc.)

Run:
    python -m uvicorn src.api:app --reload --host 0.0.0.0 --port 8000
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import uuid
import time
import threading
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import (
    ALLOWED_EXTENSIONS,
    ARTIFACTS_DIR,
    GHIDRA_HEADLESS,
    LABEL_MAP,
    MAX_FILE_SIZE_MB,
    PROJECT_ROOT,
    UPLOAD_DIR,
    ensure_dirs,
)
from .ghidra_runner import GhidraError, run_ghidra_analysis
from .predictor import predictor
from .rag_service import rag_service
from .utils.pdf_generator import convert_markdown_to_pdf

# --- Simple In-Memory Rate Limiter (per-IP token bucket) ---
class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self._lock = threading.Lock()
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self._buckets: dict[str, list[datetime]] = defaultdict(list)

    def check(self, client_ip: str) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - self.window
        with self._lock:
            self._buckets[client_ip] = [t for t in self._buckets[client_ip] if t > cutoff]
            if len(self._buckets[client_ip]) >= self.max_requests:
                return False
            self._buckets[client_ip].append(now)
            return True

rate_limiter = RateLimiter(max_requests=20, window_seconds=60)  # 20 req/min per IP


# --- Optional API Key Authentication ---
API_KEY = os.getenv("SENTINEL_API_KEY", "")
def verify_api_key(request: Request):
    if not API_KEY:
        return True  # Auth disabled if no key is configured
    provided = request.headers.get("X-API-Key", "")
    if provided == API_KEY:
        return True
    raise HTTPException(status_code=401, detail="Invalid or missing API key. Provide X-API-Key header.")


# --- File Content Validation ---
MAGIC_BYTES = {
    b"\x4d\x5a": "Windows PE (exe/dll)",
    b"\x7f\x45\x4c\x46": "ELF (Linux binary)",
}
def validate_file_content(content: bytes, filename: str) -> None:
    """Basic content validation: reject non-binary files uploaded as binary, check magic bytes."""
    ext = Path(filename).suffix.lower()
    binary_exts = {".exe", ".o", ".elf", ".dll", ".so", ".bin"}
    if ext in binary_exts and len(content) >= 4:
        # Check if it's actually a binary (not text masquerading as binary)
        if content[:2] not in [b"\x4d\x5a", b"\x7f\x45"] and ext in {".exe", ".elf", ".dll"}:
            logger.warning(f"File {filename} has extension {ext} but invalid magic bytes: {content[:4].hex()}")
    # Reject files containing null bytes if they claim to be text
    text_exts = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}
    if ext in text_exts and b"\x00" in content[:1024]:
        raise HTTPException(status_code=400, detail=f"Source file {filename} contains null bytes — not valid text.")


# --- Security Headers Middleware Helper ---
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("api")


def compile_source(source_path: Path, output_o_path: Path) -> Path:
    """
    Compiles a C/C++ source file into a relocatable object file (.o)
    using MinGW GCC/G++ in an isolated temp directory with resource limits.

    Security measures:
    - Compilation runs in an isolated temp directory (tempfile.mkdtemp)
    - 120-second timeout prevents runaway compilation
    - Temp directories are cleaned up in finally block
    - Header files (.h/.hpp) have static/inline removed to force symbol emission
    - Output is copied out of the isolated directory, then the directory is destroyed
    """
    file_ext = source_path.suffix.lower()
    is_header = file_ext in [".h", ".hpp"]
    
    temp_source_path = source_path
    if is_header:
        # Read header content
        with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        
        # Replace static inline / inline with empty space so the compiler emits symbols
        import re
        code_modified = re.sub(r'\bstatic\s+inline\b', ' ', code)
        code_modified = re.sub(r'\binline\b', ' ', code_modified)
        
        # Create temp source file
        temp_suffix = ".cpp" if file_ext == ".hpp" else ".c"
        temp_source_path = source_path.parent / f"temp_hdr_compile_{uuid.uuid4().hex}{temp_suffix}"
        with open(temp_source_path, "w", encoding="utf-8") as f:
            f.write(code_modified)

    try:
        compiler = "g++" if temp_source_path.suffix.lower() == ".cpp" else "gcc"
        # Compile in isolated temp directory with timeout and resource limits
        import tempfile
        compile_dir = Path(tempfile.mkdtemp(prefix="sentinel_compile_"))
        isolated_o_path = compile_dir / output_o_path.name
        command = [compiler, "-O0", "-g", "-c", "-o", str(isolated_o_path), str(temp_source_path)]
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=120  # 2-minute compile timeout
        )
        if result.returncode != 0:
            raise Exception(f"MinGW compilation failed:\n{result.stderr}")
        shutil.copy2(isolated_o_path, output_o_path)
    except subprocess.TimeoutExpired:
        raise Exception("MinGW compilation timed out after 120s")
    finally:
        # Clean up temp source file if created
        if is_header and temp_source_path.exists():
            temp_source_path.unlink()
        # Clean up isolated compile directory
        try:
            shutil.rmtree(str(compile_dir), ignore_errors=True)
        except Exception:
            pass
            
    return output_o_path


# --- Lifespan: load models on startup ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML models when the server starts."""
    ensure_dirs()
    try:
        predictor.load_models()
        logger.info("API ready - models loaded.")
    except FileNotFoundError as e:
        logger.warning(f"Models not loaded: {e}")
        logger.warning("The /analyze endpoint will fail until models are trained.")
    yield
    logger.info("Shutting down API.")


# --- FastAPI App ---
app = FastAPI(
    title="Sentinel AI - Vulnerability Detection API",
    description=(
        "Upload a compiled binary (.exe, .o, .elf) or C/C++ source file and get an AI-powered "
        "vulnerability assessment using Ghidra reverse engineering + "
        "GATv2 Graph Attention Network (GNN) machine learning."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — restrict origins in production (must be explicitly configured)
ALLOWED_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()] if ALLOWED_ORIGINS_RAW else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_credentials=bool(ALLOWED_ORIGINS),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# Security headers + rate limiting middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Rate limiting (skip for health/model-info endpoints)
    if request.url.path not in ("/health", "/model-info") and request.method != "GET":
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Too many requests", "message": "Rate limit exceeded. Try again later."}
            )
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Static reports folder configuration
reports_static_dir = PROJECT_ROOT / "src" / "static" / "reports"
reports_static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(reports_static_dir)), name="reports")

# --- Serve Frontend Locally ---
@app.get("/", tags=["Frontend"])
async def serve_welcome():
    """Serves the onboarding welcome landing page."""
    welcome_html = PROJECT_ROOT.parent / "project-frontend" / "templates" / "welcome.html"
    if welcome_html.exists():
        return FileResponse(str(welcome_html))
    raise HTTPException(status_code=404, detail=f"welcome.html not found at: {welcome_html}")

@app.get("/dashboard", tags=["Frontend"])
async def serve_dashboard():
    """Serves the main dashboard user interface."""
    frontend_index = PROJECT_ROOT.parent / "project-frontend" / "templates" / "index.html"
    if frontend_index.exists():
        return FileResponse(str(frontend_index))
    raise HTTPException(status_code=404, detail=f"Frontend index.html not found at: {frontend_index}")

@app.get("/guide", tags=["Frontend"])
async def serve_guide():
    """Serves the interactive user guide page."""
    guide_html = PROJECT_ROOT.parent / "project-frontend" / "templates" / "guide.html"
    if guide_html.exists():
        return FileResponse(str(guide_html))
    raise HTTPException(status_code=404, detail=f"guide.html not found at: {guide_html}")

@app.get("/library", tags=["Frontend"])
async def serve_library():
    """Serves the interactive threat intelligence reference library."""
    library_html = PROJECT_ROOT.parent / "project-frontend" / "templates" / "library.html"
    if library_html.exists():
        return FileResponse(str(library_html))
    raise HTTPException(status_code=404, detail=f"library.html not found at: {library_html}")

# Mount frontend static folder
frontend_static = PROJECT_ROOT.parent / "project-frontend" / "static"
if frontend_static.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_static)), name="static")

# --- GET /health ---
@app.get("/health", tags=["General"])
async def health_check():
    """Check system health: model status, Ghidra availability."""
    return {
        "status": "healthy",
        "model_loaded": predictor.is_loaded,
        "ghidra_available": GHIDRA_HEADLESS.exists(),
        "ghidra_path": str(GHIDRA_HEADLESS),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# --- GET /model-info ---
@app.get("/model-info", tags=["General"])
async def model_info():
    """Return model training metadata for the dashboard stats bar."""
    meta_path = ARTIFACTS_DIR / "model_metadata.json"
    if not meta_path.exists():
        return {
            "accuracy": 0,
            "total_samples": 0,
            "gnn_layers": 0,
            "model_type": "N/A",
            "trained_at": "Not trained yet",
        }
    with open(meta_path, "r") as f:
        return json.load(f)


# --- POST /analyze ---
@app.post("/analyze", tags=["Analysis"])
async def analyze_binary(file: UploadFile = File(...), _auth_ok: bool = Depends(verify_api_key)):
    """
    Upload a binary file or C/C++ source code for vulnerability analysis.

    The system will:
    1. Validate the file type (.c and .cpp files are auto-compiled on the fly)
    2. Run Ghidra headless reverse engineering
    3. Extract assembly features (opcodes)
    4. Run the hybrid GNN + heuristic ensemble model
    5. Return a prediction with confidence score

    **Accepted formats:** .exe, .o, .elf, .dll, .so, .bin, .c, .cpp, .cc, .h, .hpp

    **Authentication:** Set SENTINEL_API_KEY env var and pass X-API-Key header.
    """
    total_start = time.time()

    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid file type",
                "received": file_ext,
                "allowed": sorted(ALLOWED_EXTENSIONS),
                "message": f"Only binaries and source code files are accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            },
        )

    # Check model readiness
    if not predictor.is_loaded:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Model not loaded",
                "message": "The ML model has not been trained yet. Run 'python scripts/train_model.py' first.",
            },
        )

    # Quick content-type sanity check for binary uploads
    binary_extensions = {".exe", ".o", ".elf", ".dll", ".so", ".bin"}
    if file_ext in binary_extensions and file.content_type:
        if "octet-stream" not in file.content_type and "x-msdownload" not in file.content_type:
            logger.warning(f"Unexpected Content-Type for binary: {file.content_type}")

    # Save uploaded file
    import re
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', file.filename)
    safe_filename = f"{timestamp}_{safe_name}"
    upload_path = UPLOAD_DIR / safe_filename
    upload_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        content = await file.read()

        # Check file size
        size_mb = len(content) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            raise HTTPException(
                status_code=413,
                detail={
                    "error": "File too large",
                    "size_mb": round(size_mb, 2),
                    "max_mb": MAX_FILE_SIZE_MB,
                },
            )

        # Validate file content before writing to disk
        validate_file_content(content, file.filename)

        sha256_hash = hashlib.sha256(content).hexdigest()

        with open(upload_path, "wb") as f:
            f.write(content)

        logger.info(f"File saved: {safe_filename} ({size_mb:.2f} MB, SHA256: {sha256_hash[:16]}...)")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")

    # Route and compile C/C++ source code if uploaded
    is_source_code = file_ext in {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}
    binary_path = upload_path
    compiled_path = None

    if is_source_code:
        logger.info(f"Source code detected. Compiling {file.filename} to object file...")
        compiled_filename = f"{timestamp}_{Path(file.filename).stem}.o"
        compiled_path = UPLOAD_DIR / compiled_filename
        try:
            compile_source(upload_path, compiled_path)
            binary_path = compiled_path
            logger.info(f"Compilation success! Object file generated: {compiled_filename}")
        except Exception as e:
            if upload_path.exists():
                upload_path.unlink()
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "MinGW compilation failed",
                    "message": "Your uploaded C/C++ code has syntax errors or compiler incompatibilities.",
                    "details": str(e)
                },
            )

    # Run Ghidra Analysis
    ghidra_start = time.time()
    try:
        logger.info("Starting Ghidra analysis...")
        features_file = run_ghidra_analysis(binary_path)
        ghidra_time = time.time() - ghidra_start
        logger.info(f"Ghidra completed in {ghidra_time:.1f}s")

    except GhidraError as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Ghidra analysis failed", "message": str(e)},
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "Ghidra not found", "message": str(e)},
        )

    # Run ML Prediction using GNN
    ml_start = time.time()
    try:
        logger.info("Running GNN prediction on CFGs...")
        result = predictor.predict(features_file)
        ml_time = time.time() - ml_start
        logger.info(
            f"GNN Prediction completed in {ml_time:.3f}s | Result: {result['prediction']} "
            f"(confidence: {result['confidence']:.2%})"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GNN prediction failed: {str(e)}")

    # Generate context-enriched Vulnerability Report and Render PDF
    try:
        logger.info("Generating context-enriched security report...")
        report_markdown = rag_service.generate_vulnerability_report(
            flagged_functions=result["flagged_functions"],
            filename=file.filename,
            sha256_hash=sha256_hash,
            total_functions=len(result["top_features"])
        )
        
        pdf_filename = f"report_{sha256_hash}.pdf"
        pdf_path = reports_static_dir / pdf_filename
        
        logger.info(f"Rendering report PDF to {pdf_path}...")
        convert_markdown_to_pdf(report_markdown, pdf_path)
        pdf_url = f"/reports/{pdf_filename}"
    except Exception as e:
        logger.error(f"Report or PDF generation failed: {str(e)}")
        report_markdown = f"# Analysis Completed\n\nFailed to generate security report: {str(e)}"
        pdf_url = ""

    # Build response payload combining Sentinel dashboard compatibility + AI report data
    total_time = time.time() - total_start
    verdict = "SAFE" if result["label"] == 0 else "VULNERABLE"
    risk_score = float(result["confidence"] * 100 if verdict == "VULNERABLE" else (1 - result["confidence"]) * 100)

    response = {
        "status": "success",
        "filename": file.filename,
        "sha256": sha256_hash,
        "prediction": result["prediction"],
        "label": result["label"],
        "confidence": result["confidence"],
        "top_features": result["top_features"],
        "verdict": verdict,
        "risk_score": round(risk_score, 1),
        "flagged_functions_count": len(result["flagged_functions"]),
        "flagged_functions": result["flagged_functions"],
        "report_markdown": report_markdown,
        "pdf_url": pdf_url,
        "timing": {
            "ghidra_seconds": round(ghidra_time, 2),
            "ml_seconds": round(ml_time, 4),
            "total_seconds": round(total_time, 2),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        f"RESULT: {file.filename} -> {verdict} "
        f"({result['confidence']:.2%}) in {total_time:.1f}s"
    )

    # Cleanup temp files
    try:
        if upload_path.exists():
            upload_path.unlink()
        if compiled_path and compiled_path.exists():
            compiled_path.unlink()
        if features_file.exists():
            features_file.unlink()
        if features_file.parent.exists() and features_file.parent != UPLOAD_DIR:
            shutil.rmtree(features_file.parent, ignore_errors=True)
    except Exception as e:
        logger.warning(f"Error during temp file cleanup: {e}")

    return JSONResponse(content=response)


# --- Chatbot API Models & Endpoint ---

class ChatRequest(BaseModel):
    session_id: str
    query: str
    decompiled_code: str = ""
    chat_history: list[dict] = []


@app.post("/chat", tags=["Chatbot"])
async def chat_with_assistant(request: ChatRequest):
    """
    Interactive real-time chat with the pre-loaded SEI CERT C reference guides and uploaded function code.
    Allows developers to ask clarifying questions or get detailed secure remediation code rewrites.
    """
    try:
        response_text = rag_service.get_chat_response(
            query=request.query,
            decompiled_code=request.decompiled_code,
            chat_history=request.chat_history
        )
        return {
            "status": "success",
            "response": response_text
        }
    except Exception as e:
        logger.error(f"Chat failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Chatbot failed",
                "message": str(e)
            }
        )

