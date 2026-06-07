"""
api.py - The Controller API for the Vulnerability Detection System.

This is the brain of the operation. A single FastAPI application that:
  1. Serves a professional web dashboard at /
  2. Accepts an uploaded binary file via /analyze
  3. Runs Ghidra headless analysis to extract features
  4. Feeds features into the trained ML model
  5. Returns a JSON verdict: Safe or Vulnerable

Run:
    python -m uvicorn src.api:app --reload --host 0.0.0.0 --port 8000
"""

import hashlib
import json
import logging
import shutil
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
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
    using MinGW GCC/G++, supporting standalone functions without main().
    """
    file_ext = source_path.suffix.lower()
    compiler = "g++" if file_ext in [".cpp", ".cc", ".cxx", ".hpp"] else "gcc"
    
    # Run compiler: gcc -O0 -g -c -o output_o_path source_path
    command = [compiler, "-O0", "-g", "-c", "-o", str(output_o_path), str(source_path)]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"MinGW compilation failed:\n{result.stderr}")
        
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

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
            "n_estimators": 0,
            "trained_at": "Not trained yet",
        }
    with open(meta_path, "r") as f:
        return json.load(f)


# --- POST /analyze ---
@app.post("/analyze", tags=["Analysis"])
async def analyze_binary(file: UploadFile = File(...)):
    """
    Upload a binary file or C/C++ source code for vulnerability analysis.

    The system will:
    1. Validate the file type (.c and .cpp files are auto-compiled on the fly)
    2. Run Ghidra headless reverse engineering
    3. Extract assembly features (opcodes)
    4. Run the trained Random Forest model
    5. Return a prediction with confidence score

    **Accepted formats:** .exe, .o, .elf, .dll, .so, .bin, .c, .cpp, .cc, .h, .hpp
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

    # Generate RAG Vulnerability Report and Render PDF
    try:
        logger.info("Generating RAG security report...")
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
        logger.error(f"RAG or PDF generation failed: {str(e)}")
        report_markdown = f"# Analysis Completed\n\nFailed to generate interactive RAG report: {str(e)}"
        pdf_url = ""

    # Build response payload combining Sentinel dashboard compatibility + Ultimate RAG blueprint
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

