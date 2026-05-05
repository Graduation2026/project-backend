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
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("api")


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
        "Upload a compiled binary (.exe, .o, .elf) and get an AI-powered "
        "vulnerability assessment using Ghidra reverse engineering + "
        "Random Forest machine learning."
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

# Mount static files
app.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "static")), name="static")


# --- GET / (Web Dashboard) ---
@app.get("/", tags=["Dashboard"], include_in_schema=False)
async def dashboard():
    """Serve the main web dashboard."""
    return FileResponse(str(PROJECT_ROOT / "templates" / "index.html"))


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
    Upload a binary file for vulnerability analysis.

    The system will:
    1. Validate the file type
    2. Run Ghidra headless reverse engineering
    3. Extract assembly features (opcodes)
    4. Run the trained Random Forest model
    5. Return a prediction with confidence score

    **Accepted formats:** .exe, .o, .elf, .dll, .so, .bin
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
                "message": f"Only binary executables are accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{file.filename}"
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

    # Run Ghidra Analysis
    ghidra_start = time.time()
    try:
        logger.info("Starting Ghidra analysis...")
        features_file = run_ghidra_analysis(upload_path)
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

    # Read extracted features
    try:
        with open(features_file, "r", encoding="utf-8", errors="ignore") as f:
            features_text = f.read().strip()

        if not features_text:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "Empty features",
                    "message": "Ghidra extracted no features from this binary. It may be corrupted or packed.",
                },
            )

        logger.info(f"Features loaded: {len(features_text)} characters")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read features file: {str(e)}")

    # Run ML Prediction
    ml_start = time.time()
    try:
        result = predictor.predict(features_text)
        ml_time = time.time() - ml_start
        logger.info(
            f"Prediction: {result['prediction']} "
            f"(confidence: {result['confidence']:.2%}, {ml_time:.3f}s)"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")

    # Build response
    total_time = time.time() - total_start

    response = {
        "filename": file.filename,
        "sha256": sha256_hash,
        "prediction": result["prediction"],
        "label": result["label"],
        "confidence": result["confidence"],
        "top_features": result["top_features"],
        "timing": {
            "ghidra_seconds": round(ghidra_time, 2),
            "ml_seconds": round(ml_time, 4),
            "total_seconds": round(total_time, 2),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    verdict = "SAFE" if result["label"] == 0 else "VULNERABLE"
    logger.info(
        f"RESULT: {file.filename} -> {verdict} "
        f"({result['confidence']:.2%}) in {total_time:.1f}s"
    )

    # Cleanup temp files
    try:
        if upload_path.exists():
            upload_path.unlink()
        if features_file.parent.exists() and features_file.parent != UPLOAD_DIR:
            shutil.rmtree(features_file.parent, ignore_errors=True)
    except Exception:
        pass

    return JSONResponse(content=response)

# Trigger server reload to load new models

# Trigger reload for ensemble model
