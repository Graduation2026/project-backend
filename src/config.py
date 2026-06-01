"""
Central configuration for the Vulnerability Detection System.
All paths, model parameters, and constants live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ─── PROJECT ROOT ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # project-backend/

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")

# ─── GHIDRA CONFIGURATION ───────────────────────────────────────────────────
GHIDRA_INSTALL_DIR = Path(
    os.getenv("GHIDRA_INSTALL_DIR", "d:/ml_binpool_attempt/ghidra_12.0.3_PUBLIC")
)
_ghidra_executable = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
GHIDRA_HEADLESS = GHIDRA_INSTALL_DIR / "support" / _ghidra_executable
GHIDRA_SCRIPT_DIR = PROJECT_ROOT / "ghidra_scripts"
GHIDRA_SCRIPT_NAME = "ExtractAllCFGs.java"

# Timeout for Ghidra analysis (seconds) — some binaries can be large
GHIDRA_TIMEOUT_SECONDS = 900  # 15 minutes

# ─── ML MODEL CONFIGURATION ─────────────────────────────────────────────────
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "vulnerability_detector_rf.pkl"
VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.pkl"

# TF-IDF parameters (must match training)
TFIDF_MAX_FEATURES = 3000
TFIDF_NGRAM_RANGE = (1, 2)

# Random Forest parameters
RF_N_ESTIMATORS = 2500
RF_RANDOM_STATE = 42
RF_N_JOBS = -1  # Use all CPU cores

# ─── TRAINING DATA ──────────────────────────────────────────────────────────
LABELS_CSV = PROJECT_ROOT / "labels_mapping.csv"
FEATURES_DIR = Path(
    os.getenv("FEATURES_DIR", str(PROJECT_ROOT / "temp" / "features"))
)

# ─── TEMP DIRECTORIES ───────────────────────────────────────────────────────
UPLOAD_DIR = PROJECT_ROOT / "temp" / "uploads"
GHIDRA_OUTPUT_DIR = PROJECT_ROOT / "temp" / "ghidra_output"
GHIDRA_PROJECT_DIR = PROJECT_ROOT / "temp" / "ghidra_projects"

# ─── FILE VALIDATION ────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {
    ".exe", ".o", ".elf", ".dll", ".so", ".bin",
    ".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"
}
MAX_FILE_SIZE_MB = 50


# ─── LABEL MAPPING ──────────────────────────────────────────────────────────
LABEL_MAP = {0: "Safe", 1: "Vulnerable"}


def ensure_dirs():
    """Create all necessary directories if they don't exist."""
    for d in [ARTIFACTS_DIR, UPLOAD_DIR, GHIDRA_OUTPUT_DIR, GHIDRA_PROJECT_DIR, GHIDRA_SCRIPT_DIR]:
        d.mkdir(parents=True, exist_ok=True)
