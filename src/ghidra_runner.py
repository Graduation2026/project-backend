"""
ghidra_runner.py — Subprocess wrapper for running Ghidra headless analysis.

Handles:
  - Building the analyzeHeadless command
  - Running Ghidra with proper timeout handling
  - Locating and returning the generated features file
"""

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from .config import (
    GHIDRA_HEADLESS,
    GHIDRA_OUTPUT_DIR,
    GHIDRA_PROJECT_DIR,
    GHIDRA_SCRIPT_DIR,
    GHIDRA_SCRIPT_NAME,
    GHIDRA_TIMEOUT_SECONDS,
    ensure_dirs,
)

logger = logging.getLogger(__name__)


class GhidraError(Exception):
    """Raised when Ghidra analysis fails."""
    pass


import time

# Simple file lock to prevent duplicate concurrent analysis of the same binary
_LOCK_DIR = None

def _get_lock_dir():
    global _LOCK_DIR
    if _LOCK_DIR is None:
        _LOCK_DIR = Path(tempfile.mkdtemp(prefix="ghidra_locks_"))
    return _LOCK_DIR

def _acquire_binary_lock(binary_path: Path) -> str:
    """Create a lock file for the binary's canonical path to prevent duplicate concurrent analysis, waiting if locked."""
    lock_dir = _get_lock_dir()
    lock_name = "lock_" + binary_path.resolve().as_posix().replace("/", "_").replace(":", "") + ".lock"
    lock_path = lock_dir / lock_name
    
    timeout = 120  # Wait up to 2 minutes
    start_time = time.time()
    
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL)
            os.close(fd)
            return str(lock_path)
        except FileExistsError:
            if time.time() - start_time > timeout:
                raise GhidraError(
                    f"Timeout waiting for binary '{binary_path.name}' to finish its current analysis."
                )
            logger.info(f"Binary '{binary_path.name}' is currently being analyzed. Waiting in queue...")
            time.sleep(1)

def _release_binary_lock(lock_path: str):
    try:
        Path(lock_path).unlink(missing_ok=True)
    except Exception:
        pass


def run_ghidra_analysis(binary_path: Path) -> Path:
    """
    Run Ghidra headless analysis on a single binary file to extract function CFGs.

    Args:
        binary_path: Path to the uploaded binary file (.exe, .o, .elf, etc.)

    Returns:
        Path to the generated cfg_features.json file.

    Raises:
        GhidraError: If Ghidra fails, times out, or the features file isn't created.
        FileNotFoundError: If Ghidra installation is not found.
    """
    ensure_dirs()

    # Validate Ghidra installation
    if not GHIDRA_HEADLESS.exists():
        raise FileNotFoundError(
            f"Ghidra analyzeHeadless.bat not found at: {GHIDRA_HEADLESS}\n"
            f"Please update GHIDRA_INSTALL_DIR in src/config.py"
        )

    if not binary_path.exists():
        raise FileNotFoundError(f"Binary file not found: {binary_path}")

    # Acquire binary lock to prevent duplicate concurrent analysis of same file
    lock_path = _acquire_binary_lock(binary_path)

    # Each analysis gets a unique session with isolated temp directories
    # The -deleteProject flag cleans up the Ghidra project after analysis
    # Per-session temp dirs ensure concurrent analyses on different files never collide
    session_id = uuid.uuid4().hex[:8]
    project_name = f"InferenceProject_{session_id}"

    # Use per-session temp directories to avoid collisions
    session_temp_dir = Path(tempfile.mkdtemp(prefix=f"ghidra_{session_id}_"))
    session_project_dir = session_temp_dir / "project"
    session_project_dir.mkdir(parents=True, exist_ok=True)

    # Create a unique output directory for this analysis
    output_dir = GHIDRA_OUTPUT_DIR / session_id
    output_dir.mkdir(parents=True, exist_ok=True)
    output_json_path = output_dir / "cfg_features.json"

    # =========================================================================
    # DEMYSTIFYING THE REVERSE ENGINEERING DATA FLOW
    # =========================================================================
    # Step 1 (Input): The user uploads a binary file or compiles a source file.
    # Step 2 (Headless Ghidra): We trigger analyzeHeadless in the background.
    # Step 3 (Java Script): Ghidra imports the binary and runs ExtractAllCFGs.java.
    # Step 4 (Extraction): The Java script disassembles the functions, traces their CFGs,
    #        and outputs nodes and edge indices to a unified JSON file.
    # Step 5 (Output): We read the JSON file, embed instructions with Word2Vec, and
    #        route the graph structures to our high-performance GNN!
    # =========================================================================
    
    # Build the analyzeHeadless command using session-scoped temp project dir
    cmd = [
        str(GHIDRA_HEADLESS),
        str(session_project_dir),        # Per-session temp project directory
        project_name,                     # Temporary project name
        "-import", str(binary_path),      # The binary to analyze
        "-scriptPath", str(GHIDRA_SCRIPT_DIR),  # Where our Java script lives
        "-postScript", GHIDRA_SCRIPT_NAME, str(output_json_path),  # Run after analysis
        "-deleteProject",                 # Clean up the Ghidra project after
    ]

    logger.info(f"Running Ghidra analysis on: {binary_path.name}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GHIDRA_TIMEOUT_SECONDS,
            cwd=str(session_project_dir),
        )

        # Log Ghidra output for debugging
        if result.stdout:
            logger.info(f"Ghidra stdout:\n{result.stdout[-2000:]}")
        if result.stderr:
            logger.warning(f"Ghidra stderr:\n{result.stderr[-1000:]}")

        # Ghidra returns 0 on success, but we still need to check for the output file
        if result.returncode != 0:
            logger.error(f"Ghidra exited with code {result.returncode}")

    except subprocess.TimeoutExpired:
        raise GhidraError(
            f"Ghidra analysis timed out after {GHIDRA_TIMEOUT_SECONDS}s. "
            f"The binary may be too large or complex."
        )
    except FileNotFoundError:
        raise GhidraError(
            "Failed to execute analyzeHeadless.bat. "
            "Make sure Java 17+ is installed and in your PATH."
        )
    finally:
        # Release binary lock
        _release_binary_lock(lock_path)
        # Clean up session temp directory
        shutil.rmtree(session_temp_dir, ignore_errors=True)

    if not output_json_path.exists():
        raise GhidraError(
            f"Ghidra completed but no CFG features file was generated.\n"
            f"Expected output file: {output_json_path}\n"
            f"Check Ghidra logs above for errors."
        )

    logger.info(f"CFG Features extracted: {output_json_path.name} ({output_json_path.stat().st_size} bytes)")
    return output_json_path
