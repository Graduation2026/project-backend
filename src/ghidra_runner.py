"""
ghidra_runner.py — Subprocess wrapper for running Ghidra headless analysis.

Handles:
  - Building the analyzeHeadless command
  - Running Ghidra with proper timeout handling
  - Locating and returning the generated features file
"""

import logging
import subprocess
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


def run_ghidra_analysis(binary_path: Path) -> Path:
    """
    Run Ghidra headless analysis on a single binary file.

    Args:
        binary_path: Path to the uploaded binary file (.exe, .o, .elf, etc.)

    Returns:
        Path to the generated _features.txt file.

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

    # Create a unique project name to avoid collisions
    session_id = uuid.uuid4().hex[:8]
    project_name = f"InferenceProject_{session_id}"

    # Create a unique output directory for this analysis
    output_dir = GHIDRA_OUTPUT_DIR / session_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # DEMYSTIFYING THE REVERSE ENGINEERING DATA FLOW
    # =========================================================================
    # Step 1 (Input): The user uploads a binary file (e.g., .exe, .elf).
    # Step 2 (Headless Ghidra): We trigger analyzeHeadless in the background.
    # Step 3 (Java Script): Ghidra imports the binary and runs InferenceScanner.java.
    # Step 4 (Extraction): The Java script disassembles the binary, loops through 
    #        every function, and prints the assembly opcodes (MOV, PUSH, etc.) 
    #        to a text file.
    # Step 5 (Output): We read the text file and feed it to the ML model!
    # =========================================================================
    
    # Build the analyzeHeadless command
    # Format: analyzeHeadless <projectDir> <projectName>
    #         -import <file>
    #         -scriptPath <scriptDir>
    #         -postScript <script.java> <scriptArg1>
    #         -deleteProject
    cmd = [
        str(GHIDRA_HEADLESS),
        str(GHIDRA_PROJECT_DIR),         # Where Ghidra stores its temp project
        project_name,                     # Temporary project name
        "-import", str(binary_path),      # The binary to analyze
        "-scriptPath", str(GHIDRA_SCRIPT_DIR),  # Where our Java script lives
        "-postScript", GHIDRA_SCRIPT_NAME, str(output_dir),  # Run after analysis
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
            cwd=str(GHIDRA_PROJECT_DIR),
        )

        # Log Ghidra output for debugging
        if result.stdout:
            logger.debug(f"Ghidra stdout:\n{result.stdout[-2000:]}")
        if result.stderr:
            logger.warning(f"Ghidra stderr:\n{result.stderr[-1000:]}")

        # Ghidra returns 0 on success, but we still need to check for the output file
        if result.returncode != 0:
            logger.error(f"Ghidra exited with code {result.returncode}")
            # Don't fail immediately — sometimes Ghidra returns non-zero but still works

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

    # Find the generated features file
    features_file = _find_features_file(output_dir, binary_path.name)

    if features_file is None:
        raise GhidraError(
            f"Ghidra completed but no features file was generated.\n"
            f"Expected output in: {output_dir}\n"
            f"Check Ghidra logs above for errors."
        )

    logger.info(f"Features extracted: {features_file.name} ({features_file.stat().st_size} bytes)")
    return features_file


def _find_features_file(output_dir: Path, original_filename: str) -> Path | None:
    """
    Locate the features file generated by Ghidra.

    Ghidra may strip or modify the filename, so we search for any
    file ending in _features.txt in the output directory.
    """
    # Try exact match first
    expected_name = original_filename + "_features.txt"
    exact_match = output_dir / expected_name
    if exact_match.exists():
        return exact_match

    # Fallback: find any _features.txt file in the output directory
    features_files = list(output_dir.glob("*_features.txt"))
    if features_files:
        # Return the most recently created one
        return max(features_files, key=lambda f: f.stat().st_mtime)

    return None
