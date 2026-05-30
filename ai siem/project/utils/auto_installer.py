import os
import subprocess
import sys
from pathlib import Path
from .helpers import ensure_directory, is_windows
from .logger import logger
from config.constants import REQUIREMENTS_FILE, VENV_DIR


def is_in_virtualenv() -> bool:
    return hasattr(sys, "real_prefix") or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)


def get_python_executable() -> Path:
    if is_in_virtualenv():
        return Path(sys.executable)
    candidate = VENV_DIR / ("Scripts" if is_windows() else "bin") / ("python.exe" if is_windows() else "python")
    if candidate.exists():
        return candidate
    return Path(sys.executable)


def create_virtual_environment() -> None:
    if VENV_DIR.exists() and any(VENV_DIR.iterdir()):
        logger.info("Virtual environment already exists at %s", VENV_DIR)
        return

    logger.info("Creating virtual environment at %s", VENV_DIR)
    ensure_directory(VENV_DIR)
    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    logger.info("Virtual environment created successfully.")


def install_requirements() -> None:
    if not REQUIREMENTS_FILE.exists():
        logger.warning("Requirements file not found: %s", REQUIREMENTS_FILE)
        return

    python_exec = get_python_executable()
    logger.info("Installing dependencies using %s", python_exec)
    subprocess.run([str(python_exec), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(python_exec), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)], check=True)
    logger.info("Dependencies installed successfully.")


def ensure_environment() -> None:
    try:
        if not is_in_virtualenv() and not VENV_DIR.exists():
            create_virtual_environment()
            install_requirements()
            logger.info("Environment setup is complete. Restart the application inside the new virtual environment.")
            return

        install_requirements()
    except subprocess.CalledProcessError as exc:
        logger.error("Installer failed: %s", exc)
        raise


def run_installer() -> None:
    ensure_environment()
    logger.info("SentinelAI auto-installer finished.")
