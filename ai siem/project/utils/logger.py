import logging
from pathlib import Path
from .helpers import ensure_directory
from config.constants import LOG_FILE


def configure_logger() -> logging.Logger:
    ensure_directory(LOG_FILE.parent)
    logger = logging.getLogger("SentinelAI")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


logger = configure_logger()

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
