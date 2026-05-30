import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def ensure_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_bytes(value: float) -> str:
    if value < 1024:
        return f"{value:.1f} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.1f} {unit}"
    return f"{value:.1f} PB"


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_read_file(path: Path) -> Optional[str]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handler:
            return handler.read()
    except OSError:
        return None


def is_windows() -> bool:
    return sys.platform.startswith("win")


def clean_list(values: List[Any]) -> List[str]:
    return [str(item).strip() for item in values if item is not None and str(item).strip()]
