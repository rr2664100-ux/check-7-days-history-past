import json
from pathlib import Path
from typing import Any
from utils.helpers import ensure_directory


class JSONExporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        ensure_directory(self.output_dir)

    def export(self, filename: str, data: Any) -> Path:
        path = self.output_dir / f"{filename}.json"
        with path.open("w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=2)
        return path
