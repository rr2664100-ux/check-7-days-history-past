import csv
from pathlib import Path
from typing import List, Dict
from utils.helpers import ensure_directory


class CSVExporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        ensure_directory(self.output_dir)

    def export(self, filename: str, rows: List[Dict[str, str]]) -> Path:
        path = self.output_dir / f"{filename}.csv"
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            fieldnames = rows[0].keys() if rows else []
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path
