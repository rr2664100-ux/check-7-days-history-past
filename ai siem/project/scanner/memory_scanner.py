import threading
import time
import psutil
from typing import List, Dict
from pathlib import Path
from utils.logger import logger
from utils.helpers import get_timestamp
from detection.malware_rules import SUSPICIOUS_COMMAND_PATTERNS
from scanner.yara_scanner import YaraScanner


class MemoryScanner(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.yara_scanner = YaraScanner()

    def run(self) -> None:
        logger.info("Starting lightweight memory scanner.")
        while not self.stop_event.is_set():
            self.scan_processes_memory()
            time.sleep(self.settings.get("memory_scan_interval_seconds", 60))

    def stop(self) -> None:
        self.stop_event.set()

    def scan_processes_memory(self) -> None:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = proc.info.get("name", "unknown")
                path = proc.info.get("exe") or ""
                command_line = " ".join(proc.info.get("cmdline") or [])
                matches = self._scan_text(command_line)
                if matches:
                    self.database.insert_alert(
                        f"Memory scanner flagged {name}: {', '.join(matches)}",
                        "MemoryScanner",
                        "High",
                        55,
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                logger.debug("Memory scanner failed for process: %s", exc)

    def _scan_text(self, text: str) -> List[str]:
        matches = []
        if not text:
            return matches
        matches.extend(self.yara_scanner.scan_text(text))
        for pattern in SUSPICIOUS_COMMAND_PATTERNS:
            if pattern.lower() in text.lower() and pattern not in matches:
                matches.append(pattern)
        return matches
