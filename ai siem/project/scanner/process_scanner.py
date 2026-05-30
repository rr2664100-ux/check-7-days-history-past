import os
from typing import Dict
from utils.logger import logger
from detection.malware_rules import SUSPICIOUS_PROCESS_NAMES


class ProcessScanner:
    def __init__(self):
        self.suspicious_names = [name.lower() for name in SUSPICIOUS_PROCESS_NAMES]

    def inspect_process(self, process_info: Dict[str, str]) -> Dict[str, str]:
        name = process_info.get("name", "").lower()
        path = process_info.get("path", "")
        risks = []

        if any(suspicious in name for suspicious in self.suspicious_names):
            risks.append("Suspicious process name.")

        if path and not os.path.exists(path):
            risks.append("Process path is missing or unreachable.")

        if path.lower().endswith(".exe") and not self._is_signed(path):
            risks.append("Executable appears unsigned or unknown.")

        return {"name": name, "path": path, "risks": "; ".join(risks)}

    def _is_signed(self, path: str) -> bool:
        # Placeholder implementation for code signing validation.
        return False
