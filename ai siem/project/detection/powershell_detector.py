import re
from typing import Dict
from utils.logger import logger
from detection.malware_rules import POWERSHELL_SIGNALS


class PowerShellDetector:
    def __init__(self):
        self.signals = [signal.lower() for signal in POWERSHELL_SIGNALS]
        self.encoded_pattern = re.compile(r"-encodedcommand\s+\S+", re.IGNORECASE)

    def analyze_command(self, command: str) -> Dict[str, str]:
        command_lower = command.lower()
        findings = []
        if any(signal in command_lower for signal in self.signals):
            findings.append("Suspicious PowerShell technique found.")
        if self.encoded_pattern.search(command):
            findings.append("Encoded PowerShell command detected.")
        if findings:
            logger.info("PowerShell detector matched patterns for command: %s", command)
        return {"command": command, "findings": findings}
