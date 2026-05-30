from typing import Dict, Any
from utils.logger import logger
from config.constants import SUSPICIOUS_KEYWORDS
from detection.malware_rules import SUSPICIOUS_PROCESS_NAMES, SUSPICIOUS_COMMAND_PATTERNS


class HeuristicEngine:
    def __init__(self):
        self.patterns = SUSPICIOUS_COMMAND_PATTERNS
        self.process_names = [name.lower() for name in SUSPICIOUS_PROCESS_NAMES]

    def evaluate_process(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        name = process_info.get("name", "").lower()
        path = process_info.get("path", "").lower()
        score = 0
        alerts = []

        if any(suspicious in name for suspicious in self.process_names):
            score += 35
            alerts.append("Process name matches suspicious system utility patterns.")

        if any(keyword.lower() in path for keyword in SUSPICIOUS_KEYWORDS):
            score += 30
            alerts.append("Process path contains suspicious startup or command keywords.")

        if process_info.get("cpu_percent", 0) > 30:
            score += 10
            alerts.append("Process is consuming unusually high CPU.")

        return {"score": score, "alerts": alerts}

    def evaluate_command(self, command: str) -> Dict[str, Any]:
        score = 0
        alerts = []
        command_lower = command.lower()

        if any(pattern.lower() in command_lower for pattern in self.patterns):
            score += 40
            alerts.append("Suspicious PowerShell or command shell pattern detected.")

        if any(keyword.lower() in command_lower for keyword in SUSPICIOUS_KEYWORDS):
            score += 25
            alerts.append("Potential persistence or download behavior found in command text.")

        return {"score": min(score, 100), "alerts": alerts}

    def evaluate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        message = event.get("message", "").lower()
        category = event.get("category", "").lower()
        score = 0
        alerts = []

        if "failed" in message or "failure" in category:
            score += 20
            alerts.append("A failed login or failed event was observed.")

        if "service" in category and "installed" in message:
            score += 20
            alerts.append("A service installation event may indicate persistence behavior.")

        return {"score": score, "alerts": alerts}
