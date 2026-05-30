from typing import Dict


class RiskScorer:
    def score(self, alert: Dict[str, str]) -> int:
        severity = alert.get("severity", "Low").lower()
        base = int(alert.get("risk_score", 10))
        if severity == "high":
            return min(100, base + 35)
        if severity == "medium":
            return min(100, base + 20)
        return min(100, base + 10)
