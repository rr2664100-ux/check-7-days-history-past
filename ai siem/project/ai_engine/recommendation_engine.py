from typing import Dict, List


class RecommendationEngine:
    def summarize(self, alerts: List[Dict[str, str]]) -> List[str]:
        recommendations = []
        for alert in alerts:
            severity = alert.get("severity", "Low").lower()
            text = alert.get("alert_text", "")
            if severity == "high":
                recommendations.append(f"Review immediately: {text}")
            elif severity == "medium":
                recommendations.append(f"Investigate soon: {text}")
            else:
                recommendations.append(f"Monitor: {text}")
        return recommendations
