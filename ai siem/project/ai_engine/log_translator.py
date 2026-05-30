from typing import Dict


class LogTranslator:
    def translate(self, record: Dict[str, str]) -> str:
        message = record.get("message") or record.get("alert_text") or "No message"
        source = record.get("source", "system")
        return f"The system recorded an event from {source}. Summary: {message}."
