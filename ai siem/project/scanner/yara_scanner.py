import logging
from pathlib import Path
from typing import Dict, List
from detection.malware_rules import SUSPICIOUS_COMMAND_PATTERNS

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

logger = logging.getLogger("SentinelAI.YARA")

RULE_TEXT = """
rule SuspiciousCommandPatterns {
    strings:
"""

for index, pattern in enumerate(SUSPICIOUS_COMMAND_PATTERNS):
    RULE_TEXT += f"    $pattern{index} = \"{pattern}\" nocase\n"
RULE_TEXT += "    condition:\n        any of them\n}"


class YaraScanner:
    def __init__(self):
        self.rules = None
        if yara:
            try:
                self.rules = yara.compile(source=RULE_TEXT)
            except Exception as exc:
                logger.debug("YARA compilation failed: %s", exc)

    def scan_text(self, text: str) -> List[str]:
        results = []
        if self.rules is None:
            for pattern in SUSPICIOUS_COMMAND_PATTERNS:
                if pattern.lower() in text.lower():
                    results.append(pattern)
            return results

        try:
            matches = self.rules.match(data=text)
            for match in matches:
                results.append(match.rule)
        except Exception as exc:
            logger.debug("YARA text scan failed: %s", exc)
        return results

    def scan_file(self, path: Path) -> List[str]:
        if not path.exists() or not path.is_file():
            return []
        try:
            if self.rules:
                matches = self.rules.match(str(path))
                return [match.rule for match in matches]
            if path.suffix.lower() == ".txt":
                text = path.read_text(errors="ignore")
                return self.scan_text(text)
        except Exception as exc:
            logger.debug("YARA file scan failed: %s", exc)
        return []
