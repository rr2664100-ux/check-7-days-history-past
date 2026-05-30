from utils.logger import logger
from detection.malware_rules import RAT_INDICATORS


class RATDetector:
    def __init__(self):
        self.indicators = [indicator.lower() for indicator in RAT_INDICATORS]

    def analyze_process(self, process_name: str, path: str) -> bool:
        normalized = process_name.lower()
        if any(indicator in normalized for indicator in self.indicators):
            logger.info("Potential RAT indicator detected in process name: %s", process_name)
            return True
        if any(indicator in path.lower() for indicator in self.indicators):
            logger.info("Potential RAT indicator detected in process path: %s", path)
            return True
        return False
