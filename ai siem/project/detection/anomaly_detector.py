from typing import Dict, List
from utils.logger import logger


class AnomalyDetector:
    def __init__(self):
        self.history = []

    def detect_resource_anomaly(self, resource_snapshot: Dict[str, float]) -> Dict[str, str]:
        alerts = {}
        cpu = resource_snapshot.get("cpu_percent", 0)
        memory = resource_snapshot.get("memory_percent", 0)
        disk = resource_snapshot.get("disk_percent", 0)

        if cpu > 85:
            alerts["cpu"] = "CPU usage is unusually high."
        if memory > 90:
            alerts["memory"] = "Memory usage is above healthy thresholds."
        if disk > 90:
            alerts["disk"] = "Disk usage is unusually high."

        if alerts:
            logger.info("Anomaly detector found resource issues: %s", alerts)
        return alerts

    def detect_hidden_process(self, process_name: str, path: str) -> bool:
        if process_name.lower().startswith(".") or "temp" in path.lower() or path.lower().endswith(".tmp"):
            logger.debug("Hidden or temporary process signature detected for %s", process_name)
            return True
        return False
