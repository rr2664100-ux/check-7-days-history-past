import threading
import time
import psutil
from utils.logger import logger
from config.settings import SETTINGS


class ResourceMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.summary = {}

    def run(self) -> None:
        logger.info("Starting live system resource monitor.")
        while not self.stop_event.is_set():
            self.collect_resources()
            time.sleep(self.settings.get("resource_poll_seconds", 3))

    def stop(self) -> None:
        self.stop_event.set()

    def collect_resources(self) -> None:
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            top_processes = self._top_processes_by_memory()
            self.summary = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "top_processes": top_processes,
            }
            if cpu_percent > self.settings.get("cpu_warning_percent", 80):
                self.database.insert_alert(
                    f"High CPU usage detected: {cpu_percent:.1f}%",
                    "ResourceMonitor",
                    "Medium",
                    35,
                )
            if memory.percent > self.settings.get("memory_warning_percent", 85):
                self.database.insert_alert(
                    f"High memory usage detected: {memory.percent:.1f}%",
                    "ResourceMonitor",
                    "Medium",
                    35,
                )
        except Exception as exc:
            logger.debug("Resource monitor scan failed: %s", exc)

    def _top_processes_by_memory(self):
        results = []
        try:
            for proc in sorted(psutil.process_iter(["name", "memory_info"]), key=lambda p: p.info.get("memory_info").rss if p.info.get("memory_info") else 0, reverse=True)[:5]:
                name = proc.info.get("name", "unknown")
                memory_mb = float(proc.info.get("memory_info").rss / 1024 / 1024) if proc.info.get("memory_info") else 0.0
                results.append({"name": name, "memory_mb": f"{memory_mb:.1f}"})
        except Exception as exc:
            logger.debug("Unable to read top processes: %s", exc)
        return results
