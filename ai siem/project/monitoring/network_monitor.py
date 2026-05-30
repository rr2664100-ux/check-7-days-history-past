import threading
import time
import psutil
from utils.logger import logger
from utils.helpers import get_timestamp
from config.settings import SETTINGS


class NetworkMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.last_counters = psutil.net_io_counters()
        self.connection_history = []

    def run(self) -> None:
        logger.info("Starting network activity monitor.")
        while not self.stop_event.is_set():
            self.scan_network()
            time.sleep(self.settings.get("network_poll_seconds", 5))

    def stop(self) -> None:
        self.stop_event.set()

    def scan_network(self) -> None:
        try:
            counters = psutil.net_io_counters()
            download_speed = (counters.bytes_recv - self.last_counters.bytes_recv) / max(self.settings.get("network_poll_seconds", 5), 1)
            upload_speed = (counters.bytes_sent - self.last_counters.bytes_sent) / max(self.settings.get("network_poll_seconds", 5), 1)
            self.last_counters = counters

            connections = psutil.net_connections(kind="tcp")
            suspicious_connections = [conn for conn in connections if conn.raddr and conn.status == "ESTABLISHED" and conn.raddr.ip not in ("127.0.0.1", "::1")]

            if suspicious_connections:
                self.database.insert_alert(
                    f"Detected {len(suspicious_connections)} active outbound connections.",
                    "NetworkMonitor",
                    "Low",
                    20,
                )

            self.connection_history = [
                {
                    "timestamp": get_timestamp(),
                    "download_bps": download_speed,
                    "upload_bps": upload_speed,
                    "active_tcp": len(suspicious_connections),
                }
            ]
        except Exception as exc:
            logger.debug("Network scan failed: %s", exc)
