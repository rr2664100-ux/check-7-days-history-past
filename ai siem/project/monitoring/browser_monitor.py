import threading
import re
import time
from typing import Dict, List, Optional
import psutil
from utils.logger import logger
from config.constants import BROWSER_PROCESSES

try:
    import win32gui
    import win32process
except ImportError:  # pragma: no cover
    win32gui = None
    win32process = None


class BrowserMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event, monitor_manager):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.monitor_manager = monitor_manager
        self.browser_activity: List[Dict[str, str]] = []

    def run(self) -> None:
        logger.info("Starting browser activity monitor.")
        while not self.stop_event.is_set():
            self.scan_browsers()
            time.sleep(self.settings.get("browser_poll_seconds", 10))

    def stop(self) -> None:
        self.stop_event.set()

    def scan_browsers(self) -> None:
        self.browser_activity.clear()
        active_title = self._get_active_window_title()
        active_browser: Optional[Dict[str, object]] = None

        for proc in psutil.process_iter(["name", "pid", "exe", "memory_info"]):
            try:
                name = proc.info.get("name", "").lower()
                if name in BROWSER_PROCESSES:
                    domain = self._extract_domain(active_title if active_title else "")
                    memory_mb = float(proc.info.get("memory_info").rss / 1024 / 1024) if proc.info.get("memory_info") else 0.0
                    record = {
                        "browser": name,
                        "pid": proc.info.get("pid", 0),
                        "title": active_title or "Unknown tab",
                        "domain": domain,
                        "memory_mb": memory_mb,
                    }
                    self.browser_activity.append(record)
                    self.database.insert_event(
                        "BrowserMonitor",
                        "BrowserActivity",
                        f"{name} active on {domain or 'unknown site'}",
                        "Information",
                    )

                    if not self.monitor_manager.live_state.is_baseline_pid(proc.info.get("pid", 0)):
                        active_browser = record

                    if self._is_suspicious_domain(domain) or memory_mb > 800:
                        self.database.insert_alert(
                            f"Suspicious browser activity: {name} on {domain or 'unknown site'}",
                            "BrowserMonitor",
                            "Medium",
                            30,
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:
                logger.debug("Browser monitor error: %s", exc)

        self.monitor_manager.live_state.update_live_browser(active_browser)

    def _extract_domain(self, title: str) -> str:
        match = re.search(r"(?:https?://)?([\w.-]+)", title)
        if match:
            return match.group(1)
        return title.strip()

    def _is_suspicious_domain(self, domain: str) -> bool:
        suspicious_markers = ["malicious", "bit.ly", "tinyurl", "pastebin", "127.0.0.1"]
        if not domain:
            return False
        return any(marker in domain.lower() for marker in suspicious_markers)

    def _get_active_window_title(self) -> str:
        if win32gui is None or win32process is None:
            return ""
        try:
            hwnd = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd)
            return title or ""
        except Exception:
            return ""
