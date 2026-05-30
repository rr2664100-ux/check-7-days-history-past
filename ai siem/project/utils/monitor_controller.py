import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
import psutil
from database.database import LocalDatabase
from config.settings import SETTINGS
from monitoring.event_monitor import EventMonitor
from monitoring.process_monitor import ProcessMonitor
from monitoring.browser_monitor import BrowserMonitor
from monitoring.network_monitor import NetworkMonitor
from monitoring.resource_monitor import ResourceMonitor
from monitoring.startup_monitor import StartupMonitor
from scanner.memory_scanner import MemoryScanner


class LiveMonitorState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.monitor_started = False
        self.monitor_start_time: Optional[datetime] = None
        self.baseline_pids: set[int] = set()
        self.current_apps: List[Dict[str, Any]] = []
        self.current_browser: Optional[Dict[str, Any]] = None
        self.suspicious_alerts: List[Dict[str, Any]] = []

    def reset(self) -> None:
        with self.lock:
            self.monitor_started = True
            self.monitor_start_time = datetime.now()
            self.baseline_pids = set()
            self.current_apps = []
            self.current_browser = None
            self.suspicious_alerts = []

    def initialize_baseline(self) -> None:
        baseline: set[int] = set()
        for proc in psutil.process_iter(["pid"]):
            try:
                pid = proc.info.get("pid")
                if pid:
                    baseline.add(pid)
            except Exception:
                continue
        with self.lock:
            self.baseline_pids = baseline

    def stop(self) -> None:
        with self.lock:
            self.monitor_started = False

    def is_baseline_pid(self, pid: int) -> bool:
        with self.lock:
            return pid in self.baseline_pids

    def update_live_apps(self, apps: List[Dict[str, Any]]) -> None:
        with self.lock:
            self.current_apps = apps

    def update_live_browser(self, browser: Optional[Dict[str, Any]]) -> None:
        with self.lock:
            self.current_browser = browser

    def add_suspicious_alert(self, message: str, severity: str = "Warning") -> None:
        with self.lock:
            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": message,
                "severity": severity,
            }
            self.suspicious_alerts = [alert] + self.suspicious_alerts
            self.suspicious_alerts = self.suspicious_alerts[:5]

    def get_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "monitor_started": self.monitor_started,
                "current_apps": list(self.current_apps),
                "current_browser": dict(self.current_browser) if self.current_browser else None,
                "suspicious_alerts": list(self.suspicious_alerts),
            }


class MonitorManager:
    def __init__(self, database: LocalDatabase):
        self.database = database
        self.settings = SETTINGS
        self.stop_event = threading.Event()
        self.live_state = LiveMonitorState()
        self.monitors: List[threading.Thread] = []

    def start(self) -> None:
        if self.is_running:
            return
        self.stop_event = threading.Event()
        self.live_state.reset()
        self.live_state.initialize_baseline()
        self.monitors = [
            EventMonitor(self.database, self.settings, self.stop_event, self.live_state),
            ProcessMonitor(self.database, self.settings, self.stop_event, self.live_state),
            BrowserMonitor(self.database, self.settings, self.stop_event, self.live_state),
            NetworkMonitor(self.database, self.settings, self.stop_event),
            ResourceMonitor(self.database, self.settings, self.stop_event),
            StartupMonitor(self.database, self.settings, self.stop_event),
            MemoryScanner(self.database, self.settings, self.stop_event),
        ]
        for monitor in self.monitors:
            monitor.start()

    def stop(self) -> None:
        if not self.is_running:
            return
        self.stop_event.set()
        for monitor in self.monitors:
            if hasattr(monitor, "join"):
                monitor.join(timeout=5)
        self.monitors = []
        self.live_state.stop()

    @property
    def is_running(self) -> bool:
        return any(getattr(monitor, "is_alive", False) and monitor.is_alive() for monitor in self.monitors)
