import threading
import time
from typing import Dict, List
import psutil
import wmi
from utils.logger import logger
from config.constants import KNOWN_SAFE_PROCESSES


class ProcessMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event, monitor_manager):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.monitor_manager = monitor_manager
        self.wmi_client = None
        self.previous_processes = set()
        self.first_scan = True
        try:
            self.wmi_client = wmi.WMI()
        except Exception as exc:
            logger.debug("Unable to initialize WMI client: %s", exc)

    def run(self) -> None:
        logger.info("Starting process and application monitor.")
        while not self.stop_event.is_set():
            self.scan_processes()
            time.sleep(self.settings.get("process_poll_seconds", 5))

    def stop(self) -> None:
        self.stop_event.set()

    def scan_processes(self) -> None:
        suspicious_matches: List[str] = []
        current_processes = set()
        visible_apps: List[Dict[str, object]] = []

        for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info", "status"]):
            try:
                name = proc.info.get("name") or "unknown"
                pid = proc.info.get("pid", 0)
                path = proc.info.get("exe") or "unknown"
                cpu_percent = float(proc.info.get("cpu_percent") or 0.0)
                memory_mb = float(proc.info.get("memory_info").rss / 1024 / 1024) if proc.info.get("memory_info") else 0.0
                status = proc.info.get("status") or "unknown"
                name_lower = name.lower()

                if self._is_system_process(name_lower, path):
                    continue

                current_processes.add(pid)
                self.database.insert_process_event(name, pid, path, cpu_percent, memory_mb, status)

                if not self.first_scan and pid not in self.previous_processes:
                    self.database.insert_activity("opened", name, f"{name} opened with PID {pid}", "Safe")

                if not self.monitor_manager.live_state.is_baseline_pid(pid):
                    visible_apps.append(
                        {
                            "name": name,
                            "pid": pid,
                            "cpu_percent": cpu_percent,
                            "memory_mb": memory_mb,
                            "status": status,
                        }
                    )

                if self._is_suspicious_process(name, path, cpu_percent, memory_mb):
                    suspicious_matches.append(f"{name} ({pid})")
                    self.database.insert_activity("suspicious", name, f"{name} flagged by heuristic", "Warning")
                    if not self.monitor_manager.live_state.is_baseline_pid(pid):
                        self.monitor_manager.live_state.add_suspicious_alert(
                            f"Suspicious process detected: {name} — CPU {cpu_percent:.0f}% RAM {memory_mb:.0f} MB",
                            "Warning",
                        )

                if memory_mb > 800 or cpu_percent > 50:
                    self.database.insert_activity("resource", name, f"{name} using high resources: {memory_mb:.1f} MB RAM", "Warning")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as exc:
                logger.debug("Unexpected process scan error: %s", exc)

        self.monitor_manager.live_state.update_live_apps(visible_apps)

        if self.first_scan:
            self.previous_processes = current_processes
            self.first_scan = False
        else:
            self.previous_processes = current_processes

        if suspicious_matches:
            self.database.insert_alert(
                f"Suspicious processes detected: {', '.join(suspicious_matches)}",
                "ProcessMonitor",
                "Medium",
                45,
            )

    def _is_suspicious_process(self, name: str, path: str, cpu_percent: float, memory_mb: float) -> bool:
        name_lower = name.lower()
        if name_lower not in KNOWN_SAFE_PROCESSES and path and path.endswith(".exe") and "windows" in path.lower() is False:
            if cpu_percent > 30 or memory_mb > 500 or name_lower.endswith(".tmp"):
                logger.info("Detected abnormal process behavior for %s (%s)", name, path)
                return True
        return False

    def _is_system_process(self, name_lower: str, path: str) -> bool:
        if name_lower in {"svchost.exe", "runtimebroker.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe"}:
            return True
        if "\windows\system32" in path.lower() or "\windows\syswow64" in path.lower():
            return True
        if name_lower.startswith("python") or name_lower.endswith(".py"):
            return True
        return False
