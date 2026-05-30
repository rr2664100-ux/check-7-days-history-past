import threading
import time
import subprocess
import winreg
from pathlib import Path
from typing import List, Dict
from utils.logger import logger
from utils.helpers import get_timestamp
from config.constants import SUSPICIOUS_KEYWORDS


class StartupMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.entries: List[Dict[str, str]] = []

    def run(self) -> None:
        logger.info("Starting startup and persistence monitor.")
        while not self.stop_event.is_set():
            self.scan_startup_entries()
            time.sleep(self.settings.get("startup_poll_seconds", 45))

    def stop(self) -> None:
        self.stop_event.set()

    def scan_startup_entries(self) -> None:
        self.entries.clear()
        self._read_registry_startup(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        self._read_registry_startup(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        self._read_startup_folders()
        self._scan_scheduled_tasks()

    def _read_registry_startup(self, hive, key_path: str) -> None:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as root:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(root, index)
                        self.entries.append({"location": key_path, "name": name, "command": value})
                        if any(keyword.lower() in value.lower() for keyword in SUSPICIOUS_KEYWORDS):
                            self.database.insert_alert(
                                f"Suspicious startup command found: {name}",
                                "StartupMonitor",
                                "Medium",
                                45,
                            )
                        index += 1
                    except OSError:
                        break
        except OSError:
            logger.debug("Unable to read startup registry key: %s", key_path)

    def _read_startup_folders(self) -> None:
        possible_paths = [
            Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
        ]
        for folder_path in possible_paths:
            if not folder_path.exists():
                continue
            for item in folder_path.iterdir():
                self.entries.append({"location": str(folder_path), "name": item.name, "command": str(item)})

    def _scan_scheduled_tasks(self) -> None:
        try:
            result = subprocess.run(["schtasks", "/query", "/FO", "LIST", "/V"], capture_output=True, text=True, shell=False, timeout=20)
            if result.returncode == 0:
                if "\"%windir%\\system32\\windowspowershell\\v1.0\\powershell.exe\"" in result.stdout.lower():
                    self.database.insert_alert(
                        "PowerShell scheduled task detected, review persistence rules.",
                        "StartupMonitor",
                        "Medium",
                        50,
                    )
        except Exception as exc:
            logger.debug("Scheduled task scan failed: %s", exc)
