from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT_DIR / "config"
DATABASE_DIR = ROOT_DIR / "database"
LOGS_DIR = ROOT_DIR / "logs"
ASSETS_DIR = ROOT_DIR / "assets"
DB_FILE = DATABASE_DIR / "logs.db"
EVENTS_TABLE = "events"
PROCESS_TABLE = "process_events"
ALERTS_TABLE = "alerts"
RECOMMENDATIONS_TABLE = "recommendations"
LOG_FILE = LOGS_DIR / "sentinelai.log"
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
VENV_DIR = ROOT_DIR / ".venv"

EVENT_CHANNELS = ["Security", "System", "Application"]
BROWSER_PROCESSES = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"]
KNOWN_SAFE_PROCESSES = ["explorer.exe", "svchost.exe", "python.exe", "Code.exe", "notepad.exe"]

SUSPICIOUS_KEYWORDS = [
    "Invoke-WebRequest",
    "DownloadString",
    "Invoke-Expression",
    "-EncodedCommand",
    "Base64",
    "New-Object System.Net.Sockets.TCPClient",
    "Add-MpPreference",
    "schtasks",
    "reg add",
]
