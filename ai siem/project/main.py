import os
from pathlib import Path
from utils.auto_installer import ensure_environment
from utils.permissions import check_permission_mode
from utils.logger import logger
from database.database import LocalDatabase
from utils.monitor_controller import MonitorManager
from ui.dashboard import SentinelAIDashboard


def setup_environment() -> None:
    try:
        ensure_environment()
    except Exception as exc:
        logger.warning("Auto-installer failed, continuing if required dependencies already exist: %s", exc)


def get_project_root() -> Path:
    return Path(__file__).resolve().parent


def main() -> None:
    os.chdir(get_project_root())
    setup_environment()
    mode = check_permission_mode()
    database = LocalDatabase()
    monitor_manager = MonitorManager(database)

    try:
        dashboard = SentinelAIDashboard(
            database=database,
            report_dir=get_project_root() / "reports",
            monitor_manager=monitor_manager,
        )
        dashboard.mainloop()
    except Exception as exc:
        logger.error("Dashboard failed to start: %s", exc)
    finally:
        monitor_manager.stop()
        database.close()
        logger.info("SentinelAI has shut down.")


if __name__ == "__main__":
    main()
