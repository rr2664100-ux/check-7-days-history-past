import ctypes
import sys
from .logger import logger


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        logger.warning("Unable to determine administrator privileges.")
        return False


def request_admin() -> bool:
    if is_admin():
        return True

    executable = sys.executable
    params = "\"%s\"" % " ".join(sys.argv)
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
        return True
    except Exception as exc:
        logger.warning("Administrator privileges denied or unavailable: %s", exc)
        return False


def check_permission_mode() -> str:
    if is_admin():
        logger.info("Running with administrator permissions.")
        return "admin"
    logger.info("Running in limited monitoring mode without administrator permissions.")
    return "limited"
