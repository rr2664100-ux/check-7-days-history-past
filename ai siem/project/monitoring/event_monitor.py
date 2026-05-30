import threading
import time
from datetime import datetime
from typing import List
from utils.logger import logger
from utils.helpers import get_timestamp
from config.constants import EVENT_CHANNELS

try:
    import win32evtlog
except ImportError:  # pragma: no cover
    win32evtlog = None


class EventMonitor(threading.Thread):
    def __init__(self, database, settings: dict, stop_event: threading.Event, live_state=None):
        super().__init__(daemon=True)
        self.database = database
        self.settings = settings
        self.stop_event = stop_event
        self.live_state = live_state

    def run(self) -> None:
        if win32evtlog is None:
            logger.warning("pywin32 is not available. Event log monitoring is disabled.")
            return

        logger.info("Starting Windows Event Viewer monitor.")
        while not self.stop_event.is_set():
            self.collect_events()
            time.sleep(self.settings.get("event_poll_seconds", 20))

    def stop(self) -> None:
        self.stop_event.set()

    def collect_events(self) -> None:
        for channel in EVENT_CHANNELS:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    continue
                for event in events[:20]:
                    event_time = event.TimeGenerated.Format()
                    message = self._format_message(event)
                    category = self._get_category(event.EventType)
                    source = event.SourceName
                    self.database.insert_event(source, category, message, category)
                    if self._is_suspicious(event.EventID, source, message):
                        self.database.insert_alert(
                            f"Detected suspicious event from {source}: {message}",
                            "EventMonitor",
                            "Medium",
                            40,
                        )
                        if self.live_state and self._event_is_live(event_time):
                            self.live_state.add_suspicious_alert(
                                f"Suspicious Windows event detected: {source}",
                                "Warning",
                            )
                win32evtlog.CloseEventLog(handle)
            except Exception as exc:
                logger.debug("Event log scan error for %s: %s", channel, exc)

    def _format_message(self, event) -> str:
        try:
            return " ".join([str(part) for part in event.StringInserts or []]).strip() or "No details available"
        except Exception:
            return "Unable to parse event message"

    def _get_category(self, event_type: int) -> str:
        categories = {
            win32evtlog.EVENTLOG_AUDIT_FAILURE: "AuditFailure",
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: "AuditSuccess",
            win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
            win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
            win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
        }
        return categories.get(event_type, "Unknown")

    def _is_suspicious(self, event_id: int, source: str, message: str) -> bool:
        suspicious_ids = [4625, 4624, 7031, 7040, 6008, 1102, 4698, 4699, 7045]
        if event_id in suspicious_ids:
            logger.info("Suspicious event detected: %s - %s", event_id, source)
            return True
        return False

    def _event_is_live(self, event_time: str) -> bool:
        if not self.live_state or not getattr(self.live_state, "monitor_start_time", None):
            return False
        try:
            parsed_time = datetime.strptime(event_time, "%m/%d/%Y %H:%M:%S")
            return parsed_time >= self.live_state.monitor_start_time
        except Exception:
            return False
