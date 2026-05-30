import ctypes
import sys
import os
import psutil
import re
import shutil
import sqlite3
import threading
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Global placeholders for UI elements (to be initialized in create_ui)
root = None
cpu_label = None
ram_label = None
disk_label = None
critical_label = None
status_label = None
threat_level_label = None
current_apps_frame = None
activity_frame = None
security_frame = None
app_cards = {}
activity_items = []
top_ram_app_label = None
failed_logins_label = None
usb_devices_label = None
malware_label = None
success_logins_label = None
remote_alerts_label = None
search_var = None
search_entry = None
conn = None
cur = None

# Failed Login Tracking
last_failed_user = None
consecutive_failures = 0
failed_login_count = 0

try:
    from PIL import Image
    import win32api, win32ui, win32con
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    # Define dummy class to avoid NameError
    class FileSystemEventHandler: pass
    class Observer: 
        def schedule(self, *args, **kwargs): pass
        def start(self): pass
        def stop(self): pass
        def join(self): pass

# Try importing Windows-specific modules with graceful fallback
try:
    import win32evtlog
    import win32gui
    import win32process
    WIN32_AVAILABLE = True
except ImportError as e:
    print(f'[WARNING] Windows modules not available: {e}')
    print('[WARNING] Install with: pip install pywin32')
    WIN32_AVAILABLE = False
    win32evtlog = None
    win32gui = None
    win32process = None

import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
try:
    from monitoring.event_history_loader import load_historical_events, parse_security_event
except ImportError as e:
    print(f'[WARNING] Failed to import event_history_loader: {e}')
    load_historical_events = None
    parse_security_event = None

# ============================================================================
# CONFIGURATION & GLOBAL STATE
# ============================================================================

DB_PATH = Path('siem_events.db')
monitoring = False
monitoring_lock = threading.Lock()
stop_event = threading.Event()

# Tracking sets to avoid duplicate alerts
seen_event_records = set()
seen_urls = set()
seen_processes = set()
previous_processes = set()
seen_files = {}
last_active_window = ''
last_system_metrics = {}

# Thread-safe locks
lock = threading.Lock()
ui_lock = threading.Lock()

# UI Elements (initialized after root creation)
root = None
output_box = None  # DEPRECATED - kept for compatibility
cpu_label = None
ram_label = None
disk_label = None
critical_label = None
status_label = None
threat_level_label = None

# NEW UI ELEMENTS - Dashboard panels
current_apps_frame = None  # Left panel
activity_frame = None      # Center panel
security_frame = None      # Right panel
app_cards = {}  # Dict to store app card widgets: {app_name: frame}
activity_items = []  # List of recent activity items
top_ram_app_label = None
failed_logins_label = None
usb_devices_label = None
malware_label = None
success_logins_label = None
remote_alerts_label = None
search_var = None
search_entry = None

# Event categorization
failed_login_count = 0
usb_device_count = 0
active_usb_drives = set()
icon_cache = {}

def get_exe_icon(exe_path, size=32):
    if exe_path in icon_cache:
        return icon_cache[exe_path]
    if not WIN32_AVAILABLE or not PIL_AVAILABLE or not os.path.exists(exe_path):
        return None
        
    try:
        ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
        ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)

        large, small = win32gui.ExtractIconEx(exe_path, 0)
        if not large:
            return None
            
        win32api.DestroyIcon(small[0])
        
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_y)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)
        hdc.DrawIcon((0,0), large[0])
        
        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)
        img = Image.frombuffer(
            'RGBA',
            (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
            bmpstr, 'raw', 'BGRA', 0, 1
        )
        
        win32gui.DestroyIcon(large[0])
        
        ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
        icon_cache[exe_path] = ctk_img
        return ctk_img
    except Exception as e:
        icon_cache[exe_path] = None
        return None

APP_INFO = {
    "chrome.exe": ("Google Chrome", "🌐"),
    "msedge.exe": ("Microsoft Edge", "🔵"),
    "firefox.exe": ("Mozilla Firefox", "🦊"),
    "winword.exe": ("Microsoft Word", "📄"),
    "powerpnt.exe": ("Microsoft PowerPoint", "📊"),
    "excel.exe": ("Microsoft Excel", "📈"),
    "acrord32.exe": ("Adobe Reader", "📕"),
    "explorer.exe": ("File Explorer", "📁"),
    "code.exe": ("VS Code", "💻"),
    "discord.exe": ("Discord", "🎮"),
    "vlc.exe": ("VLC Player", "🎬"),
    "spotify.exe": ("Spotify", "🎵"),
    "whatsapp.exe": ("WhatsApp", "📱"),
    "notepad.exe": ("Notepad", "📝"),
    "calculator.exe": ("Calculator", "🧮"),
    "cmd.exe": ("Command Prompt", "⌨️"),
    "powershell.exe": ("PowerShell", "🐚"),
    "telegram.exe": ("Telegram", "✈️"),
    "slack.exe": ("Slack", "💬"),
    "zoom.exe": ("Zoom", "📹"),
    "teams.exe": ("Microsoft Teams", "👥")
}

# Strict Whitelist Mode - Only track apps user actually interacts with
WHITELISTED_APPS = set(APP_INFO.keys()) | {
    "notepad++.exe", "sublime_text.exe", "pycharm64.exe", "visualstudio.exe",
    "git-bash.exe", "putty.exe", "winscp.exe", "filezilla.exe"
}

def get_app_info(exe_name):
    if exe_name in APP_INFO:
        return APP_INFO[exe_name]
    friendly = exe_name.replace('.exe', '').title()
    return (friendly, "❓")

interesting_sites = [
    ('GitHub', 'github.com'),
    ('ChatGPT', 'chat.openai.com'),
    ('ChatGPT', 'chatgpt.com'),
    ('YouTube', 'youtube.com'),
    ('WhatsApp Web', 'web.whatsapp.com'),
]



suspicious_exes = {
    'mimikatz.exe',
    'cobaltstrike.exe',
    'meterpreter.exe',
    'rundll32.exe',
    'psexec.exe',
}

file_scan_dirs = [
    Path.home() / 'Desktop',
    Path.home() / 'Downloads',
    Path.home() / 'Documents',
]

chrome_history_paths = [
    Path(os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History')),
    Path(os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History')),
]

firefox_profile_path = Path(os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'))
firefox_history_paths = list(firefox_profile_path.glob('*.default-release/places.sqlite')) if firefox_profile_path.exists() else []

# File Monitoring Extensions
DOWNLOAD_EXTS = {'.exe', '.msi', '.zip', '.rar', '.7z', '.pdf', '.docx', '.xlsx', '.pptx'}

# ============================================================================
# LOGGING & OUTPUT FUNCTIONS
# ============================================================================

def debug_log(message: str):
    """Log debug messages with timestamp."""
    try:
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f'[{timestamp}] [DEBUG] {message}')
    except Exception as e:
        print(f'[ERROR] debug_log failed: {e}')


def append_output(message: str):
    """
    DEPRECATED - Legacy function kept for compatibility.
    No longer appends to textbox since we use dynamic cards now.
    Silently discarded (was causing spam).
    """
    # Simply do nothing - prevents spam
    pass


def update_label_safe(label_ref: str, text: str):
    """Safely update a label using root.after()."""
    try:
        if root is None:
            return
        
        def do_update():
            try:
                label = globals().get(label_ref)
                if label is not None:
                    label.configure(text=text)
            except Exception as e:
                debug_log(f'Failed to update {label_ref}: {e}')
        
        root.after(0, do_update)
    except Exception as e:
        debug_log(f'update_label_safe error: {e}')


# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def init_database():
    """Initialize SQLite database for storing events."""
    try:
        with lock:
            conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            cur = conn.cursor()
            
            tables = ['app_history', 'browser_history', 'security_history', 'usb_history', 'alerts', 'events']
            for table in tables:
                cur.execute(f'''CREATE TABLE IF NOT EXISTS {table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    title TEXT,
                    details TEXT,
                    severity TEXT,
                    record_number INTEGER,
                    source_log TEXT,
                    url TEXT,
                    domain TEXT,
                    file_path TEXT,
                    file_ext TEXT
                )''')
                
                # Ensure columns exist
                for col in ['record_number', 'source_log', 'category', 'url', 'domain', 'file_path', 'file_ext']:
                    try:
                        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
                    except sqlite3.OperationalError: pass
                
            conn.commit()
            debug_log(f'Database initialized at {DB_PATH}')
        return conn, cur
    except Exception as e:
        debug_log(f'Database initialization failed: {e}')
        return None, None

def periodic_cleanup():
    while not stop_event.is_set():
        cleanup_old_logs()
        stop_event.wait(86400)

def cleanup_old_logs():
    """Delete logs older than 7 days automatically."""
    try:
        if conn is None or cur is None:
            return
        with lock:
            tables = ['app_history', 'browser_history', 'security_history', 'usb_history', 'alerts', 'events']
            total_deleted = 0
            for table in tables:
                try:
                    cur.execute(f"DELETE FROM {table} WHERE timestamp < datetime('now', '-7 days')")
                    total_deleted += cur.rowcount
                except sqlite3.OperationalError:
                    pass
            conn.commit()
            if total_deleted > 0:
                debug_log(f'Cleaned up {total_deleted} old logs older than 7 days.')
    except Exception as e:
        debug_log(f'cleanup_old_logs error: {e}')


conn, cur = init_database()


def save_event(category: str, severity: str, details: str):
    """Legacy save_event. Routes to alerts table now for backwards compatibility."""
    log_event_to_table('alerts', category, category, details, severity)

def log_event_to_table(table: str, event_type: str, title: str, details: str, severity: str, timestamp: str = None, record_number: int = None, source_log: str = None):
    try:
        if conn is None or cur is None: return
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        with lock:
            if record_number is not None:
                # Check for duplicate record in same source log
                cur.execute(f"SELECT COUNT(*) FROM {table} WHERE record_number = ? AND source_log = ?", (record_number, source_log))
                if cur.fetchone()[0] > 0:
                    return
            
            cur.execute(
                f'INSERT INTO {table}(timestamp, event_type, title, details, severity, record_number, source_log) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (timestamp, event_type, title, details, severity, record_number, source_log),
            )
            conn.commit()
    except Exception as e:
        debug_log(f'Failed to save event to {table}: {e}')

def log_security_history(title: str, details: str, severity: str = "HIGH", ts: str = None, rec: int = None):
    log_event_to_table('security_history', 'Security', title, details, severity, timestamp=ts, record_number=rec, source_log='Security')

def log_app_history(title: str, details: str, severity: str = "LOW", ts: str = None, rec: int = None):
    log_event_to_table('app_history', 'Application', title, details, severity, timestamp=ts, record_number=rec, source_log='App')

def log_browser_history(title: str, browser: str, title_page: str, domain: str, url: str):
    log_event_to_table('browser_history', 'Browser', title_page, f"{domain} | {url}", "LOW", source_log=browser)

def log_security_history(title: str, details: str, severity: str = "HIGH", ts: str = None, rec: int = None):
    log_event_to_table('security_history', 'Security', title, details, severity, timestamp=ts, record_number=rec, source_log='Security')

def log_usb_history(title: str, details: str, severity: str = "MEDIUM", ts: str = None, rec: int = None):
    log_event_to_table('usb_history', 'USB', title, details, severity, timestamp=ts, record_number=rec, source_log='USB')

def log_file_history(event_type: str, file_name: str, file_path: str, severity: str = "LOW"):
    ext = os.path.splitext(file_name)[1].lower()
    log_event_to_table('app_history', 'File', f"{event_type}: {file_name}", f"Path: {file_path}", severity, source_log='FileMonitor')


def get_critical_count():
    """Get count of critical alerts from database."""
    try:
        if conn is None or cur is None:
            return 0
        with lock:
            result = cur.execute('SELECT COUNT(*) FROM events WHERE severity = ?', ('CRITICAL',)).fetchone()
        return result[0] if result else 0
    except Exception as e:
        debug_log(f'Failed to get critical count: {e}')
        return 0


# ============================================================================
# ALERT & EVENT HANDLING
# ============================================================================

def log_background(category: str, severity: str, details: str):
    """
    Silently save event to database without showing in UI.
    For background monitoring that should not spam the dashboard.
    """
    try:
        save_event(category, severity, details)
    except Exception as e:
        debug_log(f'log_background error: {e}')


def populate_security_summary():
    """Update the right-side security summary panel with real-time stats."""
    try:
        if conn and cur:
            with lock:
                # 1. Failed Logins (7 Days)
                cur.execute("SELECT COUNT(*) FROM security_history WHERE event_type='Security' AND title LIKE '%Failed Login%' AND timestamp > datetime('now', '-7 days')")
                failed = cur.fetchone()[0]
                
                # 2. Successful Logins
                cur.execute("SELECT COUNT(*) FROM security_history WHERE event_type='Security' AND title LIKE '%Successful Login%' AND timestamp > datetime('now', '-7 days')")
                success = cur.fetchone()[0]
                
                # 3. USB Devices
                cur.execute("SELECT COUNT(*) FROM usb_history WHERE timestamp > datetime('now', '-7 days')")
                usb_events = cur.fetchone()[0]
                
                # 4. Suspicious Activity (High severity alerts)
                cur.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL') AND timestamp > datetime('now', '-7 days')")
                suspicious = cur.fetchone()[0]
                
                # 5. Malware (Critical severity specific)
                cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND timestamp > datetime('now', '-7 days')")
                malware = cur.fetchone()[0]
                
            def do_update():
                if failed_logins_label:
                    failed_logins_label.configure(
                        text=f"🔴 Failed Logins (7 Days): {failed}", 
                        text_color="#ff6b6b" if failed > 0 else "#1dd1a1"
                    )
                if success_logins_label:
                    success_logins_label.configure(text=f"🟢 Successful Logins: {success}", text_color="#1dd1a1")
                if usb_devices_label:
                    usb_devices_label.configure(
                        text=f"🟠 USB Devices Connected: {usb_events}",
                        text_color="#feca57" if usb_events > 0 else "gray"
                    )
                if remote_alerts_label:
                    remote_alerts_label.configure(
                        text=f"⚠ Suspicious Activity: {suspicious}",
                        text_color="#ff9f43" if suspicious > 0 else "gray"
                    )
                if malware_label:
                    malware_label.configure(
                        text=f"🛡 Malware Detected: {'Yes' if malware > 0 else 'No'}",
                        text_color="#ff6b6b" if malware > 0 else "#1dd1a1"
                    )
            
            root.after(0, do_update)
    except Exception as e:
        debug_log(f"populate_security_summary error: {e}")

def update_security_labels():
    populate_security_summary()

def update_app_card(app_name: str, status: str, ram_mb: float, is_high_ram: bool, icon_text: str = '❓', ctk_img=None):
    """Update or create app card in left panel."""
    if root is None or current_apps_frame is None:
        return
        
    def do_update():
        
        color = "#1dd1a1" if status == "Active" else ("#54a0ff" if status == "Background" else "#ff9f43" if is_high_ram else "#576574")
        if status == "Closed":
            color = "#576574"
        if "High RAM" in status or "High CPU" in status:
            color = "#ff6b6b"
            
        if app_name in app_cards:
            card_data = app_cards[app_name]
            card_data['frame'].configure(border_color=color)
            card_data['status'].configure(text=status, text_color=color)
            card_data['ram'].configure(text=f"RAM: {ram_mb:.1f} MB")
            if ctk_img:
                card_data['icon_lbl'].configure(image=ctk_img, text="")
        else:
            card = ctk.CTkFrame(current_apps_frame, corner_radius=10, border_width=1, border_color=color)
            card.pack(fill="x", pady=5, padx=5)
            
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=(5,0))
            
            icon_lbl = ctk.CTkLabel(header, text=icon_text if not ctk_img else "", image=ctk_img)
            icon_lbl.pack(side="left", padx=(0,5))
            
            ctk.CTkLabel(header, text=f"{app_name}", font=('Helvetica', 14, 'bold')).pack(side="left")
            
            ram_lbl = ctk.CTkLabel(card, text=f"RAM: {ram_mb:.1f} MB", font=('Helvetica', 12))
            ram_lbl.pack(anchor="w", padx=10)
            
            status_lbl = ctk.CTkLabel(card, text=status, font=('Helvetica', 12, 'bold'), text_color=color)
            status_lbl.pack(anchor="w", padx=10, pady=(0,5))
            
            app_cards[app_name] = {
                'frame': card,
                'status': status_lbl,
                'ram': ram_lbl,
                'icon_lbl': icon_lbl
            }
    
    root.after(0, do_update)

def show_live_activity(title: str, details: str = None, color_override: str = None, browser_info: dict = None, icon: str = None):
    """
    Display important live activity in UI with professional modern cards.
    Supports website-specific cards with browser info and custom icons.
    """
    try:
        if root is None or activity_frame is None:
            return
            
        def do_update():
            color = color_override or "gray"
            msg = (title + (details or "")).lower()
            
            # Smart coloring
            if not color_override:
                if "🔴" in title or "[security]" in msg or "failed" in msg: color = "#ff6b6b"
                elif "🟡" in title or "⚠️" in title or "usb" in msg: color = "#feca57"
                elif "🟢" in title or "✅" in title or "opened" in msg: color = "#1dd1a1"
                elif "🔵" in title or "🌐" in title or "browser" in msg: color = "#48dbfb"
                else: color = "#576574"
                
            card = ctk.CTkFrame(activity_frame, corner_radius=15, border_width=2, border_color=color, fg_color="#1a1a1a")
            card.pack(fill="x", pady=6, padx=10)
            
            # Main Layout
            content = ctk.CTkFrame(card, fg_color="transparent")
            content.pack(fill="x", padx=15, pady=10)
            
            # Left side: Icon/Marker
            icon_text = icon if icon else ("🌐" if browser_info else (title[0] if title else "ℹ️"))
            if "🔴" in title or "[security]" in msg: icon_text = "🔒"
            if "⬇️" in title or "download" in msg: icon_text = "⬇️"
            if "🗑️" in title or "delete" in msg: icon_text = "🗑️"
            if "📄" in title: icon_text = "📄"
            
            icon_lbl = ctk.CTkLabel(content, text=icon_text, font=('Helvetica', 24))
            icon_lbl.pack(side="left", padx=(0, 15))
            
            # Middle: Text Info
            text_frame = ctk.CTkFrame(content, fg_color="transparent")
            text_frame.pack(side="left", fill="both", expand=True)
            
            if browser_info:
                # Website Card Format
                ctk.CTkLabel(text_frame, text=browser_info.get('site', 'Website'), font=('Helvetica', 16, 'bold'), text_color=color, anchor="w").pack(fill="x")
                ctk.CTkLabel(text_frame, text=f"Browser: {browser_info.get('browser', 'Unknown')}", font=('Helvetica', 11), text_color="gray", anchor="w").pack(fill="x")
                ctk.CTkLabel(text_frame, text=f"Tab: {browser_info.get('tab', 'Active Tab')}", font=('Helvetica', 12), text_color="lightgray", wraplength=400, anchor="w", justify="left").pack(fill="x")
            else:
                # Standard Activity Format
                ctk.CTkLabel(text_frame, text=title, font=('Helvetica', 14, 'bold'), text_color=color, anchor="w").pack(fill="x")
                if details:
                    ctk.CTkLabel(text_frame, text=details, font=('Helvetica', 12), text_color="lightgray", wraplength=400, anchor="w", justify="left").pack(fill="x")
            
            # Right side: Timestamp
            time_lbl = ctk.CTkLabel(content, text=datetime.now().strftime('%I:%M %p'), font=('Helvetica', 10), text_color="gray")
            time_lbl.pack(side="right", anchor="n")
            
            # Auto-scroll and retention
            activity_items.append(card)
            if len(activity_items) > 50:
                old_card = activity_items.pop(0)
                old_card.destroy()
                
        root.after(0, do_update)
    except Exception as e:
        debug_log(f'show_live_activity error: {e}')


def show_alert(category: str, severity: str, details: str):
    """
    DEPRECATED: Use log_background() or show_live_activity() instead.
    This function mixes database logging with UI display - causes spam.
    Kept for compatibility but should be phased out.
    """
    try:
        message = f'[{severity:8s}] {datetime.now().strftime("%H:%M:%S")} - {category}: {details}\n'
        save_event(category, severity, details)
        append_output(message)
        
        # Update critical count if severity is CRITICAL
        if severity == 'CRITICAL':
            count = get_critical_count()
            update_label_safe('critical_label', f'Critical Alerts: {count}')
        
        debug_log(f'{category} [{severity}]: {details}')
    except Exception as e:
        debug_log(f'show_alert error: {e}')






# ============================================================================
# WINDOWS EVENT LOG MONITORING
# ============================================================================

def parse_event(event, logtype: str) -> bool:
    """
    Parse Windows event and display if significant.
    Correctly counts failed logins and handles security events.
    """
    global failed_login_count, last_failed_user, consecutive_failures
    try:
        event_id = int(getattr(event, 'EventID', 0) & 0xFFFF)
        
        if event_id == 4625: # Failed Login
            user = "Unknown User"
            try:
                # Extract user from event data if available
                if hasattr(event, 'StringInserts') and event.StringInserts:
                    user = event.StringInserts[5] # TargetUserName usually at index 5
            except: pass
            
            if user == last_failed_user:
                consecutive_failures += 1
            else:
                last_failed_user = user
                consecutive_failures = 1
                
            failed_login_count += 1
            show_live_activity(
                f"🔴 Failed Login Attempt", 
                f"User {user} entered wrong password {consecutive_failures} times", 
                color_override="#ff6b6b"
            )
            log_security_history("Failed Login Attempt", f"User: {user} | Attempts: {consecutive_failures}", "HIGH")
            populate_security_summary()
            return True
            
        elif event_id == 4624: # Success Login
            user = "Unknown User"
            try:
                if hasattr(event, 'StringInserts') and event.StringInserts:
                    user = event.StringInserts[5]
            except: pass
            
            show_live_activity("🟢 Successful Login", f"User {user} logged in successfully", color_override="#1dd1a1")
            log_security_history("Successful Login", f"User: {user}", "LOW")
            last_failed_user = None
            consecutive_failures = 0
            populate_security_summary()
            return True
            
        elif event_id == 4634: # Logoff
            show_live_activity("ℹ️ User Logged Off", "A user session has ended", color_override="#54a0ff")
            log_security_history("User Logged Off", "User logged out", "LOW")
            return True
            
        elif event_id == 4648: # Explicit Credentials
            show_live_activity("🟠 Explicit Credentials Used", "A logon attempt with explicit credentials", color_override="#ff9f43")
            log_security_history("Explicit Credentials Used", "Logon with explicit credentials", "MEDIUM")
            return True
            
        elif event_id == 6416: # USB Connect
            show_live_activity("🟠 USB Device Connected", "A new hardware device was plugged in", color_override="#feca57")
            log_usb_history("USB Device Connected", "Hardware plugged in")
            populate_security_summary()
            return True
            
        elif event_id == 1102: # Log Cleared
            show_live_activity("🚨 Security Log Cleared", "The security audit log was wiped!", color_override="#ff6b6b")
            log_security_history("Security Log Cleared", "The security audit log was cleared", "CRITICAL")
            return True
            
        elif event_id == 6008: # Unexpected Shutdown
            show_live_activity("🚨 Unexpected Shutdown", "The previous system shutdown was unexpected", color_override="#ff6b6b")
            log_security_history("Unexpected Shutdown", "System shut down unexpectedly", "MEDIUM")
            return True
        return False
    except Exception as e:
        debug_log(f'parse_event error: {e}')
        return False


def event_time(event):
    """Extract timestamp from event."""
    try:
        timestamp = getattr(event, 'TimeGenerated', None)
        if hasattr(timestamp, 'year'):
            return timestamp
        return datetime.fromtimestamp(time.mktime(timestamp.timetuple()))
    except Exception:
        return datetime.now()


def load_old_windows_events():
    """Load historical events from Windows Event Viewer (last 7 days)."""
    try:
        if not WIN32_AVAILABLE:
            return
            
        show_live_activity("⏳ [SYSTEM] Loading 7-day historical events...")
        server = 'localhost'
        from datetime import datetime, timedelta
        seven_days_ago = datetime.now() - timedelta(days=7)
        
        logs_to_scan = [
            ('Security', [4625, 4624, 4800, 4801, 1102]), # Failed Login, Success Login, Lock, Unlock, Log Clear
            ('System', [1, 1074, 6005, 6006, 6008, 6416]),# Power events, Startup/Shutdown, Unexpected, USB
            ('Application', [])
        ]
        
        counts = {"Failed": 0, "Success": 0, "Total": 0}
        
        for log_name, ids in logs_to_scan:
            try:
                hand = win32evtlog.OpenEventLog(server, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while not stop_event.is_set():
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events: break
                    
                    stop_scan = False
                    for event in events:
                        if event.TimeGenerated < seven_days_ago:
                            stop_scan = True
                            break
                            
                        eid = event.EventID & 0xFFFF
                        ts = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                        rec = event.RecordNumber
                        
                        if eid == 4625:
                            counts["Failed"] += 1
                            log_security_history("Failed Login Attempt", f"Wrong password entered", "HIGH", ts, rec)
                        elif eid == 4624:
                            counts["Success"] += 1
                            log_security_history("Successful Login", "User logged in successfully", "LOW", ts, rec)
                        elif eid == 4634:
                            log_security_history("User Logged Off", "User logged out from session", "LOW", ts, rec)
                        elif eid == 4648:
                            log_security_history("Explicit Credentials Used", "A logon was attempted using explicit credentials", "MEDIUM", ts, rec)
                        elif eid == 1102:
                            log_security_history("Security Log Cleared", "The security audit log was cleared", "CRITICAL", ts, rec)
                        elif eid == 6416:
                            log_usb_history("USB Device Connected", "Hardware device plugged in (Historical)", "MEDIUM", ts, rec)
                        elif eid in [6005, 6006]:
                            status = "Started" if eid == 6005 else "Shut Down"
                            log_security_history(f"System {status}", f"Windows system {status.lower()}", "LOW", ts, rec)
                        elif eid == 6008:
                            log_security_history("Unexpected Shutdown", "System shut down unexpectedly", "MEDIUM", ts, rec)
                        
                        counts["Total"] += 1
                        
                    if stop_scan: break
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                debug_log(f"Error scanning {log_name}: {e}")
            
        show_live_activity(f"✅ [SECURITY] History Loaded: {counts['Failed']} Failed logins detected in last 7 days.")
        populate_security_summary()
    except Exception as e:
        debug_log(f"load_old_windows_events error: {e}")


def monitor_windows_logs_live():
    """
    Monitor Windows Security event log in real-time.
    Runs in background thread.
    """
    if not WIN32_AVAILABLE:
        log_background('Security Monitor', 'MEDIUM', 'Windows modules not available')
        return
    
    try:
        # Pre-fill seen_event_records with the most recent events to avoid initial spam
        handle = win32evtlog.OpenEventLog('localhost', 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if events:
            for event in events:
                record = getattr(event, 'RecordNumber', None)
                if record is not None:
                    seen_event_records.add(record)
        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        debug_log(f'Failed initial Security log read: {e}')
    
    show_live_activity('✅ [MONITOR] Security log monitoring started')
    
    while not stop_event.is_set():
        try:
            handle = win32evtlog.OpenEventLog('localhost', 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            batch_events = []
            hit_seen = False
            
            while not hit_seen and not stop_event.is_set():
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    record = getattr(event, 'RecordNumber', None)
                    if record is None or record in seen_event_records:
                        hit_seen = True
                        break
                        
                    seen_event_records.add(record)
                    batch_events.append(event)
                    
            win32evtlog.CloseEventLog(handle)
            
            # Process events chronologically
            for event in reversed(batch_events):
                try:
                    parse_event(event, 'Security')
                except Exception as e:
                    debug_log(f'Error processing live event: {e}')
            
        except Exception as e:
            debug_log(f'monitor_windows_logs_live error: {e}')
            
        stop_event.wait(2)  # Check every 2 seconds, but allow instant stop


# ============================================================================
# BROWSER HISTORY MONITORING
# ============================================================================

def copy_history_file(history_path: Path) -> Path | None:
    """Copy Chrome/Edge history to temp to avoid file lock."""
    try:
        temp_dir = Path(os.getenv('TEMP', r'C:\Windows\Temp'))
        temp_dir.mkdir(parents=True, exist_ok=True)
        copy_path = temp_dir / f'history_copy_{int(time.time() * 1000)}.db'
        shutil.copy2(str(history_path), str(copy_path))
        return copy_path
    except Exception as e:
        debug_log(f'Failed to copy history: {e}')
        return None


def read_browser_history(db_path: Path) -> list[str]:
    """Read URLs from Chrome/Edge history database."""
    results = []
    try:
        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 300')
        
        for row in cur.fetchall():
            if row and row[0]:
                results.append(str(row[0]))
        
        conn.close()
    except Exception as e:
        debug_log(f'Failed to read browser history: {e}')
    finally:
        try:
            db_path.unlink()
        except Exception:
            pass
    
    return results


def scan_browser_history():
    """Scan Chrome, Edge, and Firefox history."""
    global seen_urls
    first_run = not bool(seen_urls)
    
    # Check Chrome and Edge
    for history_path in chrome_history_paths:
        if not history_path.exists(): continue
        browser_name = "Chrome" if "Chrome" in str(history_path) else "Edge"
        browser_icon = "🌐" if browser_name == "Chrome" else "🔵"
        
        temp_path = copy_history_file(history_path)
        if not temp_path: continue
        
        try:
            conn_hist = sqlite3.connect(str(temp_path))
            cur_hist = conn_hist.cursor()
            cur_hist.execute('SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20')
            for url, title, _ in cur_hist.fetchall():
                if url in seen_urls: continue
                seen_urls.add(url)
                
                domain = url.split('/')[2] if '//' in url else url
                log_browser_history(title, browser_name, title or domain, domain, url)
                
                if not first_run:
                    show_live_activity(f"{browser_icon} {browser_name}: {title[:50]}", f"URL: {url}", icon="🌐")
            conn_hist.close()
        except: pass
        finally: 
            try: temp_path.unlink()
            except: pass

    # Check Firefox
    for history_path in firefox_history_paths:
        if not history_path.exists(): continue
        temp_path = copy_history_file(history_path)
        if not temp_path: continue
        
        try:
            conn_hist = sqlite3.connect(str(temp_path))
            cur_hist = conn_hist.cursor()
            cur_hist.execute('SELECT url, title FROM moz_places ORDER BY last_visit_date DESC LIMIT 20')
            for url, title in cur_hist.fetchall():
                if url in seen_urls: continue
                seen_urls.add(url)
                domain = url.split('/')[2] if '//' in url else url
                log_browser_history(title, "Firefox", title or domain, domain, url)
                if not first_run:
                    show_live_activity(f"🦊 Firefox: {title[:50]}", f"URL: {url}", icon="🦊")
            conn_hist.close()
        except: pass
        finally:
            try: temp_path.unlink()
            except: pass


def monitor_browser_live():
    """Monitor browser history in real-time."""
    show_live_activity('✅ [MONITOR] Browser monitoring started')
    
    while not stop_event.is_set():
        try:
            scan_browser_history()
        except Exception as e:
            debug_log(f'monitor_browser_live error: {e}')
        
        stop_event.wait(15)  # Check every 15 seconds, but allow instant stop


# ============================================================================
# PROCESS & APPLICATION MONITORING
# ============================================================================

def monitor_apps_live():
    """Monitor running processes dynamically."""
    global previous_processes, app_start_times
    app_start_times = {}
    
    show_live_activity('✅ [MONITOR] Application monitoring started')
    previous_processes = set()
    
    while not stop_event.is_set():
        try:
            current_processes = set()
            app_stats = {}
            app_icons = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    name = proc.info.get('name', '').lower()
                    if not name:
                        continue
                    
                    current_processes.add(name)
                    
                    try:
                        exe_path = proc.exe()
                        if exe_path:
                            drive = exe_path[:2].upper()
                            if drive in active_usb_drives and name not in previous_processes:
                                show_live_activity(f'🔴 [CRITICAL] EXE Executed From USB Drive: {name}')
                                save_event('USB Execution', 'CRITICAL', f'Launched {exe_path} from USB')
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe_path = ''
                        
                    # Check for powershell injection
                    if name == 'powershell.exe' and name not in previous_processes:
                        try:
                            cmdline = " ".join(proc.cmdline()).lower()
                            if '-enc' in cmdline or '-encodedcommand' in cmdline:
                                show_live_activity(f'🔴 [CRITICAL] Encoded PowerShell Detected!')
                                save_event('PowerShell Injection', 'CRITICAL', f'Encoded command: {cmdline[:100]}')
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass

                    if name in WHITELISTED_APPS:
                        app_name, icon = get_app_info(name)
                        mem = proc.info.get('memory_info')
                        ram_mb = mem.rss / 1024 / 1024 if mem else 0.0
                        
                        ctk_img = get_exe_icon(exe_path) if exe_path else None
                        
                        if app_name not in app_stats:
                            app_stats[app_name] = ram_mb
                            app_icons[app_name] = (icon, ctk_img)
                        else:
                            app_stats[app_name] += ram_mb
                    
                    # Check if it's a new app
                    if name in WHITELISTED_APPS and name not in previous_processes:
                        app_name, icon = get_app_info(name)
                        show_live_activity(f'✨ [APP OPENED] {icon} {app_name}')
                        save_event('App Opened', 'LOW', f'{app_name} started')
                    
                    # Check for suspicious executables
                    if name in suspicious_exes and name not in previous_processes:
                        show_live_activity(f'🚨 [SUSPICIOUS] {name} detected!')
                        save_event('SUSPICIOUS EXE', 'CRITICAL', f'Detected: {name}')
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    pass
            
            # Update app cards for apps that use more than 50MB or are common apps
            for app_name, ram_mb in app_stats.items():
                if ram_mb > 50 or app_name in [v[0] for v in APP_INFO.values()]:
                    is_high_ram = ram_mb > 500
                    status = "Using High RAM" if is_high_ram else "Active"
                    icon_text, ctk_img = app_icons.get(app_name, ('❓', None))
                    update_app_card(app_name, status, ram_mb, is_high_ram, icon_text, ctk_img)
            
            # Detect closed apps
            closed_apps = previous_processes - current_processes
            for name in closed_apps:
                if name in WHITELISTED_APPS:
                    app_name, icon = get_app_info(name)
                    duration_str = ""
                    if name in app_start_times:
                        duration = datetime.now() - app_start_times[name]
                        mins = int(duration.total_seconds() / 60)
                        duration_str = f" used for {mins} mins"
                        del app_start_times[name]
                    
                    show_live_activity(f'⛔ [APP CLOSED] {icon} {app_name}{duration_str}')
                    log_app_history(f"{app_name} Closed", f"App session ended{duration_str}")
                    update_app_card(app_name, "Closed", 0.0, False, icon)
            
            # Track start times for usage duration
            for name in current_processes:
                if name in WHITELISTED_APPS and name not in app_start_times:
                    app_start_times[name] = datetime.now()
            
            previous_processes = current_processes
        
        except Exception as e:
            debug_log(f'monitor_apps_live error: {e}')
        
        stop_event.wait(3)  # Check every 3 seconds, but allow instant stop


# ============================================================================
# USB DEVICE MONITORING
# ============================================================================

def monitor_usb_live():
    """Monitor USB devices being inserted/removed."""
    global usb_device_count
    show_live_activity('✅ [MONITOR] USB device monitoring started')
    previous = set()
    
    while not stop_event.is_set():
        try:
            current = set()
            
            # Check all drive letters
            for letter in map(chr, range(65, 91)):
                drive = f'{letter}:\\'
                try:
                    if os.path.exists(drive):
                        # Check if it's a removable drive (USB)
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            current.add(drive)
                except Exception:
                    continue
            
            # Detect new USB drives
            added = current - previous
            for drive in added:
                usb_device_count += 1
                active_usb_drives.add(drive[:2].upper())
                update_security_labels()
                try:
                    volume_info = os.popen(f'vol {drive}').read()
                    show_live_activity(f'🔌 [USB CONNECTED] Device on {drive}')
                    log_usb_history(f'USB Connected on {drive}', 'Device inserted', 'MEDIUM')
                except Exception:
                    show_live_activity(f'🔌 [USB CONNECTED] Device on {drive}')
                    log_usb_history(f'USB Connected on {drive}', 'Device inserted', 'MEDIUM')
            
            # Detect removed USB drives
            removed = previous - current
            for drive in removed:
                usb_device_count = max(0, usb_device_count - 1)
                active_usb_drives.discard(drive[:2].upper())
                update_security_labels()
                show_live_activity(f'🔌 [USB REMOVED] Device from {drive}')
                log_usb_history(f'USB Removed from {drive}', 'Device removed', 'LOW')
            
            previous = current
        
        except Exception as e:
            debug_log(f'monitor_usb_live error: {e}')
        
        stop_event.wait(5)  # Check every 5 seconds, but allow instant stop


# ============================================================================
# FILE ACTIVITY MONITORING (DOWNLOADS & DELETIONS)
# ============================================================================

class FileActivityHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_name = os.path.basename(event.src_path)
            ext = os.path.splitext(file_name)[1].lower()
            if ext in DOWNLOAD_EXTS:
                show_live_activity(f"⬇️ Download Detected: {file_name}", f"Location: {os.path.dirname(event.src_path)}", icon="⬇️")
                log_file_history("Download", file_name, event.src_path, "LOW")

    def on_deleted(self, event):
        if not event.is_directory:
            file_name = os.path.basename(event.src_path)
            show_live_activity(f"🗑️ File Deleted: {file_name}", f"Original Path: {os.path.dirname(event.src_path)}", icon="🗑️", color_override="#ff6b6b")
            log_file_history("Deletion", file_name, event.src_path, "MEDIUM")

def monitor_files_live():
    """Start watchdog file monitoring."""
    if not WATCHDOG_AVAILABLE:
        debug_log("Watchdog not available. File monitoring disabled.")
        return

    observer = Observer()
    handler = FileActivityHandler()
    for directory in file_scan_dirs:
        if directory.exists():
            observer.schedule(handler, str(directory), recursive=False)
    
    observer.start()
    try:
        while not stop_event.is_set():
            stop_event.wait(1)
    finally:
        observer.stop()
        observer.join()


# ============================================================================
# ACTIVE WINDOW MONITORING
# ============================================================================

def extract_website_info(title, process_name):
    """
    Enhanced browser tab parsing for Chrome, Edge, and Firefox.
    Extracts cleaner site names and tab titles.
    """
    browser = None
    browser_icon = "🌐"
    
    if 'chrome.exe' in process_name:
        browser = "Chrome"
        browser_icon = "🌐"
    elif 'msedge.exe' in process_name:
        browser = "Edge"
        browser_icon = "🔵"
    elif 'firefox.exe' in process_name:
        browser = "Firefox"
        browser_icon = "🦊"
    else:
        return None, None, None
        
    # Standard format for browsers: "Tab Title - Browser Name"
    # But sometimes it's just "Tab Title" or includes URLs
    
    site_name = "Website"
    tab_title = title
    
    # Popular sites map for cleaner display
    popular_sites = {
        "youtube.com": "YouTube", "youtube": "YouTube",
        "facebook.com": "Facebook", "facebook": "Facebook",
        "github.com": "GitHub", "github": "GitHub",
        "chatgpt.com": "ChatGPT", "chat.openai": "ChatGPT",
        "web.whatsapp.com": "WhatsApp", "whatsapp": "WhatsApp",
        "gmail.com": "Gmail", "google.com": "Google",
        "linkedin.com": "LinkedIn", "linkedin": "LinkedIn",
        "netflix.com": "Netflix", "reddit.com": "Reddit",
        "twitter.com": "Twitter/X", "x.com": "Twitter/X"
    }
    
    lower_title = title.lower()
    for domain, clean in popular_sites.items():
        if domain in lower_title:
            site_name = clean
            # Extract tab title by removing the site branding if possible
            tab_title = title.split(' - ')[0] if ' - ' in title else title
            break
    else:
        # Fallback: take the first part of the title as the site
        if ' - ' in title:
            parts = title.split(' - ')
            tab_title = parts[0]
            site_name = parts[1] if len(parts) > 1 else "Web Page"
        else:
            site_name = "Web Page"
            tab_title = title

    return browser, browser_icon, site_name, tab_title

last_website = ""

def monitor_active_window():
    """Monitor the currently active window and detect website activity."""
    if not WIN32_AVAILABLE:
        return
    
    show_live_activity('✅ [MONITOR] Active window monitoring started')
    global last_active_window, last_website
    
    while not stop_event.is_set():
        try:
            try:
                hwnd = win32gui.GetForegroundWindow()
                title = win32gui.GetWindowText(hwnd) or ''
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                
                process_name = ''
                try:
                    process_name = psutil.Process(pid).name().lower()
                except Exception:
                    pass
                
                current = f'{process_name}|{title}'
                
                if current and current != last_active_window:
                    last_active_window = current
                    lower_title = title.lower()
                    
                    browser_name, browser_icon, site_name, tab_title = extract_website_info(title, process_name)
                    
                    if browser_name:
                        if site_name != last_website:
                            # Show modern website card
                            show_live_activity(
                                f"🌐 {site_name} Opened", 
                                color_override="#48dbfb",
                                browser_info={
                                    'site': site_name,
                                    'browser': browser_name,
                                    'tab': tab_title
                                }
                            )
                            log_browser_history(f"{site_name}", f"Visited via {browser_name}: {tab_title}")
                            last_website = site_name
                    else:
                        last_website = ""
                        
                        # Only show user-facing applications (Whitelisting check)
                        is_user_app = False
                        if process_name in WHITELISTED_APPS:
                            is_user_app = True
                        elif any(marker in lower_title for marker in ['.docx', '.pdf', '.xlsx', '.pptx', '.txt', 'jpg', 'png', 'mp4']):
                            is_user_app = True
                        elif 'explorer.exe' in process_name and title:
                            is_user_app = True
                        
                        if is_user_app:
                            if '.docx' in lower_title:
                                show_live_activity(f"📄 Word Document Opened", f"File: {title[:50]}")
                                log_app_history(f'Word Document: {title}', 'Document opened')
                            elif '.pdf' in lower_title:
                                show_live_activity(f"📕 PDF Opened", f"File: {title[:50]}")
                                log_app_history(f'PDF: {title}', 'Document opened')
                            elif '.pptx' in lower_title:
                                show_live_activity(f"📊 PowerPoint Opened", f"File: {title[:50]}")
                                log_app_history(f'PPT: {title}', 'Document opened')
                            elif '.xlsx' in lower_title:
                                show_live_activity(f"📈 Excel Opened", f"File: {title[:50]}")
                                log_app_history(f'Excel: {title}', 'Document opened')
                            elif '.txt' in lower_title:
                                show_live_activity(f"📝 Text File Opened", f"File: {title[:50]}")
                                log_app_history(f'Text File: {title}', 'Document opened')
                            elif 'explorer.exe' in process_name and title:
                                show_live_activity(f"📁 Folder Opened", f"Path: {title[:50]}")
                                log_app_history(f'Folder: {title}', 'Explorer opened')
                            else:
                                # Show generic app card for whitelisted apps
                                app_friendly, app_icon = get_app_info(process_name)
                                show_live_activity(f"{app_icon} {app_friendly} Active", f"Window: {title[:50]}")
                                log_app_history(app_friendly, f'Active window: {title}')
                        else:
                            # Fallback for other interesting windows
                            found = False
                            for label, marker in interesting_sites:
                                if marker in lower_title or marker in process_name:
                                    show_live_activity(f'👁️ [{label.upper()}] Window active: {title[:50]}')
                                    log_security_history(f'Active Window: {label}', f'User active on {title}', 'LOW')
                                    found = True
                                    break
            except Exception as e:
                debug_log(f'monitor_active_window scan error: {e}')
        except Exception as e:
            debug_log(f'monitor_active_window error: {e}')
        stop_event.wait(1)

def update_system_info():
    """Monitor CPU, RAM, and Disk usage."""
    show_live_activity('✅ [MONITOR] System metrics monitoring started')
    
    while not stop_event.is_set():
        try:
            # Get metrics
            cpu_percent = psutil.cpu_percent(interval=0.5)
            ram_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('C:\\').percent
            
            # Find top RAM app
            top_proc = None
            max_rss = -1
            for p in psutil.process_iter(['name', 'memory_info']):
                try:
                    mem = p.info.get('memory_info')
                    if mem and mem.rss > max_rss:
                        max_rss = mem.rss
                        top_proc = p
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            top_ram_app = ""
            top_ram_mb = 0
            if top_proc:
                top_ram_app = top_proc.info.get('name', 'Unknown')
                top_ram_mb = max_rss / 1024 / 1024

            if cpu_percent > 80:
                save_event('CPU Usage', 'MEDIUM', f'High CPU usage: {cpu_percent:.1f}%')
            
            if ram_percent > 85:
                save_event('RAM Usage', 'MEDIUM', f'High RAM usage: {ram_percent:.1f}%')
            
            # Check network
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.pid:
                        try:
                            p = psutil.Process(conn.pid)
                            pname = p.name().lower()
                            if pname in suspicious_exes or pname == 'powershell.exe' or pname == 'mstsc.exe':
                                if f"net_{conn.pid}" not in previous_processes:
                                    show_live_activity(f'🔴 [NETWORK] Suspicious Outbound Connection: {pname}')
                                    save_event('Network Alert', 'HIGH', f'{pname} connected to {conn.raddr.ip}')
                                    previous_processes.add(f"net_{conn.pid}")
                        except Exception:
                            pass
            except psutil.AccessDenied:
                pass
            
            # Update labels safely using root.after()
            def update_labels():
                try:
                    update_label_safe('cpu_label', f'CPU: {cpu_percent:.1f}%')
                    update_label_safe('ram_label', f'RAM: {ram_percent:.1f}%')
                    update_label_safe('disk_label', f'Disk: {disk_percent:.1f}%')
                    if top_ram_app_label and top_ram_app:
                        color = "#ff6b6b" if top_ram_mb > 1000 else ("#feca57" if top_ram_mb > 500 else "#1dd1a1")
                        top_ram_app_label.configure(text=f"🔴 High RAM App: {top_ram_app} ({top_ram_mb:.1f} MB)", text_color=color)
                except Exception as e:
                    debug_log(f'Failed to update labels: {e}')
            
            if root is not None:
                root.after(0, update_labels)
        
        except Exception as e:
            debug_log(f'update_system_info error: {e}')
        
        stop_event.wait(5)  # Check every 5 seconds, but allow instant stop


# ============================================================================
# MONITORING CONTROL
# ============================================================================

def start_monitoring():
    """Start all monitoring threads."""
    global monitoring
    
    print("Starting monitoring...")
    
    with monitoring_lock:
        if monitoring:
            messagebox.showwarning('Monitoring', 'Monitoring is already running.')
            return
        
        monitoring = True
        stop_event.clear()
    
    append_output('\n' + '═' * 70 + '\n')
    append_output('🚀 REAL-TIME MONITORING STARTED\n')
    append_output('═' * 70 + '\n')
    update_label_safe('status_label', 'Status: MONITORING ACTIVE ✓')
    
    cleanup_old_logs()
    populate_security_summary()
    
    # Start all monitor threads (FILE ACTIVITY REMOVED)
    threads = [
        ('Load Old Events', load_old_windows_events),
        ('Windows Logs', monitor_windows_logs_live),
        ('Browser History', monitor_browser_live),
        ('Running Apps', monitor_apps_live),
        ('USB Devices', monitor_usb_live),
        ('File Activity', monitor_files_live),
        ('Active Window', monitor_active_window),
        ('System Metrics', update_system_info),
    ]
    
    for name, target in threads:
        try:
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            debug_log(f'Started thread: {name}')
        except Exception as e:
            show_live_activity(f'❌ Failed to start {name}: {e}')


def stop_monitoring():
    """Stop all monitoring threads gracefully."""
    global monitoring
    
    with monitoring_lock:
        if not monitoring:
            return
        monitoring = False
        stop_event.set()
    
    # Give threads time to check stop_event and exit
    time.sleep(0.5)
    
    append_output('\n' + '═' * 70 + '\n')
    append_output('⏹️  MONITORING STOPPED\n')
    append_output('═' * 70 + '\n')
    update_label_safe('status_label', 'Status: STOPPED')


# ============================================================================
# UI FUNCTIONS
# ============================================================================

def clear_output():
    """Clear all activity cards from the dashboard."""
    global activity_items
    for item in activity_items:
        try: item.destroy()
        except: pass
    activity_items.clear()
    debug_log("Activity dashboard cleared")

def show_statistics():
    """Show security statistics in a popup window."""
    try:
        if conn is None or cur is None: return
        
        with lock:
            cur.execute("SELECT COUNT(*) FROM security_history")
            total_sec = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM browser_history")
            total_browser = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM app_history")
            total_apps = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
            total_critical = cur.fetchone()[0]
            
        stats_window = ctk.CTkToplevel(root)
        stats_window.title("System Security Statistics")
        stats_window.geometry("400x400")
        stats_window.attributes('-topmost', True)
        
        ctk.CTkLabel(stats_window, text="📊 Security Metrics", font=('Helvetica', 20, 'bold'), text_color="#3498db").pack(pady=20)
        
        # Simple stats cards
        for label, val, color in [
            ("🔴 Critical Alerts", total_critical, "#ff6b6b"),
            ("🛡️ Security Events", total_sec, "#1dd1a1"),
            ("🌐 Web Activities", total_browser, "#48dbfb"),
            ("💻 App Usage Logs", total_apps, "#feca57")
        ]:
            f = ctk.CTkFrame(stats_window, fg_color="transparent")
            f.pack(fill="x", padx=40, pady=5)
            ctk.CTkLabel(f, text=label, font=('Helvetica', 14)).pack(side="left")
            ctk.CTkLabel(f, text=str(val), font=('Helvetica', 14, 'bold'), text_color=color).pack(side="right")
        
        ctk.CTkButton(stats_window, text="Done", command=stats_window.destroy, width=120).pack(pady=30)
    except Exception as e:
        debug_log(f"show_statistics error: {e}")

def export_data():
    """Export all logs to a CSV file."""
    try:
        if conn is None or cur is None: return
        
        import csv
        filename = f"siem_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with lock:
            cur.execute("SELECT * FROM alerts ORDER BY id DESC")
            rows = cur.fetchall()
            
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Timestamp', 'Event Type', 'Title', 'Details', 'Severity'])
            writer.writerows(rows)
            
        messagebox.showinfo("Export Success", f"Security logs exported to:\n{filename}")
        show_live_activity(f"💾 Logs exported to {filename}")
    except Exception as e:
        debug_log(f"export_data error: {e}")


def search_events():
    """Search events or history in database with modern UI and filters."""
    try:
        if conn is None or cur is None:
            return
            
        search_term = search_var.get().strip().lower()
        
        top = ctk.CTkToplevel(root)
        top.geometry("900x700")
        top.title(f"History & Search Results")
        top.transient(root)
        
        # Header
        header_frame = ctk.CTkFrame(top, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(header_frame, text="📜 History & Search", font=('Helvetica', 20, 'bold')).pack(side="left")
        
        # Global Search Bar in Popup
        popup_search_var = ctk.StringVar(value=search_term)
        
        def execute_search(*args):
            term = popup_search_var.get().lower()
            current_filter = getattr(top, "current_filter", "All")
            
            # Natural Language Processing for specific SIEM queries
            if "websites visited" in term or "how many websites" in term:
                current_filter = "Browser"
                term = ""
            elif "downloaded exe" in term:
                current_filter = "Applications"
                term = ".exe"
            elif "deleted pdf" in term:
                current_filter = "Applications"
                term = "deletion"
            elif "chrome history" in term:
                current_filter = "Browser"
                term = "chrome"
            elif "youtube" in term:
                current_filter = "Browser"
                term = "youtube"
            elif "facebook" in term:
                current_filter = "Browser"
                term = "facebook"
            elif "pdf opened" in term:
                current_filter = "Applications"
                term = ".pdf"
                
            load_results(term, current_filter)
        
        search_entry = ctk.CTkEntry(header_frame, textvariable=popup_search_var, width=300, placeholder_text="Search history...")
        search_entry.pack(side="right")
        search_entry.bind("<Return>", execute_search)
        
        # Filter Buttons
        filters = ["All", "Applications", "Browser", "Security", "USB", "Malware", "Failed Login", "Files", "Network"]
        filter_frame = ctk.CTkScrollableFrame(top, height=50, orientation="horizontal", fg_color="transparent")
        filter_frame.pack(fill="x", padx=20, pady=5)
        
        top.current_filter = "All"
        
        def set_filter(f_name):
            top.current_filter = f_name
            execute_search()
            
        for f in filters:
            btn = ctk.CTkButton(filter_frame, text=f, width=100, corner_radius=20, 
                                fg_color="#34495e", hover_color="#2c3e50",
                                command=lambda name=f: set_filter(name))
            btn.pack(side="left", padx=5)
            
        # Results Area
        scroll = ctk.CTkScrollableFrame(top)
        scroll.pack(fill="both", expand=True, padx=20, pady=10)
        
        stats_lbl = ctk.CTkLabel(top, text="", font=('Helvetica', 12, 'italic'))
        stats_lbl.pack(pady=5)
        
        def load_results(term, filter_type):
            for widget in scroll.winfo_children():
                widget.destroy()
                
            queries = []
            
            # Map filters to tables/conditions
            # tables: app_history, browser_history, security_history, usb_history, alerts, events
            
            if filter_type in ["All", "Applications"]:
                queries.append(("app_history", "SELECT timestamp, event_type, title, details, severity FROM app_history WHERE lower(title) LIKE ? OR lower(details) LIKE ? ORDER BY id DESC LIMIT 50"))
            if filter_type in ["All", "Browser"]:
                queries.append(("browser_history", "SELECT timestamp, event_type, title, details, severity FROM browser_history WHERE lower(title) LIKE ? OR lower(details) LIKE ? ORDER BY id DESC LIMIT 50"))
            if filter_type in ["All", "Security", "Failed Login", "Malware", "Network"]:
                queries.append(("security_history", "SELECT timestamp, event_type, title, details, severity FROM security_history WHERE lower(title) LIKE ? OR lower(details) LIKE ? ORDER BY id DESC LIMIT 50"))
            if filter_type in ["All", "USB"]:
                queries.append(("usb_history", "SELECT timestamp, event_type, title, details, severity FROM usb_history WHERE lower(title) LIKE ? OR lower(details) LIKE ? ORDER BY id DESC LIMIT 50"))
            if filter_type in ["All", "Files"]:
                # From app_history where title contains PDF, Docx etc.
                queries.append(("app_history", "SELECT timestamp, event_type, title, details, severity FROM app_history WHERE (lower(title) LIKE '%pdf%' OR lower(title) LIKE '%doc%' OR lower(title) LIKE '%xls%') AND (lower(title) LIKE ? OR lower(details) LIKE ?) ORDER BY id DESC LIMIT 50"))
                
            # Legacy events fallback
            if filter_type == "All":
                 queries.append(("events", "SELECT timestamp, category, category, details, severity FROM events WHERE lower(category) LIKE ? OR lower(details) LIKE ? ORDER BY id DESC LIMIT 50"))
            
            all_results = []
            with lock:
                for table, q in queries:
                    try:
                        cur.execute(q, (f'%{term}%', f'%{term}%'))
                        rows = cur.fetchall()
                        for r in rows:
                            all_results.append(r)
                    except Exception as e:
                        print(f"Query error on {table}: {e}")
                        
            # Sort by timestamp desc
            all_results.sort(key=lambda x: x[0], reverse=True)
            
            stats_lbl.configure(text=f"Showing {len(all_results)} results for filter '{filter_type}'")
            
            if not all_results:
                ctk.CTkLabel(scroll, text="No events found.", font=('Helvetica', 14)).pack(pady=40)
            else:
                for row in all_results:
                    # Depending on table, columns might be different, but we standardized to 5
                    ts, etype, title, det, sev = row[0], row[1], row[2], row[3], row[4]
                    
                    # Apply specialized filters
                    if filter_type == "Failed Login" and "failed" not in title.lower(): continue
                    if filter_type == "Malware" and sev != "CRITICAL": continue
                    
                    color = "#ff6b6b" if sev in ["HIGH", "CRITICAL"] else ("#feca57" if sev == "MEDIUM" else "#1dd1a1")
                    icon = "📄"
                    if "Browser" in etype: 
                        icon = "🦊" if "Firefox" in title or "Firefox" in str(row) else "🌐"
                    elif "USB" in etype: icon = "🔌"
                    elif "Security" in etype: icon = "🚨" if "failed" in title.lower() else "🔒"
                    elif "Application" in etype: icon = "🚀"
                    elif "File" in etype:
                        icon = "⬇️" if "Download" in title else "🗑️"
                    
                    row_frame = ctk.CTkFrame(scroll, corner_radius=8, fg_color="#2b2b2b")
                    row_frame.pack(fill="x", pady=2, padx=5)
                    
                    top_line = ctk.CTkFrame(row_frame, fg_color="transparent")
                    top_line.pack(fill="x", padx=10, pady=5)
                    
                    ctk.CTkLabel(top_line, text=f"{icon} {title}", font=('Helvetica', 14, 'bold'), text_color=color, anchor="w").pack(side="left")
                    ctk.CTkLabel(top_line, text=ts, font=('Helvetica', 11), text_color="gray").pack(side="right")
                    
                    ctk.CTkLabel(row_frame, text=det, font=('Helvetica', 12), text_color="#dcdde1", anchor="w", justify="left").pack(fill="x", padx=35, pady=(0, 5))

        # Initial load
        execute_search()
    
    except Exception as e:
        debug_log(f'search_events error: {e}')

# Function removed - consolidated into load_old_windows_events
pass

def create_ui():
    """Create the main UI."""
    global root, output_box, cpu_label, ram_label, disk_label, critical_label, status_label, search_entry, search_var
    global current_apps_frame, activity_frame, security_frame, failed_logins_label, usb_devices_label, malware_label, success_logins_label, remote_alerts_label, top_ram_app_label
    
    root = ctk.CTk()
    root.geometry('1600x900')
    root.title('Advanced Windows SIEM Dashboard')
    root.protocol('WM_DELETE_WINDOW', lambda: [stop_monitoring(), root.destroy()])
    
    # ---- Header Frame ----
    header_frame = ctk.CTkFrame(root, fg_color='#1a1a1a', height=60)
    header_frame.pack(fill='x', padx=0, pady=0)
    header_frame.pack_propagate(False)
    
    title_label = ctk.CTkLabel(header_frame, text='🛡️  SIEM SECURITY DASHBOARD', font=('Helvetica', 16, 'bold'))
    title_label.pack(side='left', padx=20, pady=10)
    
    status_label = ctk.CTkLabel(header_frame, text='Status: STOPPED', font=('Helvetica', 11), text_color='#ff6b6b')
    status_label.pack(side='right', padx=20, pady=10)
    
    # ---- Metrics Frame ----
    metrics_frame = ctk.CTkFrame(root)
    metrics_frame.pack(fill='x', padx=20, pady=10)
    
    critical_label = ctk.CTkLabel(metrics_frame, text='Critical Alerts: 0', font=('Helvetica', 10, 'bold'), text_color='#ff6b6b')
    critical_label.pack(side='left', padx=15)
    
    cpu_label = ctk.CTkLabel(metrics_frame, text='CPU: 0%', font=('Helvetica', 10))
    cpu_label.pack(side='left', padx=15)
    
    ram_label = ctk.CTkLabel(metrics_frame, text='RAM: 0%', font=('Helvetica', 10))
    ram_label.pack(side='left', padx=15)
    
    disk_label = ctk.CTkLabel(metrics_frame, text='Disk: 0%', font=('Helvetica', 10))
    disk_label.pack(side='left', padx=15)
    
    # ---- Main Output Area ----
    main_frame = ctk.CTkFrame(root, fg_color="transparent")
    main_frame.pack(fill='both', expand=True, padx=20, pady=10)
    
    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_columnconfigure(1, weight=3)  # Wider center panel
    main_frame.grid_columnconfigure(2, weight=1)
    main_frame.grid_rowconfigure(0, weight=1)

    global current_apps_frame, activity_frame, security_frame
    global malware_label, failed_logins_label, usb_devices_label, top_ram_app_label
    global success_logins_label, remote_alerts_label
    
    # Left Panel - Apps
    left_wrapper = ctk.CTkFrame(main_frame)
    left_wrapper.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
    ctk.CTkLabel(left_wrapper, text="📱 LIVE APPS", font=('Helvetica', 14, 'bold')).pack(pady=10)
    current_apps_frame = ctk.CTkScrollableFrame(left_wrapper, fg_color="transparent")
    current_apps_frame.pack(fill="both", expand=True, padx=5, pady=5)
    
    # Center Panel - Activity
    center_wrapper = ctk.CTkFrame(main_frame)
    center_wrapper.grid(row=0, column=1, sticky="nsew", padx=10)
    ctk.CTkLabel(center_wrapper, text="⚡ CURRENT ACTIVITY", font=('Helvetica', 14, 'bold')).pack(pady=10)
    activity_frame = ctk.CTkScrollableFrame(center_wrapper, fg_color="transparent")
    activity_frame.pack(fill="both", expand=True, padx=5, pady=5)
    
    # Right Panel - Security Summary
    right_wrapper = ctk.CTkFrame(main_frame, fg_color="#1a1a1a")
    right_wrapper.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
    ctk.CTkLabel(right_wrapper, text="SECURITY SUMMARY", font=('Helvetica', 16, 'bold'), text_color="#3498db").pack(pady=15)
    security_frame = ctk.CTkFrame(right_wrapper, fg_color="#1e1e1e", corner_radius=15)
    security_frame.pack(fill="both", expand=True, padx=10, pady=5)

    failed_logins_label = ctk.CTkLabel(security_frame, text="🔴 Failed Logins (7 Days): 0", font=('Helvetica', 14))
    failed_logins_label.pack(anchor="w", pady=10, padx=20)
    
    success_logins_label = ctk.CTkLabel(security_frame, text="🟢 Successful Logins: 0", font=('Helvetica', 14), text_color="#1dd1a1")
    success_logins_label.pack(anchor="w", pady=10, padx=20)
    
    usb_devices_label = ctk.CTkLabel(security_frame, text="🟠 USB Devices Connected: 0", font=('Helvetica', 14))
    usb_devices_label.pack(anchor="w", pady=10, padx=20)
    
    remote_alerts_label = ctk.CTkLabel(security_frame, text="⚠ Suspicious Activity: 0", font=('Helvetica', 14))
    remote_alerts_label.pack(anchor="w", pady=10, padx=20)
    
    malware_label = ctk.CTkLabel(security_frame, text="🛡 Malware Detected: No", font=('Helvetica', 14), text_color="#1dd1a1")
    malware_label.pack(anchor="w", pady=10, padx=20)
    
    ctk.CTkFrame(security_frame, height=2, fg_color="#333").pack(fill="x", padx=20, pady=10)
    
    top_ram_app_label = ctk.CTkLabel(security_frame, text="⚙️ System Performance: Stable", font=('Helvetica', 12), text_color="gray")
    top_ram_app_label.pack(anchor="w", pady=5, padx=20)
    
    # Initialize some known apps to Closed
    for exe, (app_name, icon) in APP_INFO.items():
        if app_name in ['Google Chrome', 'VS Code', 'Discord', 'Microsoft Edge', 'PowerShell']:
            update_app_card(app_name, "Closed", 0.0, False, icon)
        
    show_live_activity("✨ Advanced Windows SIEM Dashboard v2.0 - LIVE")
    show_live_activity("ℹ️ Click 'Start Monitoring' to begin")
    
    # ---- Control Buttons ----
    button_frame = ctk.CTkFrame(root)
    button_frame.pack(fill='x', padx=20, pady=10)
    
    ctk.CTkButton(button_frame, text='▶ Start Monitoring', command=start_monitoring, fg_color='#2ecc71', width=150).pack(side='left', padx=5)
    ctk.CTkButton(button_frame, text='⏹ Stop Monitoring', command=stop_monitoring, fg_color='#e74c3c', width=150).pack(side='left', padx=5)
    ctk.CTkButton(button_frame, text='📊 Statistics', command=show_statistics, width=100).pack(side='left', padx=5)
    ctk.CTkButton(button_frame, text='🗑️ Clear', command=clear_output, width=100).pack(side='left', padx=5)
    ctk.CTkButton(button_frame, text='💾 Export CSV', command=export_data, width=100).pack(side='left', padx=5)
    
    # ---- Search Frame ----
    search_frame = ctk.CTkFrame(root, fg_color="transparent")
    search_frame.pack(fill='x', padx=20, pady=10)
    
    global search_var
    search_var = ctk.StringVar(value="Failed Login")
    search_dropdown = ctk.CTkComboBox(search_frame, variable=search_var, values=[
        "Failed Login", "Successful Login", "USB Events", "PDFs Opened", "Word Documents", "Suspicious Activity", "Browser Activity", "All Apps Opened"
    ], width=200)
    search_dropdown.pack(side='left', padx=10)
    
    ctk.CTkButton(search_frame, text='🔍 Search History (Last 7 Days)', command=search_events, width=150, fg_color="#3498db").pack(side='left', padx=5)
    
    debug_log('UI created successfully')


# =========================================================
# ADMIN CHECK
# =========================================================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# =========================================================
# MAIN START
# =========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("STARTING SIEM DASHBOARD")
    print("=" * 60)

    # ---------------------------------------------
    # STEP 1: CHECK ADMIN
    # ---------------------------------------------
    admin_status = is_admin()
    print(f"Admin Status: {admin_status}")

    # ---------------------------------------------
    # STEP 2: REQUEST ADMIN IF NOT ADMIN
    # ---------------------------------------------
    if not admin_status:
        print("NOT ADMIN")
        print("Requesting admin privileges...")
        try:
            # We use the renamed file project_seim.py
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{os.path.abspath(__file__)}"',
                None,
                1
            )
            print("Admin request sent.")
            print("Closing old process...")
            sys.exit(0)
        except Exception as e:
            print("Admin request failed:")
            print(e)
            sys.exit(1)

    # ---------------------------------------------
    # STEP 3: ONLY ADMIN PROCESS CONTINUES
    # ---------------------------------------------
    print("ADMIN ACCESS GRANTED")
    print("Opening dashboard...")

    # IMPORT UI ONLY HERE
    import customtkinter as ctk
    from tkinter import messagebox

    try:
        # CREATE UI HERE ONLY
        create_ui()
        print("UI CREATED")

        # START UI LOOP
        root.mainloop()

    except Exception as e:
        print("DASHBOARD CRASHED")
        print(e)
        import traceback
        traceback.print_exc()
        input("Press ENTER to close...")
