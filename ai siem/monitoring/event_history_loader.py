import sqlite3
import datetime
import time
from pathlib import Path
try:
    import win32evtlog
    import win32api
    import win32con
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

def get_event_time(event):
    try:
        timestamp = getattr(event, 'TimeGenerated', None)
        if hasattr(timestamp, 'year'):
            return timestamp
        return datetime.datetime.fromtimestamp(time.mktime(timestamp.timetuple()))
    except Exception:
        return datetime.datetime.now()

def parse_security_event(event):
    event_id = int(getattr(event, 'EventID', 0) & 0xFFFF)
    source = getattr(event, 'SourceName', 'Unknown')
    inserts = getattr(event, 'StringInserts', [])
    
    username = 'Unknown'
    ip_addr = 'N/A'
    logon_type = 'N/A'
    
    if inserts:
        if event_id == 4625:
            # Failed Login
            username = inserts[5] if len(inserts) > 5 else 'Unknown'
            logon_type = inserts[10] if len(inserts) > 10 else 'N/A'
            ip_addr = inserts[19] if len(inserts) > 19 else 'N/A'
            return ('Login Failed', 'HIGH', f'Failed login attempt by {username} (Type: {logon_type}, IP: {ip_addr})', source, event_id, username, ip_addr, logon_type)
        elif event_id == 4624:
            username = inserts[5] if len(inserts) > 5 else 'Unknown'
            logon_type = inserts[8] if len(inserts) > 8 else 'N/A'
            ip_addr = inserts[18] if len(inserts) > 18 else 'N/A'
            # Ignore automated SYSTEM logins to prevent spam
            if username.endswith('$') or username in ['SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE']:
                return None
            return ('Login Success', 'LOW', f'Successful login by {username} (Type: {logon_type})', source, event_id, username, ip_addr, logon_type)
        elif event_id == 4800:
            username = inserts[1] if len(inserts) > 1 else 'Unknown'
            return ('Workstation Locked', 'LOW', f'Workstation locked by {username}', source, event_id, username, '', '')
        elif event_id == 4801:
            username = inserts[1] if len(inserts) > 1 else 'Unknown'
            return ('Workstation Unlocked', 'LOW', f'Workstation unlocked by {username}', source, event_id, username, '', '')
        elif event_id == 6416:
            return ('USB Device', 'MEDIUM', 'USB device connected', source, event_id, '', '', '')
            
    return None

def load_historical_events(db_path, db_lock, stop_event, status_callback=None):
    if not WIN32_AVAILABLE:
        if status_callback: status_callback('Failed to load history: pywin32 not installed')
        return

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    cur = conn.cursor()

    # Ensure tables exist
    with db_lock:
        cur.execute('''CREATE TABLE IF NOT EXISTS login_history(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        username TEXT,
                        status TEXT,
                        source_ip TEXT,
                        logon_type TEXT
                    )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS usb_history(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        device_name TEXT,
                        action TEXT
                    )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        category TEXT,
                        severity TEXT,
                        details TEXT,
                        source TEXT,
                        event_id INTEGER
                    )''')
        
        # Check if source/event_id exist in events, and add if not
        try:
            cur.execute("ALTER TABLE events ADD COLUMN source TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("ALTER TABLE events ADD COLUMN event_id INTEGER")
        except sqlite3.OperationalError:
            pass
            
        conn.commit()

    since = datetime.datetime.now() - datetime.timedelta(days=7)
    
    logs_to_read = ['Security', 'System', 'Application']
    loaded = 0
    seen = set()

    for logtype in logs_to_read:
        if stop_event.is_set(): break
        if status_callback: status_callback(f'Loading {logtype} history...')
        
        try:
            handle = win32evtlog.OpenEventLog('localhost', logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            finished = False
            
            while not finished and not stop_event.is_set():
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                
                batch = []
                login_batch = []
                usb_batch = []
                
                for event in events:
                    record = getattr(event, 'RecordNumber', None)
                    if record is None or record in seen:
                        continue
                    seen.add(record)
                    
                    timestamp = get_event_time(event)
                    if timestamp < since:
                        finished = True
                        break
                        
                    time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    parsed = parse_security_event(event)
                    
                    if parsed:
                        cat, sev, det, src, ev_id, usr, ip, ltype = parsed
                        batch.append((time_str, cat, sev, det, src, ev_id))
                        
                        if 'Login' in cat:
                            login_batch.append((time_str, usr, cat, ip, ltype))
                        elif 'USB' in cat:
                            usb_batch.append((time_str, det, cat))
                    else:
                        # General events mapping
                        event_id = int(getattr(event, 'EventID', 0) & 0xFFFF)
                        source = getattr(event, 'SourceName', 'Unknown')
                        if logtype == 'System' and event_id in [6008, 6009]:
                            batch.append((time_str, 'System Event', 'LOW', f'System event {event_id}', source, event_id))
                
                if batch:
                    with db_lock:
                        cur.executemany('INSERT INTO events(timestamp, category, severity, details, source, event_id) VALUES (?,?,?,?,?,?)', batch)
                        if login_batch:
                            cur.executemany('INSERT INTO login_history(timestamp, username, status, source_ip, logon_type) VALUES (?,?,?,?,?)', login_batch)
                        if usb_batch:
                            cur.executemany('INSERT INTO usb_history(timestamp, device_name, action) VALUES (?,?,?)', usb_batch)
                        conn.commit()
                        loaded += len(batch)
                        
        except Exception as e:
            if status_callback: status_callback(f'Error reading {logtype}: {e}')
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    if status_callback: status_callback(f'Loaded {loaded} historical events successfully.')
    conn.close()
