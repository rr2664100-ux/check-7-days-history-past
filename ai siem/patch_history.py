with open('project seim.py', 'r', encoding='utf-8') as f:
    content = f.read()

import_statement = "import win32evtlog\\n"
if "import win32evtlog" not in content:
    content = content.replace("import win32gui", "import win32gui\\nimport win32evtlog")

history_loader = '''def load_historical_windows_events():
    """Load historical events from Windows Event Viewer (last 7 days)."""
    try:
        if not WIN32_AVAILABLE:
            return
            
        show_live_activity("⏳ [SYSTEM] Loading 7-day historical events...")
        server = 'localhost'
        log_type = 'Security'
        
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        hand = win32evtlog.OpenEventLog(server, log_type)
        
        from datetime import datetime, timedelta
        seven_days_ago = datetime.now() - timedelta(days=7)
        total_failed_logins = 0
        
        try:
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    if event.TimeGenerated < seven_days_ago:
                        raise StopIteration
                        
                    event_id = event.EventID & 0xFFFF
                    if event_id == 4625:  # Failed Login
                        total_failed_logins += 1
                        strings = event.StringInserts
                        user = strings[5] if strings and len(strings) > 5 else "Unknown User"
                        
                        timestamp = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                        with lock:
                            cur.execute(
                                'INSERT INTO security_history(timestamp, event_type, title, details, severity) VALUES (?, ?, ?, ?, ?)',
                                (timestamp, 'Security', 'Failed Login Attempt', f'User: {user} entered wrong password', 'HIGH')
                            )
        except StopIteration:
            pass
        except Exception as e:
            pass
            
        if total_failed_logins > 0:
            conn.commit()
            show_live_activity(f"🔴 [SECURITY] Loaded {total_failed_logins} past failed logins")
            
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        debug_log(f"Event Log Load Error: {e}")

def create_ui():'''

if "def load_historical_windows_events():" not in content:
    content = content.replace("def create_ui():", history_loader)
    
start_monitoring_target = '''    global monitor_thread, system_thread, browser_thread, usb_thread
    
    stop_event.clear()
    
    monitor_thread = threading.Thread(target=monitor_apps_live, daemon=True)
    monitor_thread.start()
'''

start_monitoring_replacement = '''    global monitor_thread, system_thread, browser_thread, usb_thread
    
    stop_event.clear()
    
    threading.Thread(target=load_historical_windows_events, daemon=True).start()
    
    monitor_thread = threading.Thread(target=monitor_apps_live, daemon=True)
    monitor_thread.start()
'''

if "load_historical_windows_events" not in content.split("def start_monitoring():")[1]:
    content = content.replace(start_monitoring_target, start_monitoring_replacement)

with open('project seim.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Added Event ID 4625 loader successfully!")
