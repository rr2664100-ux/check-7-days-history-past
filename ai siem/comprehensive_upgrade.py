import sys
from datetime import datetime, timedelta

def patch_seim():
    with open('project seim.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Update app_start_times global
    if "app_start_times = {}" not in content:
        content = content.replace("global previous_processes", "global previous_processes, app_start_times\n    app_start_times = {}")

    # 2. Overhaul load_historical_windows_events to include more IDs
    new_historical_loader = '''def load_historical_windows_events():
    """Load historical events from Windows Event Viewer (last 7 days)."""
    try:
        if not WIN32_AVAILABLE:
            return
            
        show_live_activity("⏳ [SYSTEM] Loading 7-day historical events...")
        server = 'localhost'
        from datetime import datetime, timedelta
        seven_days_ago = datetime.now() - timedelta(days=7)
        
        logs_to_scan = [
            ('Security', [4625, 4624, 4800, 4801]), # Failed Login, Success Login, Lock, Unlock
            ('System', [1, 1074, 6005, 6006]),     # Power events, Startup/Shutdown
            ('Application', [])
        ]
        
        counts = {"Failed": 0, "Success": 0, "Security": 0}
        
        for log_name, ids in logs_to_scan:
            try:
                hand = win32evtlog.OpenEventLog(server, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events: break
                    
                    for event in events:
                        if event.TimeGenerated < seven_days_ago:
                            raise StopIteration
                            
                        eid = event.EventID & 0xFFFF
                        ts = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                        
                        if eid == 4625:
                            counts["Failed"] += 1
                            log_security_history("Failed Login Attempt", f"Wrong password entered", "HIGH")
                        elif eid == 4624:
                            counts["Success"] += 1
                            log_security_history("Successful Login", "User logged in successfully", "LOW")
                        elif eid == 4800:
                            log_security_history("Workstation Locked", "Screen was locked", "LOW")
                        elif eid == 4801:
                            log_security_history("Workstation Unlocked", "Screen was unlocked", "LOW")
                        elif eid in [6005, 6006]:
                            status = "Started" if eid == 6005 else "Shut Down"
                            log_security_history(f"System {status}", f"Windows system {status.lower()}", "LOW")
            except StopIteration: pass
            except Exception: pass
            
        show_live_activity(f"🔴 [SECURITY] Loaded history: {counts['Failed']} Failed, {counts['Success']} Success logins.")
    except Exception as e:
        debug_log(f"Historical Load Error: {e}")

def create_ui():'''

    content = content.replace('''def load_historical_windows_events():
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

def create_ui():''', new_historical_loader)

    # 3. Add App Usage tracking to monitor_apps_live
    # We need to find the closed app loop
    old_app_monitor = '''            # Detect closed apps
            closed_apps = previous_processes - current_processes
            for name in closed_apps:
                if name in WHITELISTED_APPS:
                    app_name, icon = get_app_info(name)
                    if app_name in [v[0] for v in APP_INFO.values()]:
                        show_live_activity(f'⛔ [APP CLOSED] {icon} {app_name}')
                        update_app_card(app_name, "Closed", 0.0, False, icon)
                    log_background('App Closed', 'LOW', f'{app_name} closed')'''
    
    new_app_monitor = '''            # Detect closed apps
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
                    app_start_times[name] = datetime.now()'''

    content = content.replace(old_app_monitor, new_app_monitor)
    
    # 4. Update periodic cleanup
    cleanup_loop = '''def periodic_cleanup():
    while not stop_event.is_set():
        cleanup_old_logs()
        stop_event.wait(86400) # 24 hours'''
        
    if "def periodic_cleanup():" not in content:
        content = content.replace("def cleanup_old_logs():", "def periodic_cleanup():\n    while not stop_event.is_set():\n        cleanup_old_logs()\n        stop_event.wait(86400)\n\ndef cleanup_old_logs():")
        content = content.replace("monitor_thread = threading.Thread(target=monitor_apps_live, daemon=True)", 
                                 "threading.Thread(target=periodic_cleanup, daemon=True).start()\n    monitor_thread = threading.Thread(target=monitor_apps_live, daemon=True)")

    with open('project seim.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Full History & Search Upgrade Patched Successfully")

patch_seim()
