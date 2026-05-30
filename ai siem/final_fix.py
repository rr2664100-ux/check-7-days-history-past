with open('project seim.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    # Look for the wrongly indented else block
    if line.strip() == "else:" and line.startswith("                    else:"):
        # If it follows the document elif chain, indent it more
        # We need to detect if it's the second else in the block.
        # But wait, let's just use a more specific check.
        # Line 1070 (0-indexed 1069)
        pass
    new_lines.append(line)

# Let's just rewrite the monitor_active_window function completely one last time correctly.
# I'll read it, find the start/end and replace.

def fix_it():
    start_marker = "def monitor_active_window():"
    end_marker = "def update_system_info():"
    
    with open('project seim.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    start = content.find(start_marker)
    end = content.find(end_marker)
    
    if start == -1 or end == -1:
        print("Markers not found")
        return

    new_func = '''def monitor_active_window():
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
                    
                    browser_name, browser_icon, site_name = extract_website_info(title, process_name)
                    
                    if browser_name:
                        if site_name != last_website:
                            action = "SWITCHED" if last_website else "OPENED"
                            color = "🔵" if action == "SWITCHED" else "🟢"
                            show_live_activity(f"{color} {action.title()} Website", f"{site_name}\\n({browser_name})", color_override="#48dbfb" if action == "SWITCHED" else "#1dd1a1")
                            log_browser_history(f"{site_name}", f"Visited via {browser_name}")
                            last_website = site_name
                    else:
                        last_website = ""
                        
                        if '.docx' in lower_title:
                            show_live_activity(f"📄 Word Document Opened: {title[:50]}")
                            log_app_history(f'Word Document: {title}', 'Document opened')
                        elif '.pdf' in lower_title:
                            show_live_activity(f"📕 PDF Opened: {title[:50]}")
                            log_app_history(f'PDF: {title}', 'Document opened')
                        elif '.pptx' in lower_title:
                            show_live_activity(f"📊 PowerPoint Opened: {title[:50]}")
                            log_app_history(f'PPT: {title}', 'Document opened')
                        elif '.xlsx' in lower_title:
                            show_live_activity(f"📈 Excel Opened: {title[:50]}")
                            log_app_history(f'Excel: {title}', 'Document opened')
                        elif '.txt' in lower_title:
                            show_live_activity(f"📝 Text File Opened: {title[:50]}")
                            log_app_history(f'Text File: {title}', 'Document opened')
                        elif '.jpg' in lower_title or '.png' in lower_title:
                            show_live_activity(f"🖼️ Image Viewed: {title[:50]}")
                            log_app_history(f'Image: {title}', 'Media opened')
                        elif '.mp4' in lower_title:
                            show_live_activity(f"🎬 Video Opened: {title[:50]}")
                            log_app_history(f'Video: {title}', 'Media opened')
                        elif 'explorer.exe' in process_name and title:
                            show_live_activity(f"📁 {title[:30]} Folder Opened")
                            log_app_history(f'Folder: {title}', 'Explorer opened')
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

'''
    updated_content = content[:start] + new_func + content[end:]
    with open('project seim.py', 'w', encoding='utf-8') as f:
        f.write(updated_content)
    print("Fixed monitor_active_window syntax")

fix_it()
