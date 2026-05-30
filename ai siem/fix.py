import sys

target1 = """def monitor_active_window():
    \"\"\"Monitor the currently active window and detect website activity.\"\"\"
    if not WIN32_AVAILABLE:
        return
    
    show_live_activity('✅ [MONITOR] Active window monitoring started')
    global last_active_window"""

replacement1 = """def extract_website_info(title, process_name):
    browser = None
    lower_title = title.lower()
    
    if "chrome" in process_name or "- google chrome" in lower_title:
        browser = "Chrome"
        browser_icon = "🌐"
    elif "edge" in process_name or "- microsoft edge" in lower_title:
        browser = "Edge"
        browser_icon = "🔵"
    elif "firefox" in process_name or "- mozilla firefox" in lower_title:
        browser = "Firefox"
        browser_icon = "🦊"
    else:
        return None, None, None
        
    parts = title.rsplit(" - ", 1)
    site_name = parts[0] if len(parts) > 1 else title
    
    popular_sites = {
        "youtube": "YouTube", "facebook": "Facebook", "instagram": "Instagram",
        "github": "GitHub", "chatgpt": "ChatGPT", "whatsapp": "WhatsApp Web",
        "gmail": "Gmail", "linkedin": "LinkedIn", "netflix": "Netflix",
        "amazon": "Amazon", "reddit": "Reddit", "twitter": "Twitter/X", "x": "Twitter/X"
    }
    
    clean_name = site_name
    for key, display in popular_sites.items():
        if key in site_name.lower():
            clean_name = display
            break
            
    return browser, browser_icon, clean_name

last_website = ""

def monitor_active_window():
    \"\"\"Monitor the currently active window and detect website activity.\"\"\"
    if not WIN32_AVAILABLE:
        return
    
    show_live_activity('✅ [MONITOR] Active window monitoring started')
    global last_active_window, last_website"""

target2 = """                    lower_title = title.lower()
                    if '.docx' in lower_title:
                        show_live_activity(f"📄 Word Document Opened: {title[:50]}")
                        save_event('Document', 'LOW', f'Word Document: {title}')
                    elif '.pdf' in lower_title:
                        show_live_activity(f"📕 PDF Opened: {title[:50]}")
                        save_event('Document', 'LOW', f'PDF: {title}')
                    elif '.pptx' in lower_title:
                        show_live_activity(f"📊 PowerPoint Opened: {title[:50]}")
                        save_event('Document', 'LOW', f'PPT: {title}')
                    elif '.xlsx' in lower_title:
                        show_live_activity(f"📈 Excel Opened: {title[:50]}")
                        save_event('Document', 'LOW', f'Excel: {title}')
                    elif '.txt' in lower_title:
                        show_live_activity(f"📝 Text File Opened: {title[:50]}")
                        save_event('Document', 'LOW', f'Text: {title}')
                    elif '.jpg' in lower_title or '.png' in lower_title:
                        show_live_activity(f"🖼️ Image Viewed: {title[:50]}")
                        save_event('Media', 'LOW', f'Image: {title}')
                    elif '.mp4' in lower_title:
                        show_live_activity(f"🎬 Video Opened: {title[:50]}")
                        save_event('Media', 'LOW', f'Video: {title}')
                    elif 'explorer.exe' in process_name and title:
                        show_live_activity(f"📁 {title[:30]} Folder Opened")
                        save_event('Folder', 'LOW', f'Folder: {title}')
                    else:
                        found = False
                        for label, marker in interesting_sites:
                            if marker in lower_title or marker in process_name:
                                show_live_activity(f'👁️ [{label.upper()}] Window active: {title[:50]}')
                                save_event(label, 'LOW', f'Active: {title}')
                                found = True
                                break
                                
                        if not found and 'whatsapp' in process_name:
                            log_background('WhatsApp', 'LOW', f'Active: {title}')
                        elif not found and 'code.exe' in process_name:
                            log_background('VS Code', 'LOW', f'Active: {title}')
                        elif not found and any(x in process_name for x in ['chrome.exe', 'msedge.exe', 'firefox.exe']):
                            log_background('Browser', 'LOW', f'Active: {title}')"""

replacement2 = """                    lower_title = title.lower()
                    
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
                            log_app_history(f"Word Document: {title}", "Document opened")
                        elif '.pdf' in lower_title:
                            show_live_activity(f"📕 PDF Opened: {title[:50]}")
                            log_app_history(f"PDF: {title}", "Document opened")
                        elif '.pptx' in lower_title:
                            show_live_activity(f"📊 PowerPoint Opened: {title[:50]}")
                            log_app_history(f"PPT: {title}", "Document opened")
                        elif '.xlsx' in lower_title:
                            show_live_activity(f"📈 Excel Opened: {title[:50]}")
                            log_app_history(f"Excel: {title}", "Document opened")
                        elif '.txt' in lower_title:
                            show_live_activity(f"📝 Text File Opened: {title[:50]}")
                            log_app_history(f"Text File: {title}", "Document opened")
                        elif '.jpg' in lower_title or '.png' in lower_title:
                            show_live_activity(f"🖼️ Image Viewed: {title[:50]}")
                            log_app_history(f"Image: {title}", "Media opened")
                        elif '.mp4' in lower_title:
                            show_live_activity(f"🎬 Video Opened: {title[:50]}")
                            log_app_history(f"Video: {title}", "Media opened")
                        elif 'explorer.exe' in process_name and title:
                            show_live_activity(f"📁 {title[:30]} Folder Opened")
                            log_app_history(f"Folder: {title}", "Explorer opened")"""

with open('c:/Users/adarsh/Desktop/ai siem/project seim.py', 'r', encoding='utf-8') as f:
    content = f.read()

if target1 in content:
    content = content.replace(target1, replacement1)
    print("Replaced chunk 1")
else:
    print("Chunk 1 not found")

if target2 in content:
    content = content.replace(target2, replacement2)
    print("Replaced chunk 2")
else:
    print("Chunk 2 not found")

with open('c:/Users/adarsh/Desktop/ai siem/project seim.py', 'w', encoding='utf-8') as f:
    f.write(content)
