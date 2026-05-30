with open('project seim.py', 'r', encoding='utf-8') as f:
    content = f.read()

target2 = '''                    lower_title = title.lower()
                    if '.docx' in lower_title:'''

replacement2 = '''                    lower_title = title.lower()
                    
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
                        
                        if '.docx' in lower_title:'''

if target2 in content:
    content = content.replace(target2, replacement2)
    content = content.replace("save_event('Document', 'LOW', f'Word Document: {title}')", "log_app_history(f'Word Document: {title}', 'Document opened')")
    content = content.replace("save_event('Document', 'LOW', f'PDF: {title}')", "log_app_history(f'PDF: {title}', 'Document opened')")
    content = content.replace("save_event('Document', 'LOW', f'PPT: {title}')", "log_app_history(f'PPT: {title}', 'Document opened')")
    content = content.replace("save_event('Document', 'LOW', f'Excel: {title}')", "log_app_history(f'Excel: {title}', 'Document opened')")
    content = content.replace("save_event('Document', 'LOW', f'Text: {title}')", "log_app_history(f'Text File: {title}', 'Document opened')")
    content = content.replace("save_event('Media', 'LOW', f'Image: {title}')", "log_app_history(f'Image: {title}', 'Media opened')")
    content = content.replace("save_event('Media', 'LOW', f'Video: {title}')", "log_app_history(f'Video: {title}', 'Media opened')")
    content = content.replace("save_event('Folder', 'LOW', f'Folder: {title}')", "log_app_history(f'Folder: {title}', 'Explorer opened')")
    
    with open('project seim.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Patched successfully!')
else:
    print('target2 not found')
