with open('project seim.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace("save_event('USB Inserted', 'MEDIUM', f'USB device connected on {drive}')", "log_usb_history(f'USB Connected on {drive}', 'Device inserted', 'MEDIUM')")
content = content.replace("log_background('USB Removed', 'LOW', f'USB device removed from {drive}')", "log_usb_history(f'USB Removed from {drive}', 'Device removed', 'LOW')")

with open('project seim.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Patched USB logger')
