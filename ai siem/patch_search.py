with open('project seim.py', 'r', encoding='utf-8') as f:
    content = f.read()

import re

# Find the search_events function
# We will use regex to find the entire search_events block and replace it.
# It starts with 'def search_events():' and ends before 'def create_ui():' or similar.

def get_block():
    start_str = "def search_events():"
    end_str = "def create_ui():"
    start = content.find(start_str)
    end = content.find(end_str)
    if start != -1 and end != -1:
        return content[start:end]
    return ""

old_search = get_block()

new_search = '''def search_events():
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
                for timestamp, event_type, title, details, severity in all_results:
                    color = "#ff6b6b" if severity in ["HIGH", "CRITICAL"] else ("#feca57" if severity == "MEDIUM" else "#1dd1a1")
                    if filter_type == "Failed Login" and "failed" not in title.lower(): continue
                    if filter_type == "Malware" and severity not in ["HIGH", "CRITICAL"]: continue
                    
                    row_frame = ctk.CTkFrame(scroll, corner_radius=8, fg_color="#2b2b2b")
                    row_frame.pack(fill="x", pady=5, padx=5)
                    
                    top_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
                    top_frame.pack(fill="x", padx=10, pady=(10, 5))
                    
                    # Icons based on event type
                    icon = "🔹"
                    if event_type == "Browser": icon = "🌐"
                    elif event_type == "Security": icon = "🔴" if severity in ["HIGH", "CRITICAL"] else "🟢"
                    elif event_type == "USB": icon = "🟡"
                    elif event_type == "Application": icon = "🚀"
                    
                    ctk.CTkLabel(top_frame, text=f"{icon} {title}", font=('Helvetica', 14, 'bold'), text_color=color, anchor="w").pack(side="left")
                    ctk.CTkLabel(top_frame, text=f"{timestamp}", font=('Helvetica', 11), text_color="gray").pack(side="right")
                    
                    ctk.CTkLabel(row_frame, text=f"{details}", font=('Helvetica', 12), text_color="#dcdde1", anchor="w", justify="left").pack(fill="x", padx=35, pady=(0, 10))

        # Initial load
        execute_search()
    
    except Exception as e:
        debug_log(f'search_events error: {e}')

'''

if old_search:
    content = content.replace(old_search, new_search)
    with open('project seim.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Search UI upgraded successfully!")
else:
    print("Search UI block not found.")
