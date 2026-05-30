from typing import List, Dict
import customtkinter as ctk


class AlertsPanel(ctk.CTkFrame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.label = ctk.CTkLabel(self, text="Threat Alerts", anchor="w", font=("Segoe UI", 16, "bold"))
        self.label.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        self.listbox = ctk.CTkTextbox(self, width=360, height=220, wrap="word")
        self.listbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    def update_alerts(self, alerts: List[Dict[str, str]]) -> None:
        self.listbox.configure(state="normal")
        self.listbox.delete("1.0", "end")
        for alert in alerts[:20]:
            text = f"[{alert.get('timestamp')}] {alert.get('severity')} - {alert.get('alert_text')}\n"
            self.listbox.insert("end", text)
        self.listbox.configure(state="disabled")
