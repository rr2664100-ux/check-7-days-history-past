from datetime import datetime
from pathlib import Path
import psutil
import customtkinter as ctk
from typing import Dict, List
from config.settings import SETTINGS
from ui.themes import DARK_BACKGROUND, DARK_PANEL, TEXT_COLOR, SECONDARY_TEXT, ACCENT_COLOR, URL_COLOR, ACTIVITY_TITLE_COLOR, ALERT_COLOR
from reports.csv_export import CSVExporter
from reports.json_export import JSONExporter
from reports.pdf_report import PDFReport
from utils.helpers import ensure_directory


class SentinelAIDashboard(ctk.CTk):
    def __init__(self, database, report_dir: Path, monitor_manager):
        super().__init__()
        self.title("SentinelAI - Activity Monitor")
        self.geometry("1240x760")
        self.configure(fg_color=DARK_BACKGROUND)
        self.database = database
        self.report_dir = report_dir
        self.monitor_manager = monitor_manager
        ensure_directory(self.report_dir)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._build_interface()
        self.after(3000, self.refresh)

    def _build_interface(self) -> None:
        header = ctk.CTkFrame(self, fg_color=DARK_PANEL)
        header.pack(fill="x", padx=12, pady=12)

        self.status_label = ctk.CTkLabel(header, text="� Monitoring Stopped", font=("Segoe UI", 18, "bold"), text_color=TEXT_COLOR)
        self.status_label.pack(side="left", padx=(12, 6))

        self.cpu_label = ctk.CTkLabel(header, text="CPU 0%", font=("Segoe UI", 14), text_color=SECONDARY_TEXT)
        self.cpu_label.pack(side="left", padx=16)

        self.ram_label = ctk.CTkLabel(header, text="RAM 0%", font=("Segoe UI", 14), text_color=SECONDARY_TEXT)
        self.ram_label.pack(side="left", padx=16)

        self.threat_label = ctk.CTkLabel(header, text="Threat Level: Safe", font=("Segoe UI", 14), text_color=TEXT_COLOR)
        self.threat_label.pack(side="left", padx=16)

        main_frame = ctk.CTkFrame(self, fg_color=DARK_BACKGROUND)
        main_frame.pack(fill="both", expand=True, padx=12, pady=12)

        left_panel = ctk.CTkFrame(main_frame, fg_color=DARK_PANEL)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 6), pady=0)

        center_panel = ctk.CTkFrame(main_frame, fg_color=DARK_PANEL)
        center_panel.pack(side="left", fill="both", expand=True, padx=6, pady=0)

        right_panel = ctk.CTkFrame(main_frame, fg_color=DARK_PANEL)
        right_panel.pack(side="right", fill="both", expand=True, padx=(6, 0), pady=0)

        ctk.CTkLabel(left_panel, text="Current Running Apps", font=("Segoe UI", 20, "bold"), text_color=TEXT_COLOR).pack(anchor="nw", padx=16, pady=(16, 6))
        self.apps_box = ctk.CTkTextbox(left_panel, width=320, height=260, wrap="word")
        self.apps_box.pack(fill="both", padx=16, pady=(0, 16), expand=True)

        ctk.CTkLabel(left_panel, text="Browser Currently Used", font=("Segoe UI", 20, "bold"), text_color=TEXT_COLOR).pack(anchor="nw", padx=16, pady=(0, 6))
        self.browser_box = ctk.CTkTextbox(left_panel, width=320, height=220, wrap="word")
        self.browser_box.pack(fill="both", padx=16, pady=(0, 16), expand=True)
        self.browser_box.tag_config("url", foreground=URL_COLOR)

        ctk.CTkLabel(center_panel, text="Live Activity", font=("Segoe UI", 24, "bold"), text_color=TEXT_COLOR).pack(anchor="nw", padx=16, pady=(16, 6))
        self.activity_box = ctk.CTkTextbox(center_panel, width=560, height=520, wrap="word", fg_color="#000000")
        self.activity_box.pack(fill="both", padx=16, pady=(0, 16), expand=True)
        self.activity_box.tag_config("activity_title", foreground=ACTIVITY_TITLE_COLOR, font=("Segoe UI", 13, "bold"))
        self.activity_box.tag_config("alert", foreground=ALERT_COLOR, font=("Segoe UI", 12, "bold"))

        ctk.CTkLabel(right_panel, text="Security Summary (Last 7 Days)", font=("Segoe UI", 20, "bold"), text_color=TEXT_COLOR).pack(anchor="nw", padx=16, pady=(16, 6))
        self.summary_box = ctk.CTkTextbox(right_panel, width=340, height=520, wrap="word")
        self.summary_box.pack(fill="both", padx=16, pady=(0, 16), expand=True)

        controls = ctk.CTkFrame(self, fg_color=DARK_PANEL)
        controls.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(controls, text="▶ Start Monitoring", command=self.start_monitoring, fg_color=ACCENT_COLOR).pack(side="left", expand=True, padx=8, pady=8)
        ctk.CTkButton(controls, text="⏹ Stop Monitoring", command=self.stop_monitoring, fg_color="#dc2626").pack(side="left", expand=True, padx=8, pady=8)
        ctk.CTkButton(controls, text="Export CSV", fg_color=ACCENT_COLOR, command=self.export_csv).pack(side="left", expand=True, padx=8, pady=8)
        ctk.CTkButton(controls, text="Export JSON", fg_color=ACCENT_COLOR, command=self.export_json).pack(side="left", expand=True, padx=8, pady=8)
        ctk.CTkButton(controls, text="Generate PDF", fg_color=ACCENT_COLOR, command=self.generate_pdf).pack(side="left", expand=True, padx=8, pady=8)

        search_frame = ctk.CTkFrame(self, fg_color=DARK_PANEL)
        search_frame.pack(fill="x", padx=12, pady=(0, 12))

        self.search_term = ctk.StringVar()
        self.search_start_date = ctk.StringVar()
        self.search_end_date = ctk.StringVar()
        self.search_severity = ctk.StringVar()

        ctk.CTkEntry(search_frame, placeholder_text="Search keyword", textvariable=self.search_term, width=260).pack(side="left", padx=6, pady=12)
        ctk.CTkEntry(search_frame, placeholder_text="Start YYYY-MM-DD", textvariable=self.search_start_date, width=140).pack(side="left", padx=6, pady=12)
        ctk.CTkEntry(search_frame, placeholder_text="End YYYY-MM-DD", textvariable=self.search_end_date, width=140).pack(side="left", padx=6, pady=12)
        ctk.CTkComboBox(search_frame, values=["", "Safe", "Warning", "Critical"], variable=self.search_severity, width=140).pack(side="left", padx=6, pady=12)
        ctk.CTkButton(search_frame, text="Search Logs", fg_color=ACCENT_COLOR, command=self.perform_search).pack(side="left", padx=6, pady=12)

        self.search_results = ctk.CTkTextbox(self, width=1180, height=140, wrap="word")
        self.search_results.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def refresh(self) -> None:
        self._update_system_status()
        self._update_apps_panel()
        self._update_browser_panel()
        self._update_activity_panel()
        self._update_summary_panel()
        self.after(4000, self.refresh)

    def _update_system_status(self) -> None:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        ram_percent = psutil.virtual_memory().percent
        live_state = self.monitor_manager.get_live_snapshot()
        threat = "Safe"
        if live_state["suspicious_alerts"]:
            threat = "Critical"
        self.status_label.configure(text="🟢 Monitoring Active" if self.monitor_manager.is_running else "🔴 Monitoring Stopped")
        self.cpu_label.configure(text=f"CPU {cpu_percent:.0f}%")
        self.ram_label.configure(text=f"RAM {ram_percent:.0f}%")
        self.threat_label.configure(text=f"Threat Level: {threat}")

    def _update_apps_panel(self) -> None:
        live_state = self.monitor_manager.get_live_snapshot()
        if not live_state["monitor_started"]:
            self._set_textbox(self.apps_box, "Monitoring is stopped. Press Start Monitoring to begin.")
            return

        app_lines = []
        for app in live_state["current_apps"][:10]:
            app_lines.append(
                f"{self._app_icon(app['name'])} {app['name']}\nCurrently Active\nCPU: {app['cpu_percent']:.0f}%  RAM: {app['memory_mb']:.0f} MB"
            )
        if not app_lines:
            app_lines = ["No active applications detected."]
        self._set_textbox(self.apps_box, "\n\n".join(app_lines))

    def _update_browser_panel(self) -> None:
        live_state = self.monitor_manager.get_live_snapshot()
        if not live_state["monitor_started"]:
            self._set_textbox(self.browser_box, "Monitoring is stopped. Press Start Monitoring to begin.")
            return

        browser = live_state["current_browser"]
        if browser:
            self.browser_box.configure(state="normal")
            self.browser_box.delete("1.0", "end")
            domain = browser['domain'] or 'Unknown'
            self.browser_box.insert("end", f"{self._browser_icon(browser['browser'])} {browser['browser'].title()}\nActive tab: {browser['title']}\nSite: ")
            self.browser_box.insert("end", domain, "url")
            self.browser_box.insert("end", f"\nRAM: {browser['memory_mb']:.0f} MB")
            self.browser_box.configure(state="disabled")
        else:
            self._set_textbox(self.browser_box, "No active browser detected.")

    def _update_activity_panel(self) -> None:
        live_state = self.monitor_manager.get_live_snapshot()
        if not live_state["monitor_started"]:
            self._set_textbox(self.activity_box, "Monitoring is stopped. No live activity is currently being tracked.")
            return

        self.activity_box.configure(state="normal")
        self.activity_box.delete("1.0", "end")

        if live_state["suspicious_alerts"]:
            self.activity_box.insert("end", "🔴 Suspicious activity detected:\n", "alert")
            for alert in live_state["suspicious_alerts"]:
                self.activity_box.insert("end", f"{alert['message']} — {alert.get('details', '')}\n")
            self.activity_box.insert("end", "\n")

        for app in live_state["current_apps"][:8]:
            self.activity_box.insert("end", f"{self._app_icon(app['name'])} {app['name']}\n", "activity_title")
            self.activity_box.insert("end", f"Currently Active\nCPU: {app['cpu_percent']:.0f}%  RAM: {app['memory_mb']:.0f} MB\n\n")

        if not live_state["suspicious_alerts"] and not live_state["current_apps"]:
            self.activity_box.insert("end", "No live activity detected yet.")

        self.activity_box.configure(state="disabled")

    def _update_summary_panel(self) -> None:
        summary = self.database.get_7day_analysis()
        malware = "Yes" if summary.get("critical_alerts", 0) > 0 else "No"
        lines = [
            f"Failed Login Attempts: {summary.get('failed_logins', 0)}",
            f"USB Devices Connected: {summary.get('usb_insertions', 0)}",
            f"Suspicious PowerShell Events: {summary.get('suspicious_powershell', 0)}",
            f"Malware Detected: {malware}",
            f"Unknown Executables: {summary.get('unknown_executables', 0)}",
            f"Remote Connection Alerts: {summary.get('remote_connections', 0)}",
        ]
        self._set_textbox(self.summary_box, "\n".join(lines))

    def _app_icon(self, app_name: str) -> str:
        key = app_name.lower()
        if "chrome" in key:
            return "🌐"
        if "edge" in key or "msedge" in key:
            return "🟦"
        if "code" in key or "vscode" in key:
            return "💻"
        if "discord" in key:
            return "🎧"
        if "explorer" in key:
            return "🗂️"
        return "🟢"

    def _browser_icon(self, browser_name: str) -> str:
        key = browser_name.lower()
        if "chrome" in key:
            return "🌐"
        if "edge" in key:
            return "🟦"
        if "firefox" in key:
            return "🦊"
        return "🌐"

    def perform_search(self) -> None:
        term = self.search_term.get().strip()
        start_date = self.search_start_date.get().strip() or None
        end_date = self.search_end_date.get().strip() or None
        severity = self.search_severity.get().strip() or None
        results = self.database.search_logs(term, start_date, end_date, severity, limit=SETTINGS.get("search_limit", 100))
        lines = [f"Total matches: {len(results)}"]
        for row in results:
            lines.append(f"[{row['timestamp']}] {row['severity']} - {row['alert_text']}")
        self._set_textbox(self.search_results, "\n".join(lines) or "No search results.")

    def _set_textbox(self, textbox: ctk.CTkTextbox, text: str) -> None:
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.insert("end", text)
        textbox.configure(state="disabled")

    def start_monitoring(self) -> None:
        self.monitor_manager.start()
        self.status_label.configure(text="🟢 Monitoring Active")

    def stop_monitoring(self) -> None:
        self.monitor_manager.stop()
        self.status_label.configure(text="🔴 Monitoring Stopped")

    def export_csv(self) -> None:
        exporter = CSVExporter(self.report_dir)
        alerts = self.database.get_recent_alerts(limit=SETTINGS.get("search_limit", 100))
        exporter.export("sentinelai_alerts", alerts)

    def export_json(self) -> None:
        exporter = JSONExporter(self.report_dir)
        alerts = self.database.get_recent_alerts(limit=SETTINGS.get("search_limit", 100))
        exporter.export("sentinelai_alerts", alerts)

    def generate_pdf(self) -> None:
        report = PDFReport(self.report_dir)
        alerts = self.database.get_recent_alerts(limit=20)
        summary = "SentinelAI generated a local threat assessment and monitored Windows activity."
        report.create("sentinelai_report", summary, alerts, {})
