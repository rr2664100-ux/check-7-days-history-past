import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from typing import Dict, List


class GraphPanel(ctk.CTkFrame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.figure = Figure(figsize=(5, 2.5), dpi=100)
        self.axes = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=12, pady=12)

    def update_graph(self, resource_summary: Dict[str, float], network_history: List[Dict[str, float]]) -> None:
        self.axes.clear()
        if resource_summary:
            cpu = resource_summary.get("cpu_percent", 0)
            memory = resource_summary.get("memory_percent", 0)
            disk = resource_summary.get("disk_percent", 0)
            self.axes.plot([0, 1, 2], [cpu, memory, disk], marker="o", label="Resource %")
            self.axes.set_ylim(0, 100)
            self.axes.set_xticks([0, 1, 2])
            self.axes.set_xticklabels(["CPU", "RAM", "Disk"])
            self.axes.set_title("System Resource Overview")
            self.axes.set_ylabel("Usage %")
        if network_history:
            speeds = [entry.get("download_bps", 0) / 1024 for entry in network_history[-5:]]
            self.axes2 = self.axes.twinx()
            self.axes2.plot(speeds, color="#f97316", linestyle="--", marker="x", label="Download KB/s")
            self.axes2.set_ylabel("KB/s")
        self.figure.tight_layout()
        self.canvas.draw()
