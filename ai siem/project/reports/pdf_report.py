from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from typing import List, Dict
from utils.helpers import ensure_directory


class PDFReport:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        ensure_directory(self.output_dir)

    def create(self, filename: str, summary: str, alerts: List[Dict[str, str]], resource_summary: Dict[str, float]) -> Path:
        path = self.output_dir / f"{filename}.pdf"
        with PdfPages(path) as pdf:
            fig, ax = plt.subplots(figsize=(8.5, 11))
            fig.patch.set_facecolor("#121212")
            ax.axis("off")
            text = [
                f"SentinelAI Threat Report",
                f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
                "",
                "Summary:",
                summary,
                "",
                "Recent Alerts:",
            ]
            for alert in alerts[:10]:
                text.append(f"- {alert.get('timestamp')} | {alert.get('severity')} | {alert.get('alert_text')}")
            text.append("")
            text.append("Resource Snapshot:")
            for key, value in resource_summary.items():
                text.append(f"- {key}: {value}")
            ax.text(0.01, 0.99, "\n".join(text), va="top", color="white", fontsize=10, family="monospace")
            pdf.savefig(fig, facecolor=fig.get_facecolor())
            plt.close(fig)
        return path
