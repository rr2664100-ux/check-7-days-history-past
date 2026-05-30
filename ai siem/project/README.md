# SentinelAI

SentinelAI is a modular Windows cybersecurity monitoring and lightweight EDR/SIEM system built with Python 3.12. The project is designed for educational cybersecurity research, final year projects, SIEM/EDR learning, threat monitoring practice, and malware behavior analysis learning.

## What it does

- Monitors Windows Event Viewer logs (Security, System, Application)
- Tracks running applications, process start/stop, background services, and hidden processes
- Detects browser activity for Chrome, Edge, and Firefox without scraping private data
- Monitors CPU, RAM, disk and network usage in real time
- Detects suspicious PowerShell commands, encoded scripts, persistence techniques, and remote access indicators
- Scans process memory and command lines for suspicious patterns
- Converts technical alerts into human-readable information
- Generates CSV, JSON, and PDF reports
- Runs as a local monitoring application only, with safe defensive behavior

## Project structure

```
project/
│
├── main.py
├── installer.py
├── requirements.txt
├── README.md
│
├── config/
│   ├── settings.py
│   └── constants.py
│
├── monitoring/
├── detection/
├── scanner/
├── ai_engine/
├── database/
├── reports/
├── ui/
├── utils/
├── logs/
└── assets/
```

## Installation

1. Install Python 3.12 on Windows 10/11.
2. Open VS Code in the `project` folder.
3. Run:
   ```bash
   python main.py
   ```

The project includes an auto-installer that checks for dependencies and installs required packages automatically.

## Running the application

- Launch `main.py`.
- The dashboard will open in a dark theme.
- The application monitors the local Windows machine only.
- If administrator permissions are available, the application enables richer Windows event and startup scans.

## Build a Windows executable

Install `pyinstaller` and run:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed main.py
```

## Notes

- SentinelAI is a defensive tool and does NOT include offensive hacking capabilities.
- It is intended for learning and research.
- It does not perform password theft, cookie theft, remote control, exploit delivery, or destructive actions.
