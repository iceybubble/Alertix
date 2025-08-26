# 🛡️ SIEM Log Generator

A modular and extensible Security Information and Event Management (SIEM) log generator designed to simulate, collect, and store logs from various sources including Chrome, Outlook, Gmail, and Windows systems.

---

## 📁 Project Structure

| Directory/File | Description |
|----------------|-------------|
| `chrome-url-logger/` | Chrome extension and logger to track URL activity |
| `email-gmail-agent/` | Agent to collect Gmail activity via Chrome extension |
| `local-log-agent/`   | Scripts for creating and clearing local logs |
| `logs/`              | Folder containing system-generated logs |
| `siem-log-server/`   | Flask-based server for receiving and visualizing logs |
| `static/`            | Static resources (e.g., charts, CSS, JS) |
| `check_processes.py` | Script to detect suspicious processes (e.g., malware activity) |
| `chrome_logs_api.py` | Flask route to expose Chrome logs and MongoDB integration |
| `clear_logs.sh`      | Script to clear all logs |
| `database.py`        | MongoDB interface for log persistence |
| `env.env`            | Environment variables and auth tokens |
| `gmail_extension_listener.py` | Listener for Gmail Chrome extension logs |
| `outlook_desktop_agent.py` | Script to monitor Outlook desktop activity |
| `requirements.txt`    | Python package dependencies |

---




Ensure your changes are well tested

Follow the existing coding style


