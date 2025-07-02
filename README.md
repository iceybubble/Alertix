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

## 🚀 Features

- Real-time log collection from:
  - **Chrome** (web activity)
  - **Gmail** (email opens)
  - **Outlook Desktop**
  - **File Access** and **Process Monitoring**
- Dashboard for visualizing productive vs. entertainment time
- Rule-based alerting system using `alert_rules.py`
- MongoDB integration for persistent log storage

---

## ⚙️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/iceybubble/SIEM-Log-Generator.git
cd SIEM-Log-Generator

2. Install Dependencies
bash
pip install -r requirements.txt

3. Set Environment Variables
Update env.env with your secrets (e.g., Gmail API tokens).

4. Run the Server
You can use Waitress (for Windows):

bash
waitress-serve --host 0.0.0.0 --port 10000 server:app

Or directly with Flask (for development):

bash
python siem-log-server/server.py


📊 Visualizations

To view Chrome usage stats:

bash
http://localhost:5000/chrome-logs/stats

🔄 Useful Scripts
clear_logs.sh – Deletes all generated logs

check_processes.py – Monitors for suspicious activity

🧪 Example Use Cases
Simulate SIEM behavior in a training/lab environment

Analyze user activity across email, browser, and desktop apps

Build and test alerting rules for suspicious behavior

📄 LICENSE
MIT License

Copyright (c) 2025 iceybubble

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


🤝 CONTRIBUTING.md
# Contributing to SIEM Log Generator

Thanks for your interest in contributing! We welcome all contributions that help improve this project.

## 🧰 Ways to Contribute

- 🐛 **Report bugs**
- 💡 **Request features**
- 🛠️ **Submit code fixes**
- 📄 **Improve documentation**
- 🚀 **Create new log agents or alerts**

---

## 🛠 Setup for Development

1. **Clone the repo:**

```bash
git clone https://github.com/iceybubble/SIEM-Log-Generator.git
cd SIEM-Log-Generator

Install dependencies:

bash
pip install -r requirements.txt

Run the server:

bash
python siem-log-server/server.py

✅ Pull Request Guidelines
Create a feature branch (feature/<name>, bugfix/<name>)

Ensure your changes are well tested

Follow the existing coding style


