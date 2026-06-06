# 🚀 Alertix: Advanced SIEM & Real-Time Log Monitoring Ecosystem

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-green)](https://www.docker.com/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11.1-005571?logo=elasticsearch)](https://www.elastic.co/elasticsearch/)
[![Kibana](https://img.shields.io/badge/Kibana-8.11.1-E8488B?logo=kibana)](https://www.elastic.co/kibana/)

> Transform raw digital noise into actionable security intelligence and productivity insights.

---

## 📖 Table of Contents

1. [What is Alertix?](#-what-is-alertix)
2. [Motivation & Underlying Problem](#-motivation--underlying-problem)
3. [Core Architecture & Data Flow](#️-core-architecture--data-flow)
4. [Key Features](#-key-features)
5. [Tech Stack](#️-tech-stack)
6. [Folder Structure](#-folder-structure)
7. [Installation & Complete Setup Guide](#-installation--complete-setup-guide)
   - [Method A: Containerized Deployment (Docker)](#method-a-containerized-deployment-docker)
   - [Method B: Local Native Deployment (macOS & Windows)](#method-b-local-native-deployment-without-docker)
8. [Kibana Dashboard](#-kibana-dashboard)
9. [Generating Logs & Simulating Security Incidents](#-generating-logs--simulating-security-incidents)
10. [Verifying and Reviewing Data Logs](#-verifying-and-reviewing-data-logs)
11. [Contributing](#-contributing)
12. [License](#-license)

---

## 🎯 What is Alertix?

### In Simple Terms

**Alertix** is a virtual, real-time guardian for your digital life. It works behind the scenes on your computer and browser to watch your actions, group them into smart categories (like work, study, or entertainment), and immediately catch suspicious behavior or malicious software activity. It takes thousands of confusing raw log lines and turns them into clean, structured, interactive charts — so you can see exactly where your time goes and stay safe online.

### In Cybersecurity Terms

**Alertix** is a high-throughput, cross-platform Security Information and Event Management (SIEM) ecosystem. It implements multi-source decentralized instrumentation via custom endpoint agents (tracking asynchronous file-system modifications, running processes, socket endpoints, and client-side browser DOM actions). Payloads are forwarded over a localized ingestion pipeline where they are parsed through threat signatures, mapped across productivity/threat matrices, dynamically evaluated for risk severity, and stored concurrently using a resilient dual-database architecture (MongoDB + Elasticsearch) for instant analysis and full-text querying.

---

## 🛡️ Motivation & Underlying Problem

In today's hyper-connected landscape, professionals, students, and security analysts face an overlapping dual challenge: **the rapid evolution of stealthy cyber threats** and **the compounding friction of digital distractions.**

Traditional enterprise SIEM solutions are dense, monolithic configurations designed for massive data-center networks — they lack granular visibility into direct endpoint application usage, time management patterns, or client-side browsing behavior. Conversely, typical productivity apps look at screen-time tracking but completely ignore critical security telemetry, such as localized script drops, mass-encryption hooks, or stealthy command-and-control (C2) beaconing.

### Why Alertix?

Alertix bridges this gap with an open-source, lightweight alternative that empowers individuals and teams to:

- 📊 **Visualize Real-Time Time Allocation** — Clear mapping of productive vs. distractive activity vectors.
- 🛡️ **Detect Malicious Anomalies Early** — Instantly flag ransomware indicators, active processes running network utilities, or suspicious external IP lookups.
- ⚠️ **Enable Real-Time Remediation** — Catch privilege escalations or credential harvesting as they happen.
- 💡 **Promote Safer Digital Habits** — Elevate time-management visibility while defending localized endpoints from compromise.

---

## 🏗️ Core Architecture & Data Flow

```
+---------------------------------------------------------------------------------+
|                          DECENTRALIZED AGENTS                                   |
|                                                                                 |
|  [Chrome Extension]  [File Access Monitor]  [Network Agent]  [Log Agent]        |
|  (Browser Activity)  (Watchdog Hooks)       (Psutil Sockets) (System Logs)      |
+---------------------------------------+-----------------------------------------+
                                        |
                              Async HTTPS POST Payloads
                                        ↓
                        +-------------------------------+
                        |       FLASK INGESTION HUB     |
                        |          (server.py)          |
                        +---------------+---------------+
                                        |
            +---------------------------+---------------------------+
            |   Parsing Rules, Severity Mapping & Classification   |
            ↓                                                       ↓
+------------------------+                              +------------------------+
|  MONGODB DOCUMENT DB   |                              |  ELASTICSEARCH ENGINE  |
| (activity_logs BSON)   |                              | (Flattened JSON Index) |
+-----------+------------+                              +-----------+------------+
            ↓                                                       ↓
+------------------------+                              +------------------------+
| MONGODB COMPASS VIEWER |                              |    KIBANA DASHBOARD    |
+------------------------+                              +------------------------+
```

### 1. Central SIEM Engine (`server.py`)

Exposes a single high-throughput `POST /log` endpoint that acts as the analysis funnel:

- **Deterministic Categorization:** Runs incoming strings against optimized categorical arrays — Work, Education, Security, Cloud, Entertainment, Social Media, Shopping, Gaming, Adult, News, Finance, Other.
- **Productivity Profiling:** Translates active categories into high-level vectors — `Productive`, `Distractive`, or `Neutral`.
- **Dynamic Severity Calculation:** Evaluates payload parameters using an ordered progression (`Low → Medium → High → Critical`) via string keyword matching and Indicators of Compromise (IOC) regex logic.

### 2. Dual-Database Storage Architecture

Every log payload undergoes an internal duplication path to eliminate single points of failure:

- **MongoDB Store:** Maintains transaction-safe BSON trees, preserving the exact structural integrity of arriving streams for quick status summaries.
- **Elasticsearch Index Engine:** Flattens incoming objects and standardizes timestamps into ISO-8601. This acts as the raw engine powering complex full-text exploration, regex mapping, and analytical dashboard feeds.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔌 **Multi-Source Event Ingestion** | Captures data simultaneously from web browsers, local file systems, live network interfaces, and system event channels |
| 🧠 **Keyword Threat Classification** | Split-second sorting without heavy external runtime dependencies |
| 🔥 **Ransomware Burst Tracking** | Measures localized rename/delete frequencies per minute to detect file-system locking events |
| ⚙️ **Process Interception Engine** | Scans active process blocks for unauthorized network tools (`nc`, `nmap`, etc.) |
| 📊 **Kibana Reporting & Visualization** | Populates charts, event counts over time, and category breakdowns in custom analytical dashboards |
| 🔔 **Real-Time Alerting** | Configurable thresholds with Email/SMS notifications |
| 🎯 **Productivity Analytics** | Aggregated time allocation reports benchmarked against user-defined goals |

### Severity Levels

| Severity | Description | Examples | Indicator |
|---|---|---|---|
| 🟢 **Low** | Productive activities | Work emails, study sites | Safe |
| 🟡 **Medium** | Mild distractions | News, shopping, social media | Monitor |
| 🟠 **High** | Strong distractions or suspicious activity | Gaming, entertainment, admin tools | Warning |
| 🔴 **Critical** | Security threats | Adult sites, blacklisted IPs, ransomware patterns | Immediate Action |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Core Platform Engine | Python 3.x |
| Asynchronous Web Ingestion | Flask + Flask-CORS + Gunicorn |
| NoSQL Transactional Layer | MongoDB 6.0 |
| Data Indexing & Aggregations | Elasticsearch 8.11.1 |
| Visualization Interface | Kibana 8.11.1 |
| Endpoint System Hooks | Watchdog, Psutil, PyWin32 (Windows) |
| Browser Extension | Chrome Extension API (Manifest V3) |

---

## 📂 Folder Structure

```
Alertix/
├── chrome-extension/          # Client browser extension for URL tracking
│   ├── manifest.json          # Chrome Extension configuration
│   ├── background.js          # Asynchronous listener scripts
│   └── popup.html             # Local status layout interface
├── local-log-agent/           # System-level auditing monitors
│   ├── agent.py               # Main platform log tailer and process scanner
│   ├── file_access_agent.py   # Watchdog filesystem file action monitor
│   └── network_agent.py       # Psutil active socket tracker
├── siem-log-server/           # Ingestion pipeline layer
│   ├── logs/                  # Localized storage for raw server.log
│   ├── requirements.txt       # Server dependencies
│   └── server.py              # Central Flask SIEM parsing hub
├── images/                    # Screenshots and visual documentation
├── .env.example               # Configuration blueprint template
├── docker-compose.yml         # Multi-container deployment architecture
├── requirements.txt           # Root Python dependencies
└── README.md                  # Documentation
```

---

## 🔧 Installation & Complete Setup Guide

### Method A: Containerized Deployment (Docker)

**Prerequisites**

Verify your host machine has the following installed:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Engine v20.10.x or higher)
- [Docker Compose](https://docs.docker.com/compose/) (v2.x or higher)
- [Python 3.10 / 3.11](https://www.python.org/downloads/)

---

**Step 1 — Clone the Repository**

```bash
git clone https://github.com/iceybubble/Alertix.git
cd Alertix
```

**Step 2 — Configure Environment Variables**

Create a `.env` file in the project root using the provided template:

```bash
cp .env.example .env
```

Then edit `.env` with your values:

```env
# Flask Infrastructure Settings
FLASK_SECRET_KEY=4a2eb91c784fe212389d02cb00a2f
SERVER_PORT=5000

# Containerized Internal Networking Addresses
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200
MONGO_URI=mongodb://mongodb:27017/
MONGO_DB_NAME=alertix_db
```

**Step 3 — Launch the Containerized Stack**

```bash
docker-compose up --build -d
```

> ⏳ **Note:** Elasticsearch can take up to 2 minutes to fully initialize. Monitor the server logs with:
> ```bash
> docker-compose logs -f siem-server
> ```
> Wait until you see `Running on http://0.0.0.0:5000` before proceeding.

---

### Method B: Local Native Deployment (Without Docker)

If you prefer running the system natively on macOS or Windows without containers, follow these steps.

**Prerequisites**

- [Python 3.10 / 3.11](https://www.python.org/downloads/)
- [MongoDB Community Edition](https://www.mongodb.com/try/download/community) running locally (or a free cloud instance on [MongoDB Atlas](https://www.mongodb.com/cloud/atlas))
- [Elasticsearch v8.x](https://www.elastic.co/downloads/elasticsearch) running locally

---

**Configure Environment Variables**

Create or edit `.env` in the project root. Change container hostnames to `localhost`:

```env
# Flask Infrastructure Settings
FLASK_SECRET_KEY=YOUR_FLASK_SECRET
SERVER_PORT=5000

# Local Native Addresses
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
MONGO_URI=mongodb://localhost:27017/
MONGO_DB_NAME=alertix_db
```

---

**🍏 macOS Setup**

```bash
cd siem-log-server
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

python3 server.py
```

The Flask backend is now listening on `http://localhost:5000`.

---

**🪟 Windows Setup**

```bash
cd siem-log-server
python -m venv venv
```

Activate the virtual environment:

```powershell
# PowerShell
.\venv\Scripts\Activate.ps1

# OR Command Prompt (CMD)
.\venv\Scripts\activate.bat
```

Then install dependencies and start the server:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python server.py
```

The Flask backend is now listening on `http://localhost:5000`.

---

### Step 4 — Configure and Run Local Monitoring Agents (All Platforms)

Open separate terminal windows for each agent below.

**Agent 1 — File Access Monitor**

Watches for file creation, modification, and deletion events across the system.

```bash
cd local-log-agent
pip install requests watchdog
python file_access_agent.py
```

This terminal will now sit silently, listening for system-wide file modifications and forwarding events to the ingestion server.

**Agent 2 — Network Connection Monitor**

Tracks active socket connections and flags connections to suspicious or blacklisted IP addresses.

```bash
cd local-log-agent
pip install psutil requests
python network_agent.py
```

**Agent 3 — Log Tailer & Process Scanner**

Continuously tails system logs and scans running processes for unauthorized tools.

```bash
cd local-log-agent
python agent.py
```

---

### Step 5 — Load the Chrome Extension Agent

1. Open Google Chrome and navigate to `chrome://extensions/`
2. Toggle **Developer mode** ON (top-right corner)
3. Click **Load unpacked** (top-left)
4. Select the `chrome-extension/` directory from your cloned project folder
5. The extension will initialize and connect to the server on port `5000`

---

## 📊 Kibana Dashboard

Once data is flowing, head to `http://localhost:5601` to explore your Kibana dashboards. Below is a live example of the Alertix monitoring dashboard showing real-time event severity distribution, activity categories, and critical alert timelines.

![Alertix Kibana Dashboard](images/kibana-dashboard.png)

> **Setting up the Data View for the first time:**
> 1. Go to **Stack Management → Data Views → Create Data View**
> 2. Set the index pattern to `alertix-logs`
> 3. Set `timestamp` as the primary time field
> 4. Open the **Discover** pane to view, filter, and graph arriving logs

The dashboard provides:
- **Bar Charts** — Severity distribution across all ingested events
- **Line Charts** — Critical security events plotted over time
- **Data Tables** — Suspicious IPs ranked by connection frequency
- **Pie Charts** — Full activity category breakdown (Productive / Neutral / Distractive / Critical)
- **Heatmaps** — Productive vs. distractive time patterns by day and week
- **Area Charts** — Category comparison across custom time windows
- **Gauge Charts** — Live productivity score (e.g., 75% productive time today)

---

## 🔬 Generating Logs & Simulating Security Incidents

After the stack is running and all agents are active, you can send safe test events to verify that the ingestion pipeline, severity classifier, and Kibana dashboards are all working correctly. The commands below simulate realistic threat patterns without causing any actual harm to your system.

> ⚠️ **Note:** All test commands below are safe simulations. They generate log events that Alertix detects and classifies — they do **not** compromise, damage, or exfiltrate anything from your machine.

---

### 1. Simulate File Integrity Warnings & Ransomware Alerts

These two commands exercise the file integrity and ransomware burst-detection pipelines.

**Test A — Simulate a Hidden Environment Config Update (Medium/High Severity)**

This mimics a scenario where malware silently writes credentials into a local `.env` file — a common technique used by info-stealers and supply-chain attackers.

```bash
# Creates a fake .env with a dummy password string
# Alertix detects writes to sensitive config files and raises a Medium/High alert
echo "PASSWORD=prod_db_root" > local-log-agent/.env
```

**What to expect in Kibana:** A new log entry should appear under the `file_access` category with severity `Medium` or `High`, flagged due to the `PASSWORD=` keyword matching credential-harvesting IOC rules.

---

**Test B — Simulate a Ransomware File Encryption Burst (Critical Severity)**

This mimics the file-locking behavior of ransomware — where malware rapidly creates hundreds of `.locked` files across a directory in a short window.

```bash
# Creates 25 dummy ".locked" files in rapid succession
# Alertix's burst-frequency engine flags mass-rename/lock events as Critical
for i in {1..25}; do echo "encrypted_payload" > "local-log-agent/file_$i.locked"; done
```

**What to expect in Kibana:** The Ransomware Burst Tracker will log a `Critical` severity alert. The event count spike will be visible in the Line Chart under the "Critical Events Over Time" visualization. Once you're done, clean up with:

```bash
rm local-log-agent/file_*.locked local-log-agent/.env
```

---

### 2. Simulate a Suspicious Admin Tool Execution (High Severity)

This exercises the Process Interception Engine, which scans running processes for known network reconnaissance and exploitation utilities.

```bash
# Netcat help flag — non-destructive, simply checks if 'nc' is available
# Alertix detects invocation of known admin/network tools and raises a High alert
nc -h
```

**What to expect in Kibana:** A `High` severity event tagged as `Suspicious Administrative Utility Execution` will appear in the Data Table and Severity Bar Chart. The process name `nc` is on Alertix's monitored tool list alongside `nmap`, `tcpdump`, and others.

> 💡 **If `nc` is not installed:** On macOS, it's bundled by default. On Windows, you can install it via [Nmap](https://nmap.org/download.html) or simply skip this test — the agent will still detect any other recognized tools if they run.

---

### 3. Simulate a Blacklisted Threat-Intel IP Communication (High/Critical Severity)

This exercises the Network Agent's outbound connection monitoring. The IP address `185.220.101.47` is a known Tor exit node that appears on multiple public threat-intelligence blocklists.

```bash
# Attempts an HTTP connection to a known threat-intel blacklisted IP
# Alertix's network agent flags outbound connections to IOC-listed addresses
curl http://185.220.101.47
```

**What to expect in Kibana:** A `High` or `Critical` severity alert will appear tagged as `Blacklisted IP Connection Event`. The source IP, timestamp, and severity are all logged to Elasticsearch for dashboard display.

> 💡 **Note:** The `curl` command will likely time out or return an error — that is expected and fine. The connection *attempt* itself is what Alertix monitors and logs; a successful response is not required.

---

### Verifying Your Simulation Results End-to-End

After running any combination of the above triggers, verify that events have propagated correctly through the entire stack:

**1. Check the live server log:**
```bash
# Docker
docker-compose logs -f siem-server

# Native
tail -f siem-log-server/logs/server.log
```
You should see incoming POST payloads logged with their parsed category and severity level.

**2. Check MongoDB Compass:**
- Connect to `mongodb://127.0.0.1:27017/`
- Open the `alertix_db` namespace
- Inspect documents in the `activity_logs` collection — each event should appear as a structured BSON document

**3. Check Kibana:**
- Navigate to `http://localhost:5601`
- Open the **Discover** pane under the `alertix-logs` data view
- Filter by `severity: Critical` or `category: ransomware` to isolate your test events
- The dashboard charts should reflect the new spike in events

---

## ✅ Verifying and Reviewing Data Logs

| Interface | Access | What to Look For |
|---|---|---|
| **Live Server Output** | `tail -f siem-log-server/logs/server.log` | Incoming POST payloads with parsed severity labels |
| **MongoDB Compass** | `mongodb://127.0.0.1:27017/` → `alertix_db` → `activity_logs` | Full BSON documents per log event |
| **Kibana Discover** | `http://localhost:5601` → Discover | Filterable, sortable log stream |
| **Kibana Dashboard** | `http://localhost:5601` → Dashboards | Visual charts, severity gauges, category breakdowns |

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the project
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📜 License & Star History

Distributed under the MIT License. See `LICENSE` for more information.

### Star History

If you find this project helpful, please consider giving it a ⭐ — it helps others discover Alertix!

[![Star History Chart](https://api.star-history.com/svg?repos=iceybubble/Alertix&type=Date)](https://github.com/iceybubble/Alertix)

---

<p align="center">Built with ❤️ by <a href="https://github.com/iceybubble">iceybubble</a></p>