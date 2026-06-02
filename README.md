# 🚀 Alertix: Advanced SIEM & Real-Time Log Monitoring Ecosystem

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue)
![Docker Ingestion](https://img.shields.io/badge/Docker-Containerized-green)

> Transform raw digital noise into actionable security intelligence and productivity insights.

---

## 📖 Table of Contents
1. [What is Alertix?](#-what-is-alertix)
2. [Motivation & Underlying Problem](#-motivation--underlying-problem)
3. [Core Architecture & Data Flow](#-core-architecture--data-flow)
4. [Key Features](#-key-features)
5. [Tech Stack](#-tech-stack)
6. [Folder Structure](#-folder-structure)
7. [Installation & Complete Setup Guide](#-installation--complete-setup-guide)
8. [Generating Logs & Simulating Security Incidents](#-generating-logs--simulating-security-incidents)
9. [Verifying and Reviewing Data Logs](#-verifying-and-reviewing-data-logs)
10. [Contributing](#-contributing)
11. [License & Star History](#-license--star-history)

---

## 🎯 What is Alertix?

### In Simple Terms
**Alertix** is a virtual, real-time guardian for your digital life. It works behind the scenes on your computer and browser to watch your actions, group them into smart categories (like work, study, or entertainment), and immediately catch bad behavior or malicious software. It takes thousands of confusing log lines and turns them into clean, beautiful, interactive charts so you can see exactly where your time goes and stay completely safe online.

### In Cybersecurity Terms
**Alertix** is a high-throughput, cross-platform Security Information and Event Management (SIEM) ecosystem. It implements multi-source decentralized instrumentation via custom endpoint agents (tracking asynchronous file-system modifications, processes, socket endpoints, and client-side browser DOM actions). Payloads are forwarded over a localized ingestion pipeline where they are parsed through hardcoded threat signatures, mapped across productivity threat matrixes, dynamically evaluated for risk severity, and stored concurrently using a resilient, dual-database architecture (MongoDB + Elasticsearch) for instant analysis and full-text querying.

---

## 🛡️ Motivation & Underlying Problem

In today's hyper-connected landscape, professionals, students, and security analysts face an overlapping dual challenge: **the rapid evolution of stealthy cyber threats** and **the compounding friction of digital distractions.** 

Traditional enterprise SIEM solutions are dense, monolithic configurations designed for massive data-center networks; they lack granular visibility into direct endpoint application usage, time management patterns, or client-side browsing distractions. Conversely, typical productivity applications look at screen-time tracking but completely ignore critical security telemetry—such as localized script drops, mass-encryption hooks, or stealthy command-and-control (C2) beaconing.

### Why Alertix?
Alertix bridges this gap by offering an open-source, lightweight alternative. It empowers individuals and teams to:
* 📊 **Visualize Real-Time Time Allocation:** Clear mapping of Productive vs. Distractive vectors.
* 🛡️ **Detect Malicious Anomalies Early:** Instantly flagging ransomware indicators, active processes running network utilities, or suspicious external IP lookups.
* ⚠️ **Enable Real-Time Remediation:** Catching privilege escalations or credential harvesting as they happen.
* 💡 **Promote Safer Digital Habits:** Elevating time-management visibility while defending localized endpoints from compromise.

---

## 🏗️ Core Architecture & Data Flow

```plaintext
+---------------------------------------------------------------------------------+
|                               DECENTRALIZED AGENTS                              |
|                                                                                 |
|  [Chrome Extension]    [File Access Monitor]    [Network Agent]    [Log Agent]  |
|   (Browser Activity)      (Watchdog Hooks)      (Psutil Sockets)  (System Logs) |
+---------------------------------------+-----------------------------------------+
                                        |
                                        | Asynchronous HTTPS POST Payloads
                                        v
                        +-------------------------------+
                        |      FLASK INGESTION HUB      |
                        |          (server.py)          |
                        +---------------+---------------+
                                        |
             +--------------------------+--------------------------+
             | Parsing Rules, Severity Mapping & Classification   |
             v                                                     v
+------------------------+                               +------------------------+
|  MONGODB DOCUMENT DB   |                               |  ELASTICSEARCH ENGINE  |
|  (activity_logs BSON)  |                               |  (Flattened JSON Index)|
+-----------+------------+                               +-----------+------------+
            |                                                        |
            v                                                        v
+------------------------+                               +------------------------+
| MONGODB COMPASS VIEWER |                               |   KIBANA DASHBOARD     |
+------------------------+                               +------------------------+
```
##

## 
**1. Central SIEM Engine (server.py)**

Exposes a single high-throughput POST endpoint (/log). 

- The server acts as an analysis funnel:Deterministic Categorization: Runs incoming strings against optimized categorical arrays (Work, Education, Security, Cloud, Entertainment, Social Media, Shopping, Gaming, Adult, News, Finance, Other).

- Productivity Profiling: Translates active groups into high-level vectors: Productive (engineering, administration, learning), Distractive (non-business vectors), or Neutral.

- Dynamic Severity Calculations: Evaluates payload parameters using an ordered array progression (Low $\rightarrow$ Medium $\rightarrow$ High $\rightarrow$ Critical) using string keywords and Indicators of Compromise (IOC) regular expression logic.

##

##

**2. Dual-Database Storage Architecture**

To ensure extreme resilience and eliminate single points of failure, every log payload undergoes an internal duplication path:

MongoDB Store: Maintains transaction-safe BSON trees. It preserves the exact structural integrity of arriving streams and handles quick retrieval tasks for status summaries.

Elasticsearch Index Engine: Flattens incoming objects and standardizes timestamps into ISO-8601 strings. This acts as the raw engine fueling complex full-text exploration, regex mapping, and structural analytical dashboards.

##

##

**✨ Key Features**

Multi-Source Event Ingestion: Captures data simultaneously from web browsers, underlying local files, live network infrastructure interfaces, and system event channels.

Keyword Threat Classification: Performs split-second sorting without relying on heavy external runtime dependecies.

Ransomware Burst Tracking: Measures localized rename and delete frequencies per minute to spot file-system locking actions.

Process Interception Engine: Scans active process execution blocks for unauthorized network tools (nc, nmap, etc.).

Kibana Reporting Visualization: Populates charts, event counts over time, and categories inside custom analytical dashboards.

##

**🛠️ Tech Stack**

Core Platform Engine: Python 3.x

Asynchronous Web Ingestion Core: Flask + Flask-CORS + Gunicorn

NoSQL Transactional Layer: MongoDB 6.0

Data Indexing & Aggregations: Elasticsearch 8.11.1

Visualization Interface UI: Kibana 8.11.1

Endpoint System Hook Extensions: Watchdog, Psutil, PyWin32 (for Windows environments)

##

##

**Folder Structure**

Alertix/
├── .vscode/                   # Development environment configurations
├── chrome-extension/          # Client browser extension for URL tracking
│   ├── manifest.json          # Chrome Extension configuration
│   ├── background.js          # Asynchronous listener scripts
│   └── popup.html             # Local status layout interface
├── local-log-agent/           # System-level auditing monitors
│   ├── agent.py               # Main platform log tailer and process scan script
│   ├── file_access_agent.py   # Watchdog filesystem file action monitor
│   └── network_agent.py       # Psutil active socket tracker
├── siem-log-server/           # Ingestion pipeline layer
│   ├── logs/                  # Localized storage folder for raw server.log
│   ├── requirements.txt       # Server dependencies
│   └── server.py              # Central Flask SIEM parsing hub
├── .env.example               # Configuration blueprint template for infrastructure keys
├── docker-compose.yml         # Global multi-container deployment architecture
└── README.md                  # Comprehensive technical documentation

##

##

**Installation & Complete Setup Guide**

**Prerequisites**

Before deployment, verify that your host machine has the following packages properly installed:

Docker Desktop (Engine version 20.10.x or higher)

Docker Compose (v2.x or higher)

Python 3.10 / 3.11

Step 1: Clone the Repository
Open your host machine terminal and check out the code space:

```
git clone [https://github.com/iceybubble/Alertix.git](https://github.com/iceybubble/Alertix.git)

cd Alertix
```

Step 2: Establish Your Environment Variables
Create a protected .env configuration file in the root of your project folder using our secure template blueprint:

```
# Central Flask Infrastructure Settings
FLASK_SECRET_KEY=4a2eb91c784fe212389d02cb00a2f
SERVER_PORT=5000

# Containerized Internal Networking Addresses
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200
MONGO_URI=mongodb://mongodb:27017/
MONGO_DB_NAME=alertix_db
```

Step 3: Launch the Containerized Stack
Deploy the virtualized backend services simultaneously inside their shared isolated bridge network:

```
docker-compose up --build -d

```

Note on Boot Speeds: Elasticsearch can take up to 2 minutes to initialize completely. Check the server connection health and wait for database dependencies to become fully available via:

```
docker-compose logs -f siem-server
```

---

### Step 4: Configure and Initialize Local Monitoring Agents
Open a separate, native terminal on the machine you wish to monitor to run the Python agents.

#### 1. Setup & Run the File Access Agent
```bash
cd local-log-agent
pip install requests watchdog
python file_access_agent.py
```

(This terminal will now sit silently, listening for system-wide file modifications.)

2. Run the Network Active Connection Monitor

```
cd local-log-agent
pip install psutil requests
python network_agent.py
```

3. Run the Native Log Tailer & Process Scanner

```
cd local-log-agent
python agent.py
```

Step 5: Load the Chrome Extension Agent

1.Open Google Chrome and navigate directly to: chrome://extensions/

2.Toggle the Developer mode switch in the top-right corner to On.

3.Click the Load unpacked button visible in the top-left section.

4.Select the chrome-extension directory from your cloned project folder path.

5.The extension will initialize and securely connect to your containerized server on port 5000.

Generating Logs & Simulating Security Incidents
To ensure your pipelines can classify events correctly and assign the right severity scores, open a separate terminal window and run these safe test triggers:

1. Trigger File Integrity Warnings & Ransomware Alerts

```
# Trigger a Medium/High Alert (Simulating hidden environment config updates)
echo "PASSWORD=prod_db_root" > local-log-agent/.env

# Trigger a Critical Ransomware Alert (Simulate high-frequency mass encryption locks)
for i in {1..25}; do echo "encrypted_payload" > "local-log-agent/file_$i.locked"; done

```

2. Trigger Suspicious Admin Tool Process Discoveries

```
# Trigger a Suspicious Administrative Utility Execution Warning
nc -h
```

3. Simulate Blacklisted Threat-Intel Communication

```
# Trigger a High/Critical Connection Event to an Intel-Blacklisted IP Address
curl [http://185.220.101.47](http://185.220.101.47)
```
##

##
**Verifying and Reviewing Data Logs**
Once your trigger commands are processed, you can observe data records populated natively across your entire administrative stack:

Live Output Logs: Stream the active centralized log server output via:

tail -f siem-log-server/logs/server.log

* **MongoDB Compass Document View:** Connect your MongoDB GUI to `mongodb://127.0.0.1:27017/`. Open the `alertix_db` namespace and explore documents inside the `activity_logs` collection.
* **Kibana Analytical Dashboarding:** Open your browser and navigate to `http://localhost:5601`. 
  1. Head to **Stack Management** $\rightarrow$ **Data Views** $\rightarrow$ **Create Data View**.
  2. Input `alertix-logs` as the index pattern and assign `timestamp` as the primary tracking time field.
  3. Open the **Discover** pane to view, filter, and track data graphs of arriving infrastructure logs.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License & Star History

Distributed under the MIT License. See `LICENSE` for more information.

### Star History
If you find this project helpful, please give it a star! ⭐

[![GitHub Trending](https://api.star-history.com/svg?repos=iceybubble/Alertix&type=Date)](https://github.com/iceybubble/Alertix)

##