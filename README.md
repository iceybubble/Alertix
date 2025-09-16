# 🚀 Alertix

## Real-Time Log Monitoring & Alert Dashboard

*Alertix* is a comprehensive, open-source real-time log monitoring and alerting system engineered to deliver in-depth insights into your online activities, productivity patterns, and emerging security threats.  

By aggregating logs from diverse sources such as browsers, email clients, and local applications, Alertix:

- Categorizes activities
- Assesses their severity
- Presents the data via dynamic, interactive dashboards in *Kibana*

This tool empowers users to enhance productivity, identify distractions, and mitigate risks like suspicious IP accesses or unauthorized content exposure.  

Ideal for individuals, teams, or organizations focused on *time management, **cybersecurity, and **data-driven decision-making*, Alertix transforms raw log data into actionable intelligence.

> In today's digital landscape, where distractions abound and cyber threats evolve rapidly, *Alertix* stands as a vigilant guardian.

Whether you're a *student, **professional, or **security analyst*, Alertix provides the transparency and tools needed to stay ahead.

---

## 🌟 Motivation

In an era of constant connectivity, it's challenging to maintain focus and security online.

### Why Alertix?

- 📊 *Visualize Time Usage:* Productive vs. distractive time
- 🛡 *Detect Risks:* Adult content, suspicious IPs
- ⚠ *Enable Real-Time Action:* Immediate alerts
- 💡 *Promote Better Habits:* Improve digital behaviors

By leveraging *open-source technologies*, Alertix ensures accessibility, customizability, and community-driven enhancements.

---

## ✨ Features

### ✅ Multi-Source Log Collection

- Logs from:
  - Browser extensions (e.g., Chrome URL logger)
  - Email clients (Gmail, Outlook)
  - Local applications
  - SIEM generators
- *Real-time ingestion* for up-to-the-minute insights

### 🧠 Advanced Activity Categorization

- Categories:
  - *Productive:* Work, Study, Education
  - *Neutral:* News, Finance, Shopping, Social Media
  - *Distractive:* Entertainment, Gaming
  - *Risky/Critical:* Adult Content, Suspicious IPs
- Customizable category rules

### 🔥 Severity Assessment

| Severity  | Description            | Examples                   | Color Code  |
|----------|------------------------|----------------------------|-------------|
| Low      | Productive activities  | Work emails, study sites   | ✅ Green     |
| Medium   | Mild distractions      | News, shopping, social     | 🟡 Yellow    |
| High     | Strong distractions    | Gaming, entertainment      | ⚠ Orange     |
| Critical | Security threats       | Adult sites, unknown IPs   | 🛑 Red       |

---

### 📊 Interactive Visualizations (via Kibana)

- Bar Charts: Severity distribution
- Line Charts: Critical events over time
- Data Tables: Suspicious IPs, frequency
- Pie Charts: Activity breakdown
- *Heatmaps* (🆕): Productive vs distractive time by day/week
- Area Charts: Category comparison over time
- *Gauge Charts*: Productivity score (e.g., 75%)

➡ *Custom Dashboards:* Create personalized views.

---

### 📈 Productivity Analytics

- Aggregated time allocation reports
- Benchmark vs. goals (e.g., 80% productive time)

### 🔔 Real-Time Alerting System

- Alerts via Email/SMS
- Custom thresholds (e.g., alert if distraction > 2 hrs)

### 🔌 Extensibility

- Plugin architecture for new log sources
- Integrate with external SIEMs (enterprise use)

---

## 🛠 Tech Stack

- *Python 3.x*: Log processing, Elasticsearch integration
- *Elasticsearch 7.x+*: Search & analytics engine
- *Kibana 7.x+*: Dashboard & alerting UI
- *SIEM Tools*: Simulated log generators
- *Browser Extensions*: Chrome API for URL logging
- *Email Agents*: Gmail & Outlook listeners
- *Databases*: SQLite / PostgreSQL

---

## 📂 Folder Structure

```plaintext
Alertix/
├── .vscode/                  # VS Code settings
├── SIEM-Log-Generator/       # Simulated SIEM logs
├── chrome-url-logger/        # Browser URL tracking
├── email-gmail-agent/        # Gmail monitoring
├── local-log-agent/          # Local log collector
├── siem-log-server/          # SIEM log ingestion
├── check_processes.py        # Monitor running processes
├── chrome_bgs_api.py         # Chrome API integration
├── clear_logs.sh             # Log cleanup script
├── database.py               # DB utilities
├── gmail_extension_listener.py # Gmail listener
├── outlook_desktop_agent.py  # Outlook agent
├── render.yaml               # Render.com deploy config
├── requirements.txt          # Python dependencies
├── server.py                 # Main Python server
├── umcorn.jpg                # Logo/image (possibly 'unicorn.jpg')
