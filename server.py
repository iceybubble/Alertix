from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
import os
import io
import re

# ---- chart backend ----
import matplotlib
matplotlib.use("Agg")  # headless rendering for servers
import matplotlib.pyplot as plt

# ---------------- Flask Setup ----------------
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)
app.secret_key = "supersecret"  # Replace with a secure key in production

# ---------------- Log Directory Setup ----------------
log_dir = Path(__file__).parent / "siem-log-server" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)
log_file_path = log_dir / "server.log"

# ---------------- Custom Logging Handler ----------------
class FlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

file_handler = FlushFileHandler(log_file_path, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)

if app.logger.hasHandlers():
    app.logger.handlers.clear()
app.logger.addHandler(console_handler)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

app.logger.info("Starting SIEM server")
app.logger.info(f"Log file path: {log_file_path.resolve()}")

# ---------------- Elasticsearch Setup ----------------
es = Elasticsearch(
    ["https://localhost:9200"],                         # HTTPS connection
    basic_auth=("elastic", "a7AUn2fk5sluS3so8q8f"),     # <-- your tested password
    verify_certs=False                                  # OK for local dev/self-signed certs
)
INDEX_NAME = "siemtrix-logs"

# ---------------- Categories ----------------
CATEGORIES = {
    "Entertainment": ["netflix", "youtube", "spotify", "primevideo", "hulu"],
    "Social Media": ["facebook", "twitter", "instagram", "tiktok", "snapchat"],
    "News": ["cnn", "bbc", "nytimes", "reuters", "news"],
    "Work": ["slack", "github", "gitlab", "zoom", "microsoft teams", "jira", "confluence"],
    "Education": ["khanacademy", "coursera", "edx", "udemy", "academia", "tryhackme"],
    "Shopping": ["amazon", "ebay", "flipkart", "etsy", "walmart"],
    "Gaming": ["twitch", "steam", "epicgames", "roblox", "riotgames"],
    "Finance": ["paypal", "bank", "finance", "trading", "investment"],
    "Adult": ["porn", "xxx", "sex", "adult", "nsfw"],
    "Other": []
}

PRODUCTIVE_CATEGORIES = {"Work", "Education"}
DISTRACTIVE_CATEGORIES = {"Entertainment", "Social Media", "Shopping", "Gaming", "Adult"}
NEUTRAL_CATEGORIES = {"News", "Finance", "Other"}

# ---- Threat & Severity rules ----
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

SEVERITY_KEYWORDS = {
    "Critical": [
        "ransomware", "data exfiltration", "rootkit", "domain admin compromise",
        "privilege escalation success", "encryption in progress",
        "c2 communication", "command and control", "wiper", "supply chain compromise"
    ],
    "High": [
        "malware detected", "trojan", "botnet", "keylogger", "backdoor",
        "sql injection", "xss", "remote code execution", "rce", "lateral movement",
        "brute force success", "multiple failed logins", "payload delivered",
        "phishing credentials posted", "ddos", "dos attack", "exploitation"
    ],
    "Medium": [
        "failed login", "suspicious", "anomalous", "port scan", "scan detected",
        "phishing", "blocked", "policy violation", "vpn anomaly", "geo anomaly",
        "file quarantine", "malicious url"
    ],
    "Low": [
        "warning", "adware", "pua", "unwanted", "spam", "info", "debug",
        "blocked by policy"
    ]
}

THREAT_TYPES = {
    "ransomware": ["ransomware", "encryption demanded", "files encrypted"],
    "malware": ["malware", "virus", "payload", "infected", "quarantined"],
    "trojan": ["trojan", "backdoor", "remote access trojan", "rat"],
    "worm": ["worm", "self-replicating"],
    "spyware": ["spyware", "keylogger", "credential theft"],
    "adware": ["adware", "pua", "unwanted"],
    "phishing": ["phishing", "credential harvest", "fake login", "spoofed"],
    "brute-force": ["brute force", "multiple failed login", "password spray"],
    "sql-injection": ["sql injection", "sqli"],
    "xss": ["xss", "cross site scripting"],
    "dos": ["ddos", "dos", "denial of service"],
    "c2": ["c2", "command and control", "beacon"],
}

IOC_PATTERNS = [
    r"(?:\d{1,3}\.){3}\d{1,3}",                  # IP addresses
    r"[0-9a-f]{32,64}",                          # hashes md5/sha1/sha256 length-ish
    r"(?:http|https)://[^\s]+",                  # urls
    r"[a-z0-9\.\-]+\.[a-z]{2,}"                  # domains
]

def categorize_log(message: str) -> str:
    m = message.lower()
    for category, keywords in CATEGORIES.items():
        if any(k in m for k in keywords):
            return category
    return "Other"

def classify_productivity(category: str) -> str:
    if category in PRODUCTIVE_CATEGORIES:
        return "Productive"
    if category in DISTRACTIVE_CATEGORIES:
        return "Distractive"
    return "Neutral"

def detect_threat_type(message: str) -> str:
    m = message.lower()
    for ttype, keys in THREAT_TYPES.items():
        if any(k in m for k in keys):
            return ttype
    return "none"

def score_severity(log_level: str, message: str, category: str) -> str:
    """
    Choose the highest matching severity by keyword; escalate
    on signal like log level ERROR/CRITICAL and obvious IOC presence.
    """
    m = message.lower()
    chosen = "Low"

    # keyword-based
    for level in SEVERITY_ORDER[::-1]:  # start from Critical downwards
        if any(k in m for k in SEVERITY_KEYWORDS[level]):
            chosen = level
            break

    # escalate if we see IOCs (IPs, URLs, hashes, domains)
    if any(re.search(p, m) for p in IOC_PATTERNS):
        chosen = max(chosen, "Medium", key=lambda s: SEVERITY_ORDER.index(s))

    # log level based hints
    lvl = (log_level or "").upper()
    if lvl in ("CRITICAL", "FATAL"):
        chosen = "Critical"
    elif lvl == "ERROR":
        chosen = max(chosen, "High", key=lambda s: SEVERITY_ORDER.index(s))
    elif lvl == "WARN":
        chosen = max(chosen, "Medium", key=lambda s: SEVERITY_ORDER.index(s))

    # productivity context: distractive with policy violation can be Medium
    if category in DISTRACTIVE_CATEGORIES and ("policy" in m or "blocked" in m):
        chosen = max(chosen, "Medium", key=lambda s: SEVERITY_ORDER.index(s))

    return chosen

def utcnow():
    # ensure timezone-aware ISO for ES
    return datetime.now(timezone.utc)

# ---------------- Routes ----------------
@app.route("/")
def home():
    return "✅ SIEM Server (Elasticsearch-enabled) is running."

@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    log_message = data.get("log", "")
    log_level = data.get("level", "INFO")

    category = categorize_log(log_message)
    productivity = classify_productivity(category)
    threat_type = detect_threat_type(log_message)
    severity = score_severity(log_level, log_message, category)

    log_entry = {
        "level": log_level,
        "time": utcnow(),                   # ES will store as date
        "log": log_message,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "category": category,
        "productivity": productivity,       # NEW
        "threat_type": threat_type,         # NEW
        "severity": severity                # NEW
    }

    # Local logging
    app.logger.info(
        f"log: {log_entry['log']}\n"
        f"ip: {log_entry['ip']}\n"
        f"user_agent: {log_entry['user_agent']}\n"
        f"category: {log_entry['category']}\n"
        f"productivity: {log_entry['productivity']}\n"
        f"threat_type: {log_entry['threat_type']}\n"
        f"severity: {log_entry['severity']}"
    )

    # Elasticsearch logging (safe)
    try:
        es.index(index=INDEX_NAME, document=log_entry)
        app.logger.info("✅ Log successfully sent to Elasticsearch")
    except Exception as e:
        app.logger.error(f"⚠️ Failed to write to Elasticsearch: {e}")

    return jsonify({"status": "Log received", "analysis": {
        "category": category,
        "productivity": productivity,
        "threat_type": threat_type,
        "severity": severity
    }}), 200

# --------- Stats: summary JSON ----------
@app.route("/stats/summary")
def stats_summary():
    """
    Returns counts for Productive/Distractive/Neutral, top categories,
    severity distribution and threat types for the last N hours.
    """
    hours = int(request.args.get("hours", 24))
    gte = f"now-{hours}h"

    body = {
        "query": {"range": {"time": {"gte": gte}}},
        "size": 0,
        "aggs": {
            "by_productivity": {"terms": {"field": "productivity.keyword", "size": 10}},
            "by_category": {"terms": {"field": "category.keyword", "size": 20}},
            "by_severity": {"terms": {"field": "severity.keyword", "size": 10}},
            "by_threat": {"terms": {"field": "threat_type.keyword", "size": 20}}
        }
    }
    try:
        res = es.search(index=INDEX_NAME, body=body)
        def buckets_to_dict(b):
            return {x["key"]: x["doc_count"] for x in b["buckets"]}
        out = {
            "total": res["hits"]["total"]["value"] if "hits" in res and "total" in res["hits"] else 0,
            "productivity": buckets_to_dict(res["aggregations"]["by_productivity"]),
            "categories": buckets_to_dict(res["aggregations"]["by_category"]),
            "severity": buckets_to_dict(res["aggregations"]["by_severity"]),
            "threat_types": buckets_to_dict(res["aggregations"]["by_threat"]),
            "window_hours": hours
        }
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --------- Chart: Productivity Pie (PNG) ----------
@app.route("/charts/productivity.png")
def productivity_pie_chart():
    """
    Returns a PNG pie chart of Productive vs Distractive vs Neutral for last N hours.
    """
    hours = int(request.args.get("hours", 24))
    gte = f"now-{hours}h"

    body = {
        "query": {"range": {"time": {"gte": gte}}},
        "size": 0,
        "aggs": {
            "by_productivity": {"terms": {"field": "productivity.keyword", "size": 10}}
        }
    }

    try:
        res = es.search(index=INDEX_NAME, body=body)
        buckets = res["aggregations"]["by_productivity"]["buckets"]
        labels = [b["key"] for b in buckets]
        sizes = [b["doc_count"] for b in buckets]

        # handle empty data
        if not sizes or sum(sizes) == 0:
            # draw an empty chart with label
            fig = plt.figure(figsize=(5, 5))
            plt.text(0.5, 0.5, "No data", ha="center", va="center")
        else:
            fig = plt.figure(figsize=(5, 5))
            plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
            plt.title(f"Productivity (last {hours}h)")

        buf = io.BytesIO()
        plt.tight_layout()
        fig.savefig(buf, format="png", dpi=120)
        plt.close(fig)
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- Main ----------------
if __name__ == "__main__":
    print("Log file path:", log_file_path.resolve())
    if not os.access(log_file_path, os.W_OK):
        print("⚠️ Warning: server.log is not writable.")
    else:
        print("✅ server.log is writable.")
    app.run(debug=True)
