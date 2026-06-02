from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from elasticsearch import Elasticsearch
from pymongo import MongoClient
from datetime import datetime, timezone
from pathlib import Path
import logging
import os
import io
import re
import requests
from dotenv import load_dotenv

load_dotenv()

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# Flask

app = Flask(__name__)
CORS(app,
     origins=["http://localhost:3000", "http://localhost:5000", "chrome-extension://*"],
     supports_credentials=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecret")


# Logging  (root logger → console + file)

BASE_DIR     = Path(__file__).parent
LOG_DIR      = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE     = LOG_DIR / "server.log"

class FlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

_fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(_fmt)

_fh = FlushFileHandler(str(LOG_FILE), encoding="utf-8")
_fh.setLevel(logging.INFO)
_fh.setFormatter(_fmt)

root = logging.getLogger()
root.setLevel(logging.INFO)
root.handlers.clear()
root.addHandler(_ch)
root.addHandler(_fh)

# suppress noisy libs
for _lib in ("elasticsearch", "urllib3", "werkzeug"):
    logging.getLogger(_lib).setLevel(logging.WARNING)

logging.info("Starting Alertix SIEM Server")
logging.info(f"Log file: {LOG_FILE.resolve()}")


# Elasticsearch

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "127.0.0.1")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")

es = None
try:
    es = Elasticsearch([f"http://{ES_HOST}:{ES_PORT}"], verify_certs=False)
    logging.info(f"Connected to Elasticsearch: {es.info()['version']['number']}")
except Exception as e:
    logging.error(f"Elasticsearch connection failed: {e}")

INDEX_NAME = "alertix-logs"


# MongoDB  (explicit IPv4 to avoid ::1 issue)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/")
MONGO_DB  = os.getenv("MONGO_DB_NAME", "alertix_db")

mongo_client = None
mongo_logs   = None

try:
    mongo_client = MongoClient(MONGO_URI,
                               serverSelectionTimeoutMS=5000,
                               connectTimeoutMS=5000,
                               socketTimeoutMS=5000)
    mongo_db   = mongo_client[MONGO_DB]
    mongo_logs = mongo_db["activity_logs"]
    mongo_client.admin.command("ping")
    logging.info(f"Connected to MongoDB: {MONGO_DB}")
except Exception as e:
    logging.error(f"MongoDB connection failed: {e}")
    mongo_client = None
    mongo_logs   = None


# Categories  (keyword-based fast path)

CATEGORIES: dict[str, list[str]] = {
    "Entertainment":  ["netflix", "youtube", "spotify", "primevideo", "hulu", "twitch",
                       "disneyplus", "hbomax", "peacock", "appletv", "crunchyroll",
                       "vimeo", "dailymotion", "soundcloud", "pandora", "deezer",
                       "tidal", "napster", "iheartradio", "tunein"],
    "Social Media":   ["facebook", "twitter", "instagram", "tiktok", "snapchat",
                       "reddit", "linkedin", "pinterest", "tumblr", "whatsapp",
                       "telegram", "discord", "mastodon", "threads", "bluesky",
                       "clubhouse", "signal", "line", "wechat", "viber"],
    "News":           ["cnn", "bbc", "nytimes", "reuters", "news", "theguardian",
                       "washingtonpost", "apnews", "npr", "bloomberg", "forbes",
                       "techcrunch", "theverge", "arstechnica", "wired", "engadget",
                       "zdnet", "techradar", "tomsguide", "pcmag"],
    "Work":           ["slack", "github", "gitlab", "zoom", "microsoft", "teams",
                       "jira", "confluence", "gmail", "outlook", "notion", "trello",
                       "asana", "monday", "clickup", "basecamp", "freshdesk",
                       "zendesk", "salesforce", "hubspot", "dropbox", "box",
                       "sharepoint", "onedrive", "googledrive", "docs.google",
                       "sheets.google", "slides.google", "figma", "miro", "linear"],
    "Education":      ["khanacademy", "coursera", "edx", "udemy", "academia",
                       "tryhackme", "hackthebox", "leetcode", "hackerrank",
                       "codeforces", "pluralsight", "skillshare", "lynda",
                       "duolingo", "brilliant", "wikipedia", "stackoverflow",
                       "medium", "dev.to", "freecodecamp", "theodinproject",
                       "mit.edu", "harvard.edu", "stanford.edu", "w3schools",
                       "mdn", "developer.mozilla"],
    "Shopping":       ["amazon", "ebay", "flipkart", "etsy", "walmart", "alibaba",
                       "aliexpress", "target", "bestbuy", "newegg", "costco",
                       "wayfair", "chewy", "wish", "shein", "zara", "hm.com",
                       "shopify", "rakuten", "overstock"],
    "Gaming":         ["steam", "epicgames", "roblox", "riotgames", "battlenet",
                       "origin", "gog", "itch.io", "gamepass", "xbox", "playstation",
                       "nintendo", "twitch", "overwolf", "curse", "nexusmods",
                       "miniclip", "kongregate", "poki", "crazygames"],
    "Finance":        ["paypal", "bank", "finance", "trading", "investment",
                       "robinhood", "coinbase", "binance", "kraken", "etrade",
                       "fidelity", "vanguard", "schwab", "stripe", "wise",
                       "revolut", "monzo", "sofi", "chime", "mint", "quicken",
                       "turbotax", "hrblock", "chase", "wellsfargo", "bofa",
                       "capitalone", "citibank", "barclays", "hsbc"],
    "Adult":          ["porn", "xxx", "sex", "adult", "nsfw", "onlyfans",
                       "playboy", "penthouse", "brazzers", "pornhub", "xvideos",
                       "xnxx", "redtube", "youporn", "xhamster"],
    "Security":       ["virustotal", "shodan", "exploit-db", "cve", "nvd.nist",
                       "mitre", "owasp", "sans", "securityfocus", "packetstorm",
                       "rapid7", "metasploit", "kali", "nmap", "wireshark",
                       "burpsuite", "maltego", "splunk", "ibm qradar", "paloalto",
                       "crowdstrike", "sentinelone", "cylance", "carbonblack"],
    "Cloud":          ["aws", "azure", "gcp", "digitalocean", "heroku", "vercel",
                       "netlify", "cloudflare", "linode", "vultr", "render",
                       "railway", "fly.io", "supabase", "firebase"],
    "Other":          []
}

PRODUCTIVE_CATEGORIES  = {"Work", "Education", "Security", "Cloud"}
DISTRACTIVE_CATEGORIES = {"Entertainment", "Social Media", "Shopping", "Gaming", "Adult"}
NEUTRAL_CATEGORIES     = {"News", "Finance", "Other"}

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "Critical": ["ransomware", "data exfiltration", "rootkit", "privilege escalation",
                 "c2 communication", "command and control", "zero-day", "0day",
                 "reverse shell", "bind shell", "lateral movement", "credential dump"],
    "High":     ["malware", "trojan", "botnet", "keylogger", "backdoor",
                 "sql injection", "xss", "rce", "remote code execution",
                 "buffer overflow", "path traversal", "lfi", "rfi", "ssrf",
                 "idor", "broken auth", "deserialization", "log4j", "shellshock"],
    "Medium":   ["failed login", "suspicious", "anomalous", "port scan", "phishing",
                 "brute force", "credential stuffing", "unusual access", "after hours",
                 "vpn", "tor", "proxy", "unauthorized", "policy violation",
                 "adult content", "data leak"],
    "Low":      ["warning", "adware", "spam", "cookie", "tracker",
                 "slow response", "high cpu", "high memory", "disk full"]
}

THREAT_TYPES = {
    "ransomware":        ["ransomware", "encrypt", "decrypt", "ransom"],
    "malware":           ["malware", "virus", "worm", "spyware", "adware"],
    "trojan":            ["trojan", "backdoor", "rat ", "remote access"],
    "phishing":          ["phishing", "credential harvest", "fake login"],
    "dos":               ["ddos", "dos attack", "flood", "slowloris"],
    "data_exfiltration": ["exfil", "data theft", "exfiltration", "upload sensitive"],
    "insider_threat":    ["unauthorized copy", "usb transfer", "after hours", "policy violation"],
    "none":              []
}

IOC_PATTERNS = [
    r"(?:\d{1,3}\.){3}\d{1,3}",          # IPv4
    r"[0-9a-f]{32,64}",                    # MD5/SHA hash
    r"(?:http|https)://[^\s]+",            # URL
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # email
]


def categorize_log(message: str) -> str:
    """Keyword-based categorization."""
    m = message.lower()
    for category, keywords in CATEGORIES.items():
        if keywords and any(k in m for k in keywords):
            return category
    # Nothing matched — fallback
    return "Other"


def classify_productivity(category: str) -> str:
    if category in PRODUCTIVE_CATEGORIES:  return "Productive"
    if category in DISTRACTIVE_CATEGORIES: return "Distractive"
    return "Neutral"


def detect_threat_type(message: str) -> str:
    m = message.lower()
    for ttype, keys in THREAT_TYPES.items():
        if keys and any(k in m for k in keys):
            return ttype
    return "none"


def score_severity(log_level: str, message: str, category: str) -> str:
    m = message.lower()
    chosen = "Low"
    for level in SEVERITY_ORDER[::-1]:
        if any(k in m for k in SEVERITY_KEYWORDS[level]):
            chosen = level
            break
    if any(re.search(p, m) for p in IOC_PATTERNS):
        idx = SEVERITY_ORDER.index(chosen)
        if idx < SEVERITY_ORDER.index("Medium"):
            chosen = "Medium"
    lvl = (log_level or "").upper()
    if lvl in ("CRITICAL", "FATAL"):
        chosen = "Critical"
    elif lvl == "ERROR":
        if SEVERITY_ORDER.index(chosen) < SEVERITY_ORDER.index("High"):
            chosen = "High"
    # Adult content always at least High
    if category == "Adult" and SEVERITY_ORDER.index(chosen) < SEVERITY_ORDER.index("High"):
        chosen = "High"
    return chosen


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Routes

@app.route("/")
def home():
    return jsonify({
        "status":        "Alertix SIEM Server running",
        "elasticsearch": "Connected" if es is not None else "Not Connected",
        "mongodb":       "Connected" if mongo_client is not None else "Not Connected"
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


@app.route("/log", methods=["POST"])
def receive_log():
    data        = request.get_json(silent=True) or {}
    log_message = data.get("log", "")
    log_level   = data.get("level", "INFO")
    source      = data.get("source", "unknown")

    category     = categorize_log(log_message)
    productivity = classify_productivity(category)
    threat_type  = detect_threat_type(log_message)
    severity     = score_severity(log_level, log_message, category)
    now          = utcnow()

    # Write to server.log
    logging.info(
        f"[{source}] {severity} | {category} | {productivity} | {threat_type} | {log_message}"
    )

    # Separate dicts: MongoDB mutates by injecting _id (ObjectId) which
    # breaks Elasticsearch JSON serialization if we reuse the same dict.
    mongo_entry = {
        "timestamp": now,
        "source": source, "log": log_message, "level": log_level,
        "ip": request.remote_addr, "category": category,
        "productivity": productivity, "threat_type": threat_type, "severity": severity
    }
    es_entry = {
        "timestamp": now.isoformat(),   # ES needs ISO string
        "source": source, "log": log_message, "level": log_level,
        "ip": request.remote_addr, "category": category,
        "productivity": productivity, "threat_type": threat_type, "severity": severity
    }

    if mongo_logs is not None:
        try:
            mongo_logs.insert_one(mongo_entry)
        except Exception as e:
            logging.error(f"MongoDB error: {e}")

    if es is not None:
        try:
            es.index(index=INDEX_NAME, document=es_entry)
        except Exception as e:
            logging.error(f"ES error: {e}")

    return jsonify({
        "status": "logged",
        "analysis": {"category": category, "productivity": productivity,
                     "severity": severity, "threat_type": threat_type}
    })


@app.route("/stats/summary")
def stats_summary():
    if es is None:
        return jsonify({"error": "ES not connected"}), 503
    hours = int(request.args.get("hours", 24))
    try:
        res = es.search(
            index=INDEX_NAME,
            query={"range": {"timestamp": {"gte": f"now-{hours}h"}}},
            size=0,
            aggs={
                "by_productivity": {"terms": {"field": "productivity.keyword"}},
                "by_category":     {"terms": {"field": "category.keyword"}},
                "by_severity":     {"terms": {"field": "severity.keyword"}},
                "by_threat":       {"terms": {"field": "threat_type.keyword"}},
                "by_source":       {"terms": {"field": "source.keyword"}}
            }
        )
        return jsonify({"data": res["aggregations"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stats/productivity")
def productivity_stats():
    if mongo_logs is None:
        return jsonify({"error": "MongoDB not connected"}), 503
    try:
        pipeline = [{"$group": {"_id": "$productivity", "count": {"$sum": 1}}}]
        stats = list(mongo_logs.aggregate(pipeline))
        return jsonify({s["_id"]: s["count"] for s in stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logs/recent")
def recent_logs():
    if mongo_logs is None:
        return jsonify({"error": "MongoDB not connected"}), 503
    try:
        logs = list(mongo_logs.find().sort("timestamp", -1).limit(20))
        for log in logs:
            log["_id"]       = str(log["_id"])
            log["timestamp"] = log["timestamp"].isoformat()
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/charts/productivity.png")
def productivity_pie():
    if es is None:
        return jsonify({"error": "ES not connected"}), 503
    try:
        res = es.search(
            index=INDEX_NAME,
            query={"range": {"timestamp": {"gte": "now-24h"}}},
            size=0,
            aggs={"by_productivity": {"terms": {"field": "productivity.keyword"}}}
        )
        buckets = res["aggregations"]["by_productivity"]["buckets"]
        labels  = [b["key"] for b in buckets]
        sizes   = [b["doc_count"] for b in buckets]

        colors = {"Productive": "#4CAF50", "Distractive": "#F44336", "Neutral": "#FFC107"}
        fig = plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%",
                colors=[colors.get(l, "#9E9E9E") for l in labels])
        plt.title("Productivity Breakdown (Last 24h)")

        buf = io.BytesIO()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("SERVER_PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)