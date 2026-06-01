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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ---- chart backend ----
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---- Flask Setup ----
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost:5000"], supports_credentials=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecret")

# ---- Log Directory Setup ----
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(parents=True, exist_ok=True)
log_file_path = log_dir / "server.log"

# ---- Custom Logging Handler ----
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

app.logger.info(" Starting Alertix SIEM Server")
app.logger.info(f" Log file path: {log_file_path.resolve()}")

# ---- Elasticsearch Setup ----
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")

es = None
try:
    es = Elasticsearch(
        [f"http://{ES_HOST}:{ES_PORT}"],
        verify_certs=False
    )
    es_info = es.info()
    app.logger.info(f" Connected to Elasticsearch: {es_info['version']['number']}")
except Exception as e:
    app.logger.error(f" Failed to connect to Elasticsearch: {e}")

INDEX_NAME = "alertix-logs"

# ---- MongoDB Setup ----
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB_NAME", "alertix_db")

mongo_client = None
mongo_logs = None

try:
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client[MONGO_DB]
    mongo_logs = mongo_db["activity_logs"]

    mongo_client.admin.command('ping')
    app.logger.info(f" Connected to MongoDB: {MONGO_DB}")
except Exception as e:
    app.logger.error(f" Failed to connect to MongoDB: {e}")

# ---- Categories ----
CATEGORIES = {
    "Entertainment": ["netflix", "youtube", "spotify", "primevideo", "hulu", "twitch"],
    "Social Media": ["facebook", "twitter", "instagram", "tiktok", "snapchat", "reddit", "linkedin"],
    "News": ["cnn", "bbc", "nytimes", "reuters", "news"],
    "Work": ["slack", "github", "gitlab", "zoom", "microsoft teams", "jira", "confluence", "gmail", "outlook"],
    "Education": ["khanacademy", "coursera", "edx", "udemy", "academia", "tryhackme"],
    "Shopping": ["amazon", "ebay", "flipkart", "etsy", "walmart"],
    "Gaming": ["steam", "epicgames", "roblox", "riotgames"],
    "Finance": ["paypal", "bank", "finance", "trading", "investment"],
    "Adult": ["porn", "xxx", "sex", "adult", "nsfw"],
    "Other": []
}

PRODUCTIVE_CATEGORIES = {"Work", "Education"}
DISTRACTIVE_CATEGORIES = {"Entertainment", "Social Media", "Shopping", "Gaming", "Adult"}
NEUTRAL_CATEGORIES = {"News", "Finance", "Other"}

# ---- Severity & Threats ----
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]

SEVERITY_KEYWORDS = {
    "Critical": ["ransomware", "data exfiltration", "rootkit", "privilege escalation", "c2 communication"],
    "High": ["malware", "trojan", "botnet", "keylogger", "backdoor", "sql injection", "xss", "rce"],
    "Medium": ["failed login", "suspicious", "anomalous", "port scan", "phishing"],
    "Low": ["warning", "adware", "spam"]
}

THREAT_TYPES = {
    "ransomware": ["ransomware", "encryption"],
    "malware": ["malware", "virus"],
    "trojan": ["trojan", "backdoor"],
    "phishing": ["phishing"],
    "dos": ["ddos"]
}

IOC_PATTERNS = [
    r"(?:\d{1,3}\.){3}\d{1,3}",
    r"[0-9a-f]{32,64}",
    r"(?:http|https)://[^\s]+"
]

# ---- Helper Functions ----
def categorize_log(message):
    m = message.lower()
    for category, keywords in CATEGORIES.items():
        if any(k in m for k in keywords):
            return category
    return "Other"

def classify_productivity(category):
    if category in PRODUCTIVE_CATEGORIES:
        return "Productive"
    if category in DISTRACTIVE_CATEGORIES:
        return "Distractive"
    return "Neutral"

def detect_threat_type(message):
    m = message.lower()
    for ttype, keys in THREAT_TYPES.items():
        if any(k in m for k in keys):
            return ttype
    return "none"

def score_severity(log_level, message, category):
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
        idx = SEVERITY_ORDER.index(chosen)
        if idx < SEVERITY_ORDER.index("High"):
            chosen = "High"

    return chosen

def utcnow():
    return datetime.now(timezone.utc)

# ============ ROUTES ============

@app.route("/")
def home():
    return jsonify({
        "status": " Alertix SIEM Server running",
        "elasticsearch": " Connected" if es is not None else " Not Connected",
        "mongodb": " Connected" if mongo_client is not None else " Not Connected"
    })

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json(silent=True) or {}
    log_message = data.get("log", "")
    log_level = data.get("level", "INFO")
    source = data.get("source", "unknown")

    category = categorize_log(log_message)
    productivity = classify_productivity(category)
    threat_type = detect_threat_type(log_message)
    severity = score_severity(log_level, log_message, category)

    log_entry = {
        "timestamp": utcnow(),
        "source": source,
        "log": log_message,
        "level": log_level,
        "ip": request.remote_addr,
        "category": category,
        "productivity": productivity,
        "threat_type": threat_type,
        "severity": severity
    }

    if mongo_logs is not None:
        try:
            mongo_logs.insert_one(log_entry)
        except Exception as e:
            app.logger.error(f"MongoDB error: {e}")

    if es is not None:
        try:
            es.index(index=INDEX_NAME, document=log_entry)
        except Exception as e:
            app.logger.error(f"ES error: {e}")

    return jsonify({
        "status": "logged",
        "analysis": {"category": category, "productivity": productivity, "severity": severity}
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
                "by_severity":     {"terms": {"field": "severity.keyword"}}
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
            log["_id"] = str(log["_id"])
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
        labels = [b["key"] for b in buckets]
        sizes = [b["doc_count"] for b in buckets]

        fig = plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%")
        plt.title("Productivity")

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