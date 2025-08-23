from flask import Flask, request, jsonify
from flask_cors import CORS
from elasticsearch import Elasticsearch
from datetime import datetime
from pathlib import Path
import logging
import os

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
    ["https://localhost:9200"],                # HTTPS connection
    basic_auth=("elastic", "a7AUn2fk5sluS3so8q8f"),  # Replace with your tested password
    verify_certs=False                         # OK for local dev/self-signed certs
)
INDEX_NAME = "siemtrix-logs"

# ---------------- Categories ----------------
CATEGORIES = {
    "Entertainment": ["netflix", "youtube", "spotify", "primevideo", "hulu"],
    "Social Media": ["facebook", "twitter", "instagram", "tiktok", "snapchat"],
    "News": ["cnn", "bbc", "nytimes", "reuters", "news"],
    "Work": ["slack", "github", "gitlab", "zoom", "microsoft teams"],
    "Education": ["khanacademy", "coursera", "edx", "udemy", "academia"],
    "Shopping": ["amazon", "ebay", "flipkart", "etsy", "walmart"],
    "Gaming": ["twitch", "steam", "epicgames", "roblox", "riotgames"],
    "Finance": ["paypal", "bank", "finance", "trading", "investment"],
    "Adult": ["porn", "xxx", "sex", "adult", "nsfw"],
    "Other": []
}

def categorize_log(message: str) -> str:
    message = message.lower()
    for category, keywords in CATEGORIES.items():
        if any(keyword in message for keyword in keywords):
            return category
    return "Other"

# ---------------- Routes ----------------
@app.route("/")
def home():
    return "✅ SIEM Server (Elasticsearch-enabled) is running."

@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    log_message = data.get("log", "")
    log_level = data.get("level", "INFO")
    log_entry = {
        "level": log_level,
        "time": datetime.utcnow(),
        "log": log_message,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "category": categorize_log(log_message)
    }

    # Local logging
    app.logger.info(
        f"log: {log_entry['log']}\n"
        f"ip: {log_entry['ip']}\n"
        f"user_agent: {log_entry['user_agent']}\n"
        f"category: {log_entry['category']}"
    )

    # Elasticsearch logging (safe)
    try:
        es.index(index=INDEX_NAME, document=log_entry)
        app.logger.info("✅ Log successfully sent to Elasticsearch")
    except Exception as e:
        app.logger.error(f"⚠️ Failed to write to Elasticsearch: {e}")

    return jsonify({"status": "Log received"}), 200

# ---------------- Main ----------------
if __name__ == "__main__":
    print("Log file path:", log_file_path.resolve())
    if not os.access(log_file_path, os.W_OK):
        print("⚠️ Warning: server.log is not writable.")
    else:
        print("✅ server.log is writable.")
    app.run(debug=True)
