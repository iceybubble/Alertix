from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import os
import json
import time
import logging

# === Load Environment Variables ===
load_dotenv()

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "fallbacksupersecret")

# === MongoDB Setup ===
MONGO_URI = os.getenv("MONGO_URI")
if MONGO_URI:
    client = MongoClient(MONGO_URI)
    db = client["logs_database"]
    collection = db["server_logs"]
else:
    client = db = collection = None  # fallback

# === Logging Setup ===
os.makedirs("logs", exist_ok=True)
log_file_path = Path("logs/server.log")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Helper Functions ===

def categorize_log(message: str) -> str:
    if any(kw in message.lower() for kw in ["malware", "virus", "trojan", "phishing"]):
        return "Security"
    elif any(kw in message.lower() for kw in ["login", "authentication", "logout"]):
        return "Authentication"
    elif any(kw in message.lower() for kw in ["error", "failed", "exception"]):
        return "Error"
    else:
        return "General"

def determine_productivity(category: str) -> str:
    if category in ["Security", "Error"]:
        return "Unproductive"
    elif category == "Authentication":
        return "Neutral"
    else:
        return "Productive"

def detect_criticality_details(message: str):
    msg = message.lower()
    if "ransomware" in msg:
        return "High", "Critical", "Ransomware"
    elif "trojan" in msg:
        return "Medium", "Warning", "Trojan"
    elif "phishing" in msg:
        return "High", "Alert", "Phishing"
    elif "error" in msg or "fail" in msg:
        return "Low", "Info", None
    else:
        return "Low", "Info", None

def write_pretty_log(entry):
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        formatted = json.dumps(entry, indent=4)
        log_file.write(f"{formatted}\n{'-'*50}\n")

def log_to_mongodb(entry, retries=3, delay=1):
    if not collection:
        print("⚠️ MongoDB not configured. Skipping DB insert.")
        return
    for attempt in range(retries):
        try:
            collection.insert_one(entry)
            break
        except Exception as e:
            print(f"MongoDB write failed (attempt {attempt+1}): {e}")
            time.sleep(delay)

# === Routes ===

@app.route("/")
def index():
    return "✅ SIEM Log Server is running!"

@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    print("Received log:", data)  # Add this for debugging

    return jsonify({"status": "Log received"}), 200

    log_message = data.get("log", "")
    visited_url = data.get("url", "")

    category = categorize_log(log_message)
    productivity = determine_productivity(category)
    criticality, severity, malware_type = detect_criticality_details(log_message)

    log_entry = {
        "level": criticality,
        "severity": severity,
        "malware_type": malware_type,
        "productivity": productivity,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
        "log": log_message,
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "category": category,
        "category_type": productivity,
        "url": visited_url
    }

    write_pretty_log(log_entry)
    log_to_mongodb(log_entry)
    return jsonify({"status": "Log received"}), 200

@app.route("/routes")
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        url = urllib.parse.unquote(str(rule))
        output.append(f"{rule.endpoint}: {url} [{methods}]")
    return "<br>".join(sorted(output))

@app.errorhandler(404)
def page_not_found(e):
    return "404 Not Found: The requested page does not exist.", 404

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# === Run App ===
if __name__ == "__main__":
    logger.info("Log file path: %s", log_file_path.resolve())
    if not os.access(log_file_path, os.W_OK):
        logger.warning("server.log is not writable.")
    else:
        logger.info("server.log is writable.")
    app.run(host="0.0.0.0", port=5000)
