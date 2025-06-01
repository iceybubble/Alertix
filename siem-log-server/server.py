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

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "fallbacksupersecret")

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise EnvironmentError("MONGO_URI is not set in environment variables or .env file")

client = MongoClient(MONGO_URI)
db = client["logs_database"]
collection = db["server_logs"]

# Set up logging
os.makedirs("logs", exist_ok=True)
log_file_path = Path("logs/server.log")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keyword categories
CATEGORIES = {
    "Entertainment": [
        "netflix", "youtube", "spotify", "primevideo", "hulu", "jiohotstar", "appletv", "disneyplus", "spotify", "deezer", "pandora",
        "soundcloud", "vevo", "vimeo", "peacock", "starz", "crunchyroll", "bbc iplayer"
    ],
    "Social Media": [
        "facebook", "twitter", "instagram", "tiktok", "snapchat", "reddit", "wechat", "threads", "discord", "linkedin", "pinterest",
        "tumblr", "quora", "clubhouse", "telegram", "signal", "messenger", "line", "kakao", "viber", "wechat"
    ],
    "News": [
        "cnn", "bbc", "nytimes", "reuters", "news", "aljazeera", "foxnews", "theguardian", "washingtonpost", "buzzfeed", "npr",
        "huffpost", "cnbc", "forbes", "economist", "dw", "thehill"
    ],
    "Work": [
        "slack", "github", "gitlab", "zoom", "microsoft teams", "dropbox", "google calendar", "asana", "jira", "trello", "notion",
        "office365", "skype", "basecamp", "monday", "zapier", "confluence"
    ],
    "Education": [
        "khanacademy", "coursera", "edx", "udemy", "academia", "linkedin learning", "codecademy", "udacity", "pluralsight",
        "brilliant", "futurelearn", "skillshare", "sololearn", "mit ocw", "harvard online", "stanford online"
    ],
    "Shopping": [
        "amazon", "ebay", "flipkart", "etsy", "walmart", "myntra", "nykaa", "alibaba", "urbanic", "ajio", "target", "bestbuy",
        "shopify", "costco", "aldi", "asos", "zara", "sephora", "luxurybrands"
    ],
    "Gaming": [
        "twitch", "steam", "epicgames", "roblox", "riotgames", "xbox", "polygon", "origin", "gog", "battle.net", "playstation network",
        "nintendo", "garena", "miniclip", "kongregate", "newgrounds", "itch.io"
    ],
    "Finance": [
        "paypal", "bank", "finance", "trading", "investment", "cnbc", "forbes", "bajaj finance", "vanguard", "fidelity", "robinhood",
        "coinbase", "blockchain", "mint", "etrade", "td ameritrade", "schwab", "square", "stripe", "intuit"
    ],
    "Adult": [
        "porn", "xxx", "sex", "adult", "nsfw", "brazzers", "xvideos", "redtube", "pornhub", "onlyfans", "chaturbate"
    ],
    "Coding": [
        "leetcode", "hackerrank", "codeforces", "codechef", "atcoder", "topcoder", "geeksforgeeks", "codingninjas", "interviewbit",
        "hackerone", "exercism", "spoj", "projecteuler", "coderbyte", "edabit", "kaggle", "github", "gitlab", "bitbucket"
    ],
    "Health & Fitness": [
        "myfitnesspal", "fitbit", "strava", "nike training club", "headspace", "calm", "peloton", "mapmyrun", "sleep cycle"
    ],
    "Travel": [
        "airbnb", "booking", "expedia", "tripadvisor", "uber", "lyft", "skyscanner", "kayak", "trivago", "hotels.com"
    ],
    "Food & Drink": [
        "ubereats", "doordash", "zomato", "grubhub", "swiggy", "foodpanda", "yelp", "opentable"
    ],
    "Utilities": [
        "google drive", "dropbox", "onedrive", "lastpass", "1password", "evernote", "notion", "todoist", "calendar", "weather"
    ],
    "Other": []
}


# Malware detection keywords
MALWARE_KEYWORDS = {
    "trojan": ("Urgent Critical", "High", "Trojan"),
    "ransomware": ("Urgent Critical", "High", "Ransomware"),
    "spyware": ("High Critical", "Moderate", "Spyware"),
    "virus": ("Attention Needed", "Moderate", "Virus"),
    "malware": ("Low Critical", "Low", "Generic Malware")
}

# Helper functions
def categorize_log(message: str) -> str:
    message = message.lower()
    for category, keywords in CATEGORIES.items():
        if any(keyword in message for keyword in keywords):
            return category
    return "Other"

def detect_criticality_details(message: str):
    message = message.lower()
    for keyword, (criticality, severity, malware_type) in MALWARE_KEYWORDS.items():
        if keyword in message:
            return criticality, severity, malware_type
    return "Info", "None", "None"

def determine_productivity(category: str) -> str:
    if category in ["Work", "Education"]:
        return "Productive"
    elif category in ["Entertainment", "Social Media", "Gaming", "Shopping", "Adult"]:
        return "Distracting"
    else:
        return "Neutral"

def write_pretty_log(entry):
    try:
        with open(log_file_path, "a", encoding="utf-8") as f:
            for key, value in entry.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
    except Exception as e:
        logger.error("Failed to write to server.log: %s", e)

def save_failed_log_to_file(entry):
    try:
        with open("logs/failed_mongo_inserts.jsonl", "a", encoding="utf-8") as f:
            json.dump(entry, f)
            f.write("\n")
    except Exception as e:
        logger.error("Failed to save failed log: %s", e)

def log_to_mongodb(entry, retries=3, delay=1):
    try:
        entry["time"] = datetime.strptime(entry["time"], "%Y-%m-%d %H:%M:%S,%f")
    except Exception as e:
        logger.warning("Time parse error. Defaulting to UTC: %s", e)
        entry["time"] = datetime.utcnow()

    for attempt in range(1, retries + 1):
        try:
            collection.insert_one(entry)
            return
        except Exception as e:
            logger.error("MongoDB insert attempt %d failed: %s", attempt, e)
            if attempt < retries:
                time.sleep(delay)
            else:
                save_failed_log_to_file(entry)

# Routes
@app.route('/')
def index():
    return '✅ SIEM Log Server is running!'

@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

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

@app.route("/logs/recent", methods=["GET"])
def recent_logs():
    logs = list(collection.find().sort("time", -1).limit(10))
    for log in logs:
        log["_id"] = str(log["_id"])
    return jsonify(logs)

@app.route("/logs/view", methods=["GET"])
@app.route("/logs")
def show_logs():
    return render_template("logs.html")  # Ensure you have templates/logs.html

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

# Run the app
if __name__ == "__main__":
    logger.info("Log file path: %s", log_file_path.resolve())
    if not os.access(log_file_path, os.W_OK):
        logger.warning("server.log is not writable.")
    else:
        logger.info("server.log is writable.")
    app.run(host="0.0.0.0", port=5000)
