from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB using URI from .env
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)

# Connect to the correct DB and collection
db = client["logs_database"]
server_logs_collection = db["server_logs"]

def add_log(username, email):
    if not username or not email:
        return {"error": "Missing username or email"}, 400

    log = {
        "username": username,
        "email": email,
        "source": "user_entry",
        "level": "INFO",
        "timestamp": datetime.utcnow()
    }
    server_logs_collection.insert_one(log)
    return {"message": "Log added to server_logs"}, 201
