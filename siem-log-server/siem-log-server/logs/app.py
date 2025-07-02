from flask import Flask, redirect, url_for, session
from flask_pymongo import PyMongo
from flask_dance.contrib.google import make_google_blueprint, google
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "supersecret"  # Use a secure, random secret in production

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/test"
mongo = PyMongo(app)

# Google OAuth blueprint
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    redirect_url="/login/google/authorized",
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))

    # Fetch user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user_info = resp.json()
    email = user_info.get("email")

    # Store or update user in MongoDB
    mongo.db.users.update_one(
        {"email": email},
        {"$set": user_info},
        upsert=True
    )

    return f"Logged in as: {email}"

if __name__ == "__main__":
    app.run(debug=True)
