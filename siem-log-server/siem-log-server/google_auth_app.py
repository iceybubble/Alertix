from flask import Flask, redirect, request, session
import google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import os

app = Flask(__name__)
app.secret_key = "REPLACE_ME"

SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # For local testing

@app.route("/")
def home():
    if "credentials" not in session:
        return redirect("/login")
    
    creds = Credentials.from_authorized_user_info(session["credentials"])
    return "You are logged in with Google!"

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/callback"
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    session["flow"] = flow
    return redirect(auth_url)

@app.route("/callback")
def callback():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/callback"
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
