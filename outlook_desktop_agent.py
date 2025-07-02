import psutil
import json
import time
import os
import socket
import requests
from datetime import datetime

OUTLOOK_PROCESS_NAME = "olk.exe"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "outlook_desktop_log.json")
SERVER_URL = "http://127.0.0.1:5000/log"

def is_outlook_running():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == OUTLOOK_PROCESS_NAME:
            return True
    return False

def write_log(message):
    os.makedirs(LOG_DIR, exist_ok=True)
    log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
        "level": "INFO",
        "log": message,
        "ip": socket.gethostbyname(socket.gethostname()),
        "user_agent": "outlook-desktop-agent/1.0",
        "source": "outlook_desktop_monitor"
    }

    # Write to local file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    # Send to server
    try:
        requests.post(SERVER_URL, json=log_entry)
    except Exception as e:
        print(f"Failed to send log to server: {e}")

def main():
    last_state = None
    while True:
        current_state = is_outlook_running()
        if current_state != last_state:
            status = "Outlook opened" if current_state else "Outlook closed"
            print(status)
            write_log(status)
            last_state = current_state
        time.sleep(5)

if __name__ == "__main__":
    main()
