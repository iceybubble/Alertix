import time
import json
import socket
import psutil
import requests
from datetime import datetime
import os

LOG_FILE = "logs/network_log.json"
SERVER_URL = "http://127.0.0.1:5000/log"  # Your server endpoint

os.makedirs("logs", exist_ok=True)

def get_connection_info():
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.status == "ESTABLISHED":
            try:
                process_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
            except Exception:
                process_name = "Unknown"

            log_message = f"{process_name} connected to {conn.raddr.ip}:{conn.raddr.port}"

            entry = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
                "level": "INFO",
                "log": log_message,
                "ip": socket.gethostbyname(socket.gethostname()),
                "user_agent": "network-agent/1.0",
                "source": "network_agent"
            }
            connections.append(entry)
    return connections

def write_log(data):
    with open(LOG_FILE, "a") as f:
        for entry in data:
            json.dump(entry, f)
            f.write("\n")

def send_to_server(data):
    for entry in data:
        try:
            response = requests.post(SERVER_URL, json=entry)
            if response.status_code != 200:
                print(f"Failed to send log: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Failed to send log: {e}")

# This was missing:
def monitor():
    while True:
        logs = get_connection_info()
        if logs:
            write_log(logs)
            send_to_server(logs)
        time.sleep(10)  # Adjust the interval as needed

#  Entry point
if __name__ == "__main__":
    monitor()
