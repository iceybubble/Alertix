import os
import json
import socket
import requests
import subprocess
from datetime import datetime

LOG_FILE = "logs/policy_log.json"
SERVER_URL = "http://127.0.0.1:5000/log"  # Your server endpoint

os.makedirs("logs", exist_ok=True)

def get_firewall_status():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error fetching firewall status: {e}"

def get_uac_status():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        )
        value, _ = winreg.QueryValueEx(key, "EnableLUA")
        winreg.CloseKey(key)
        return "Enabled" if value == 1 else "Disabled"
    except Exception as e:
        return f"Error fetching UAC status: {e}"

def create_log_entry(message):
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
        "level": "INFO",
        "log": message,
        "ip": socket.gethostbyname(socket.gethostname()),
        "user_agent": "policy-agent/1.0",
        "source": "policy_agent"
    }

def write_log(entries):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        for entry in entries:
            json.dump(entry, f)
            f.write("\n")

def send_to_server(entries):
    for entry in entries:
        try:
            response = requests.post(SERVER_URL, json=entry)
            if response.status_code != 200:
                print(f"Failed to send log: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Failed to send log: {e}")

def main():
    entries = []

    firewall_status = get_firewall_status()
    entries.append(create_log_entry(f"Firewall status:\n{firewall_status}"))

    uac_status = get_uac_status()
    entries.append(create_log_entry(f"UAC is {uac_status}"))

    write_log(entries)
    send_to_server(entries)

if __name__ == "__main__":
    main()
