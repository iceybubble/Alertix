import win32evtlog
import json
import requests
import time
import os
from datetime import datetime

import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("[!] This script requires administrator privileges. Please run as Administrator.")
    sys.exit(1)


# Configuration
SERVER = 'localhost'
LOG_TYPE = 'Security'
SIEM_ENDPOINT = "http://localhost:5000/log"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "windows_logs.jsonl")
LAST_RECORD_FILE = os.path.join(LOG_DIR, "last_record.txt")

def get_last_record_number():
    if os.path.exists(LAST_RECORD_FILE):
        with open(LAST_RECORD_FILE, "r") as f:
            try:
                return int(f.read().strip())
            except:
                return 0
    return 0

def set_last_record_number(number):
    with open(LAST_RECORD_FILE, "w") as f:
        f.write(str(number))

def fetch_logs(since_record):
    hand = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
    logs = []
    max_record = since_record

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for ev_obj in events:
            if ev_obj.RecordNumber <= since_record:
                continue
            try:
                log_data = {
                    'event_id': ev_obj.EventID,
                    'source_name': ev_obj.SourceName,
                    'time_generated': str(ev_obj.TimeGenerated),
                    'event_type': ev_obj.EventType,
                    'event_category': ev_obj.EventCategory,
                    'computer_name': ev_obj.ComputerName,
                    'string_inserts': ev_obj.StringInserts,
                    'record_number': ev_obj.RecordNumber
                }
                logs.append(log_data)
                if ev_obj.RecordNumber > max_record:
                    max_record = ev_obj.RecordNumber
            except:
                pass
    return logs, max_record

def send_logs(logs):
    try:
        requests.get("http://localhost:5000", timeout=2)
        for log in logs:
            try:
                requests.post(SIEM_ENDPOINT, json=log, timeout=2)
            except:
                pass
    except:
        pass

def save_logs_to_file(logs):
    if not logs:
        return
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")

def main():
    print("[*] Starting Windows Log Agent")
    os.makedirs(LOG_DIR, exist_ok=True)
    time.sleep(5)  # Optional buffer for server start
    last_record = get_last_record_number()
    logs, new_record = fetch_logs(last_record)
    send_logs(logs)
    save_logs_to_file(logs)
    set_last_record_number(new_record)

if __name__ == "__main__":
    main()
