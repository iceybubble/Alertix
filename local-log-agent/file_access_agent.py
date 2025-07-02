import os
import json
import requests
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MONITOR_PATH = os.path.expanduser("~")  # You can change this to any directory
SERVER_URL = "http://localhost:5000/log"

class FileAccessHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return

        log_message = f"{event.event_type.upper()} event on {event.src_path}"
        log_entry = {
            "level": "INFO",
            "log": log_message,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
            "source": "file_access_agent"
        }
        send_log_to_server(log_entry)

def send_log_to_server(log_entry):
    try:
        response = requests.post(SERVER_URL, json=log_entry)
        if response.status_code != 200:
            print("Failed to send log:", response.text)
    except Exception as e:
        print("Error sending log:", e)

def main():
    event_handler = FileAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_PATH, recursive=True)
    observer.start()
    print(f"Monitoring real-time file access in: {MONITOR_PATH}")

    try:
        while True:
            pass  # Keeps the script running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
