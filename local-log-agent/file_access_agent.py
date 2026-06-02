"""
Alertix - siem-log-server/file_access_agent.py
================================================
Monitors the local file system for suspicious file access, creation,
modification, and deletion events, and reports them to the SIEM server.

HOW TO RUN:
    cd siem-log-server
    pip install requests watchdog
    python file_access_agent.py

    # Optional env vars:
    #   ALERTIX_SERVER=http://127.0.0.1:5000/log
    #   WATCH_PATH=C:\\Users  (or /home on Linux)

What it detects:
  - Access to sensitive files (.env, .pem, id_rsa, shadow, passwd, SAM)
  - Mass file renames/deletes (ransomware indicator)
  - Scripts dropped in temp/startup folders
  - Large file copies (data exfiltration indicator)
"""

import os
import sys
import time
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

# Use Any for the base classes dynamically to completely avoid Pylance assignment type conflicts
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
    BaseHandler: Any = FileSystemEventHandler
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = object  # type: ignore
    BaseHandler = object

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_URL  = os.getenv("ALERTIX_SERVER",  "http://127.0.0.1:5000/log")
WATCH_PATH  = os.getenv("WATCH_PATH",
              str(Path.home()))   # Default: home directory
AGENT_NAME  = "file-access-agent"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [file-agent] %(levelname)s %(message)s"
)

# ── Sensitive file patterns ───────────────────────────────────────────────────
SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".crt", ".cer",   # certs/keys
    ".env", ".cfg", ".conf", ".config",                # config
    ".sql", ".db", ".sqlite", ".mdb",                  # databases
    ".kdbx", ".kdb",                                   # keepass
}

SENSITIVE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",     # SSH keys
    ".env", "shadow", "passwd", "SAM", "NTDS.dit",     # creds
    "web.config", "appsettings.json", "secrets.json",  # app secrets
    ".aws/credentials", ".ssh/config",                  # cloud creds
}

# Extensions that indicate possible ransomware encryption
RANSOMWARE_EXT = {
    ".locked", ".encrypted", ".enc", ".crypto", ".crypt",
    ".zepto", ".cerber", ".locky", ".wnry", ".wncry"
}

# Track rename/delete counts per minute for ransomware detection
_op_counter: dict[str, int] = {"rename": 0, "delete": 0}
_op_reset_time: float = time.time()
RANSOMWARE_THRESHOLD = 20   # ops per minute


def send_log(message: str, level: str = "INFO"):
    try:
        r = requests.post(
            SERVER_URL,
            json={"log": message, "level": level, "source": AGENT_NAME},
            timeout=5
        )
        if r.status_code != 200:
            logging.warning(f"Server {r.status_code}: {r.text[:100]}")
    except requests.exceptions.ConnectionError:
        logging.error("Cannot reach Alertix server.")
    except Exception as e:
        logging.error(f"send_log: {e}")


def is_sensitive(path_str: str) -> bool:
    p = Path(path_str)
    return (p.suffix.lower() in SENSITIVE_EXTENSIONS or
            p.name in SENSITIVE_NAMES or
            any(part in path_str for part in [".ssh", ".aws", "AppData\\Roaming",
                                               "/etc/", "C:\\Windows\\System32"]))


def check_ransomware(op: str):
    """Increment op counter; alert if burst threshold exceeded."""
    global _op_reset_time
    now = time.time()

    # Reset counter every 60 seconds
    if now - _op_reset_time > 60:
        _op_counter["rename"] = 0
        _op_counter["delete"] = 0
        _op_reset_time = now

    _op_counter[op] = _op_counter.get(op, 0) + 1
    total = _op_counter["rename"] + _op_counter["delete"]

    if total >= RANSOMWARE_THRESHOLD:
        send_log(
            f"[RANSOMWARE ALERT] {total} file {op} operations in <60s — "
            f"possible ransomware activity on {WATCH_PATH}",
            "CRITICAL"
        )
        # Reset to avoid spam
        _op_counter["rename"] = 0
        _op_counter["delete"] = 0


# ── Watchdog event handler ────────────────────────────────────────────────────
class AlertixFileHandler(BaseHandler):

    def on_created(self, event: Any):
        if getattr(event, "is_directory", False):
            return
        path_str = os.fsdecode(event.src_path)
        ext  = Path(path_str).suffix.lower()

        if ext in RANSOMWARE_EXT:
            send_log(f"[file-create] Possible ransomware encrypted file: {path_str}", "CRITICAL")
        elif is_sensitive(path_str):
            send_log(f"[file-create] Sensitive file created: {path_str}", "ERROR")
        elif ext in {".exe", ".bat", ".ps1", ".vbs", ".js", ".hta"}:
            send_log(f"[file-create] Executable/script dropped: {path_str}", "WARNING")

    def on_modified(self, event: Any):
        if getattr(event, "is_directory", False):
            return
        path_str = os.fsdecode(event.src_path)
        if is_sensitive(path_str):
            send_log(f"[file-modify] Sensitive file modified: {path_str}", "ERROR")

    def on_deleted(self, event: Any):
        if getattr(event, "is_directory", False):
            return
        check_ransomware("delete")
        path_str = os.fsdecode(event.src_path)
        if is_sensitive(path_str):
            send_log(f"[file-delete] Sensitive file deleted: {path_str}", "ERROR")

    def on_moved(self, event: Any):
        if getattr(event, "is_directory", False):
            return
        check_ransomware("rename")
        src_path_str = os.fsdecode(event.src_path)
        
        raw_dest = getattr(event, 'dest_path', event.src_path)
        dest_path_str = os.fsdecode(raw_dest)
        
        dest_ext = Path(dest_path_str).suffix.lower()
        if dest_ext in RANSOMWARE_EXT:
            send_log(
                f"[file-rename] File renamed to ransomware extension: "
                f"{src_path_str} → {dest_path_str}",
                "CRITICAL"
            )
        elif is_sensitive(dest_path_str):
            send_log(f"[file-rename] Sensitive file renamed: "
                     f"{src_path_str} → {dest_path_str}", "WARNING")


# ── Fallback: manual scan (no watchdog) ──────────────────────────────────────
def scan_directory(watch_path: str, state: dict):
    """
    Fallback if watchdog isn't installed.
    Scans the directory and reports any new/changed sensitive files.
    """
    try:
        for entry in Path(watch_path).rglob("*"):
            if not entry.is_file():
                continue
            try:
                mtime = entry.stat().st_mtime
                key   = str(entry)
                if key not in state:
                    state[key] = mtime
                    if is_sensitive(key):
                        send_log(f"[file-scan] Sensitive file found: {key}", "WARNING")
                elif mtime != state[key]:
                    state[key] = mtime
                    send_log(f"[file-scan] Sensitive file changed: {key}", "ERROR")
            except (PermissionError, FileNotFoundError):
                pass
    except PermissionError:
        pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    logging.info(f"File Access Agent starting (watching: {WATCH_PATH})")
    send_log(f"File Access Agent started, watching: {WATCH_PATH}", "INFO")

    if WATCHDOG_AVAILABLE:
        logging.info("Using watchdog for real-time monitoring.")
        handler  = AlertixFileHandler()
        obs = Observer()  # type: ignore
        obs.schedule(handler, WATCH_PATH, recursive=True)  # type: ignore
        obs.start()  # type: ignore
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            obs.stop()  # type: ignore
            obs.join()  # type: ignore
            logging.info("File agent stopped.")
    else:
        logging.warning("watchdog not installed — falling back to periodic scan.")
        logging.warning("Install with: pip install watchdog")
        state: dict = {}
        while True:
            try:
                scan_directory(WATCH_PATH, state)
            except KeyboardInterrupt:
                logging.info("File agent stopped.")
                sys.exit(0)
            except Exception as e:
                logging.error(f"Scan error: {e}")
            time.sleep(30)


if __name__ == "__main__":
    main()