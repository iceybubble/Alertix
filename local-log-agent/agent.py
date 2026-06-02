"""
Alertix - local-log-agent/agent.py
=====================================
Monitors local system logs (Linux/macOS/Windows) and forwards events
to the Alertix SIEM server in real time.

HOW TO RUN:
    cd local-log-agent
    pip install requests psutil
    python agent.py

    # On Windows also install: pip install pywin32
    # Optional env vars:
    #   ALERTIX_SERVER=http://127.0.0.1:5000/log
    #   AGENT_POLL_SECS=5
"""

import os
import sys
import time
import platform
import logging
import requests
from pathlib import Path
from typing import Any

# Use TYPE_CHECKING or fallback imports to resolve Pylance 'missing module' warnings safely
try:
    import win32evtlog  # type: ignore
    import win32con     # type: ignore
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    win32evtlog: Any = object
    win32con: Any = object

SERVER_URL = os.getenv("ALERTIX_SERVER", "http://127.0.0.1:5000/log")
POLL_SECS  = int(os.getenv("AGENT_POLL_SECS", "5"))
AGENT_NAME = "local-log-agent"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [agent] %(levelname)s %(message)s"
)

OS = platform.system()   # "Windows" | "Linux" | "Darwin"


# ── Send helper 
def send_log(message: str, level: str = "INFO"):
    """POST one log entry to the Alertix SIEM server."""
    try:
        r = requests.post(
            SERVER_URL,
            json={"log": message, "level": level, "source": AGENT_NAME},
            timeout=5
        )
        if r.status_code != 200:
            logging.warning(f"Server returned {r.status_code}: {r.text[:100]}")
    except requests.exceptions.ConnectionError:
        logging.error("Cannot reach Alertix server. Is server.py running?")
    except Exception as e:
        logging.error(f"send_log error: {e}")


# ── File tail helper 
def tail_file(path: str, state: dict) -> list:
    """Return new lines added to a log file since last call."""
    lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(state.get(path, 0))
            new_lines = f.readlines()
            state[path] = f.tell()
        lines = [l.strip() for l in new_lines if l.strip()]
    except (FileNotFoundError, PermissionError):
        pass
    return lines


# ── Linux / macOS file-based monitoring
LINUX_LOGS = [
    "/var/log/auth.log",           # SSH logins, sudo, PAM
    "/var/log/syslog",             # General system
    "/var/log/kern.log",           # Kernel
    "/var/log/ufw.log",            # Firewall (Ubuntu)
    "/var/log/apache2/access.log", # Apache (if running)
    "/var/log/nginx/access.log",   # Nginx (if running)
    "/var/log/secure",             # RHEL/CentOS auth
    "/var/log/messages",           # RHEL/CentOS general
]

CRIT_HINTS = [
    "FAILED", "Invalid user", "authentication failure",
    "sudo:", "segfault", "kernel panic", "OOM killer",
    "permission denied", "unauthorized", "BREAK-IN ATTEMPT"
]
HIGH_HINTS = ["error", "denied", "refused", "blocked", "intrusion", "warning"]


def run_linux(state: dict):
    for path in LINUX_LOGS:
        for line in tail_file(path, state):
            u = line.upper()
            if any(h.upper() in u for h in CRIT_HINTS):
                lvl = "ERROR"
            elif any(h.upper() in u for h in HIGH_HINTS):
                lvl = "WARNING"
            else:
                lvl = "INFO"
            send_log(f"[{Path(path).name}] {line}", lvl)


# ── macOS unified log 
def run_macos(state: dict):
    import subprocess
    try:
        result = subprocess.run(
            ["log", "show", "--last", f"{POLL_SECS}s",
             "--predicate", "eventType == logEvent",
             "--style", "compact"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if line.strip():
                send_log(f"[macOS/log] {line.strip()}", "INFO")
    except Exception:
        run_linux(state)   # fallback to file tailing


# ── Windows Event Log 
def run_windows(state: dict):
    if not WIN32_AVAILABLE:
        logging.error("pywin32 missing. Run: pip install pywin32")
        return

    for channel in ["Security", "System", "Application"]:
        try:
            h = win32evtlog.OpenEventLog(None, channel)
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            events = win32evtlog.ReadEventLog(h, flags, 0)
            win32evtlog.CloseEventLog(h)

            for ev in events[:50]:   # last 50 per channel per poll
                msg = str(ev.StringInserts or "")[:200]
                eid = ev.EventID & 0xFFFF
                lvl = ("ERROR"
                       if ev.EventType in (win32con.EVENTLOG_ERROR_TYPE,
                                           win32con.EVENTLOG_WARNING_TYPE)
                       else "INFO")
                send_log(f"[WinEvent/{channel}] EventID={eid} {msg}", lvl)
        except Exception as e:
            logging.error(f"WinEvent {channel}: {e}")


# ── Process monitor (cross-platform, needs psutil) 
SUSPICIOUS_PROCS = [
    "nc", "ncat", "netcat", "nmap", "wireshark", "tcpdump",
    "mimikatz", "meterpreter", "cobaltstrike",
    "powershell", "cmd.exe", "wscript", "cscript",
]


def monitor_processes():
    """Detect and log suspicious processes."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            try:
                name = (proc.info["name"] or "").lower()
                if any(s in name for s in SUSPICIOUS_PROCS):
                    cmd = " ".join(proc.info["cmdline"] or [])[:200]
                    send_log(
                        f"[process] pid={proc.info['pid']} "
                        f"name={proc.info['name']} "
                        f"user={proc.info['username']} cmd={cmd}",
                        "WARNING"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        pass   # psutil is optional


# ── Main loop 
def main():
    logging.info(f"Alertix Local Agent v1.0 (OS={OS}, server={SERVER_URL})")
    send_log(f"Agent started on {OS} host: {platform.node()}", "INFO")

    state: dict = {}   # tracks file read offsets

    while True:
        try:
            if   OS == "Windows": run_windows(state)
            elif OS == "Darwin":  run_macos(state)
            else:                 run_linux(state)

            monitor_processes()

        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Agent loop error: {e}")

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()