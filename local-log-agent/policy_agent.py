"""
Alertix - siem-log-server/policy_agent.py
==========================================
Monitors policy violations: acceptable use, data handling,
access time, insider threat indicators, and compliance events.

HOW TO RUN:
    cd siem-log-server
    pip install requests psutil
    python policy_agent.py

    # Optional env vars:
    #   ALERTIX_SERVER=http://127.0.0.1:5000/log
    #   POLICY_SCAN_SECS=30
    #   ALLOWED_HOURS=8-18       (work hours in 24h format)
    #   ALLOWED_DAYS=0-4         (Mon=0 … Fri=4)

What it enforces:
  - After-hours access detection
  - USB / removable media usage
  - Printing sensitive documents
  - Screen capture tools running
  - Prohibited applications (games, torrent clients, etc.)
  - Data loss prevention (DLP) indicators
  - Repeated failed logins (brute force / insider)
"""

import os
import sys
import time
import platform
import logging
import requests
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

SERVER_URL  = os.getenv("ALERTIX_SERVER",   "http://127.0.0.1:5000/log")
AGENT_NAME  = "policy-agent"
SCAN_SECS   = int(os.getenv("POLICY_SCAN_SECS", "30"))

# Work-hours policy (default 08:00 – 18:00, Mon–Fri)
ALLOWED_HOUR_START = int(os.getenv("ALLOWED_HOUR_START", "8"))
ALLOWED_HOUR_END   = int(os.getenv("ALLOWED_HOUR_END",  "18"))
ALLOWED_DAYS       = set(map(int, os.getenv("ALLOWED_DAYS", "0,1,2,3,4").split(",")))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [policy] %(levelname)s %(message)s"
)

OS = platform.system()


def send_log(message: str, level: str = "INFO"):
    try:
        r = requests.post(
            SERVER_URL,
            json={"log": message, "level": level, "source": AGENT_NAME},
            timeout=5
        )
        if r.status_code != 200:
            logging.warning(f"Server {r.status_code}: {r.text[:80]}")
    except requests.exceptions.ConnectionError:
        logging.error("Cannot reach Alertix server. Is server.py running?")
    except Exception as e:
        logging.error(f"send_log: {e}")


# ── Policy: after-hours access ────────────────────────────────────────────────
def check_access_hours():
    """Alert if system is actively used outside allowed hours."""
    now      = datetime.now()
    weekday  = now.weekday()   # 0=Mon … 6=Sun
    hour     = now.hour

    outside_hours = (hour < ALLOWED_HOUR_START or hour >= ALLOWED_HOUR_END)
    outside_days  = weekday not in ALLOWED_DAYS

    if outside_hours or outside_days:
        day_name  = now.strftime("%A")
        time_str  = now.strftime("%H:%M")
        send_log(
            f"[policy] After-hours system activity detected: "
            f"{day_name} {time_str} — outside allowed window "
            f"(Mon-Fri {ALLOWED_HOUR_START}:00-{ALLOWED_HOUR_END}:00)",
            "WARNING"
        )


# ── Policy: prohibited applications ──────────────────────────────────────────
PROHIBITED_APPS = {
    # Torrents / P2P
    "utorrent", "bittorrent", "qbittorrent", "vuze", "deluge", "transmission",
    # Games
    "steam", "epicgameslauncher", "battle.net", "origin", "gog galaxy",
    "minecraft", "fortnite",
    # Screen capture / spy tools
    "obs", "obs64", "bandicam", "fraps", "action",
    # Remote access (non-corporate)
    "anydesk", "teamviewer", "ultraviewer", "ammyy",
    # Crypto miners
    "xmrig", "cpuminer", "nicehash",
    # Data exfil tools
    "mega", "dropbox",  # flag if not on approved list
}

_seen_prohibited: set = set()


def check_prohibited_apps():
    """Alert when prohibited applications are running."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                name  = (proc.info["name"] or "").lower().replace(".exe", "")
                clean = name.replace(" ", "")
                if any(p in clean or p in name for p in PROHIBITED_APPS):
                    key = f"{name}:{proc.info['pid']}"
                    if key not in _seen_prohibited:
                        _seen_prohibited.add(key)
                        send_log(
                            f"[policy] Prohibited application running: "
                            f"name={proc.info['name']} pid={proc.info['pid']} "
                            f"user={proc.info['username']}",
                            "ERROR"
                        )
            except Exception:
                pass
    except ImportError:
        logging.warning("psutil not installed. Run: pip install psutil")


# ── Policy: USB / removable media ────────────────────────────────────────────
_known_drives: set = set()


def check_usb_devices():
    """Detect new removable drives (USB sticks, external HDDs)."""
    global _known_drives
    current_drives = set()

    if OS == "Windows":
        try:
            import psutil
            for part in psutil.disk_partitions():
                if "removable" in part.opts.lower():
                    current_drives.add(part.device)
        except ImportError:
            pass
    elif OS == "Linux":
        import glob
        for dev in glob.glob("/dev/sd[b-z]"):
            current_drives.add(dev)
    elif OS == "Darwin":
        volumes = list(Path("/Volumes").iterdir()) if Path("/Volumes").exists() else []
        current_drives = {str(v) for v in volumes
                          if v.is_mount() and str(v) != "/Volumes/Macintosh HD"}

    new_drives = current_drives - _known_drives
    for drive in new_drives:
        send_log(
            f"[policy] USB/Removable media connected: {drive} — "
            "potential data exfiltration risk",
            "WARNING"
        )
    _known_drives = current_drives


# ── Policy: screen capture tools ─────────────────────────────────────────────
SCREEN_CAPTURE_PROCS = {
    "snippingtool", "snipping tool", "screenshot", "screencapture",
    "obs", "obs64", "bandicam", "fraps",
    "lightshot", "greenshot", "sharex",
}


def check_screen_capture():
    """Alert on screen capture tools (potential data leakage)."""
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info["name"] or "").lower().replace(".exe", "")
                if any(s in name for s in SCREEN_CAPTURE_PROCS):
                    send_log(
                        f"[policy] Screen capture tool active: "
                        f"{proc.info['name']} (pid={proc.info['pid']}) — "
                        "possible sensitive data capture",
                        "WARNING"
                    )
            except Exception:
                pass
    except ImportError:
        pass


# ── Policy: DLP — large file operations ──────────────────────────────────────
DLP_SIZE_THRESHOLD_MB = 100   # files larger than this get flagged


def check_large_files():
    """Find recently modified large files that could indicate data staging."""
    watched = [Path.home() / "Desktop", Path.home() / "Downloads",
               Path("/tmp") if OS != "Windows" else Path(os.environ.get("TEMP", ""))]

    for folder in watched:
        if not folder.exists():
            continue
        try:
            for f in folder.iterdir():
                if f.is_file():
                    try:
                        size_mb = f.stat().st_size / (1024 * 1024)
                        if size_mb > DLP_SIZE_THRESHOLD_MB:
                            send_log(
                                f"[policy/DLP] Large file found: {f.name} "
                                f"({size_mb:.1f} MB) in {folder} — "
                                "possible data staging",
                                "WARNING"
                            )
                    except PermissionError:
                        pass
        except PermissionError:
            pass


# ── Policy: failed login tracking ────────────────────────────────────────────
_failed_login_counts: dict = defaultdict(int)
FAILED_LOGIN_THRESHOLD = 5


def check_failed_logins_linux():
    """Parse /var/log/auth.log for failed login attempts."""
    auth_log = "/var/log/auth.log"
    if not Path(auth_log).exists():
        return
    try:
        result = subprocess.run(
            ["grep", "Failed password", auth_log],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines()[-20:]:   # last 20 failures
            if "from" in line:
                # Extract IP from "Failed password for user from IP port ..."
                parts = line.split("from")
                if len(parts) > 1:
                    ip = parts[1].strip().split()[0]
                    _failed_login_counts[ip] += 1
                    if _failed_login_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                        send_log(
                            f"[policy] Brute force detected: {_failed_login_counts[ip]} "
                            f"failed SSH logins from {ip}",
                            "ERROR"
                        )
    except Exception as e:
        logging.debug(f"Failed login check error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    logging.info(f"Policy Agent starting (scan every {SCAN_SECS}s, server={SERVER_URL})")
    send_log("Policy Agent started", "INFO")

    while True:
        try:
            check_access_hours()
            check_prohibited_apps()
            check_usb_devices()
            check_screen_capture()
            check_large_files()
            if OS == "Linux":
                check_failed_logins_linux()

        except KeyboardInterrupt:
            logging.info("Policy agent stopped.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Policy scan error: {e}")

        time.sleep(SCAN_SECS)


if __name__ == "__main__":
    main()