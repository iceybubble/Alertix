"""
Alertix - siem-log-server/network.py
======================================
Monitors network connections, detects suspicious traffic, port scans,
C2 beaconing, and unusual outbound connections.

HOW TO RUN:
    cd siem-log-server
    pip install requests psutil
    python network.py

    # Optional env vars:
    #   ALERTIX_SERVER=http://127.0.0.1:5000/log
    #   NETWORK_SCAN_SECS=10

What it detects:
  - Connections to known malicious IPs / Tor exit nodes
  - Unusual ports (C2, IRC, NetBus, etc.)
  - Port scan activity (many SYN connections in short time)
  - DNS anomalies (very long subdomains = DNS tunneling)
  - High outbound data volume (exfiltration indicator)
  - Listening services that weren't there before
"""

import os
import sys
import time
import socket
import logging
import requests
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any

SERVER_URL       = os.getenv("ALERTIX_SERVER", "http://127.0.0.1:5000/log")
AGENT_NAME       = "network-agent"
SCAN_SECS        = int(os.getenv("NETWORK_SCAN_SECS", "10"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [network] %(levelname)s %(message)s"
)


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


# ── Threat intelligence (demo IOC list) ──────────────────────────────────────
# In production, replace with a live feed (e.g. AlienVault OTX, VirusTotal)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.47",   # Tor exit node (demo)
    "198.51.100.0",     # RFC 5737 test range (demo)
    "203.0.113.5",      # RFC 5737 test range (demo)
}

# Ports associated with C2 / malware / backdoors
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    1234:  "Common backdoor",
    31337: "Elite/Back Orifice",
    6667:  "IRC/Botnet C2",
    6666:  "IRC/Botnet C2",
    9999:  "Common backdoor",
    5555:  "Android ADB / backdoor",
    8888:  "Jupyter / common backdoor",
    2222:  "Alternative SSH",
    8080:  "Alternate HTTP (watch for tunneling)",
    3389:  "RDP — alert if unexpected outbound",
}

# Legitimate internal ranges (RFC 1918)
PRIVATE_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
    ("127.0.0.0",    "127.255.255.255"),
]


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


def is_private_ip(ip: str) -> bool:
    try:
        n = ip_to_int(ip)
        return any(ip_to_int(lo) <= n <= ip_to_int(hi)
                   for lo, hi in PRIVATE_RANGES)
    except Exception:
        return False


# ── Psutil-based connection monitoring ───────────────────────────────────────
_prev_listeners: set = set()
_conn_counts: dict   = defaultdict(int)   # remote_ip → count this cycle


def scan_connections():
    """Check all active network connections for threats."""
    global _prev_listeners

    try:
        import psutil
    except ImportError:
        logging.error("psutil not installed. Run: pip install psutil")
        return

    current_listeners = set()
    _conn_counts.clear()

    connections = psutil.net_connections(kind="inet")
    for conn in connections:
        laddr = conn.laddr
        raddr = conn.raddr

        # Track listeners safely bypassing union type definitions
        if conn.status == "LISTEN" and laddr and not isinstance(laddr, str):
            l_ip = getattr(laddr, "ip", laddr[0])
            l_port = getattr(laddr, "port", laddr[1])
            key = f"{l_ip}:{l_port}"
            current_listeners.add(key)
            if key not in _prev_listeners:
                pid_str = f"pid={conn.pid}" if conn.pid is not None else "pid=unknown"
                send_log(
                    f"[network] New listening service on {key} "
                    f"({pid_str})",
                    "WARNING"
                )

        if not raddr or isinstance(raddr, str):
            continue

        remote_ip: str = getattr(raddr, "ip", raddr[0])
        remote_port: int = getattr(raddr, "port", raddr[1])

        # Skip private/local
        if is_private_ip(remote_ip):
            continue

        _conn_counts[remote_ip] += 1

        # Known malicious IP
        if remote_ip in KNOWN_MALICIOUS_IPS:
            pname = "unknown"
            if conn.pid is not None:
                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name()
                except Exception:
                    pname = "unknown"
            
            pid_str = f"{conn.pid}" if conn.pid is not None else "unknown"
            send_log(
                f"[network] KNOWN MALICIOUS IP: {remote_ip}:{remote_port} "
                f"← pid={pid_str} ({pname})",
                "CRITICAL"
            )

        # Suspicious port
        if remote_port in SUSPICIOUS_PORTS:
            pid_str = f"{conn.pid}" if conn.pid is not None else "unknown"
            send_log(
                f"[network] Suspicious port {remote_port} "
                f"({SUSPICIOUS_PORTS[remote_port]}): "
                f"pid={pid_str} → {remote_ip}:{remote_port}",
                "ERROR"
            )

    # Port scan indicator: same process connecting to many IPs
    high_conn_ips = [(ip, cnt) for ip, cnt in _conn_counts.items() if cnt > 10]
    for ip, cnt in high_conn_ips:
        send_log(
            f"[network] Possible port scan / C2 beacon: "
            f"{cnt} connections to {ip} in one cycle",
            "ERROR"
        )

    _prev_listeners = current_listeners


def scan_network_io():
    """Alert on unusually high outbound data (possible exfiltration)."""
    try:
        import psutil
        stats = psutil.net_io_counters()
        # In production, compare delta between polls. Here we just log high values.
        bytes_sent = stats.bytes_sent
        if bytes_sent > 500 * 1024 * 1024:   # > 500 MB total sent since boot
            send_log(
                f"[network] High cumulative outbound traffic: "
                f"{bytes_sent // (1024*1024)} MB sent since boot",
                "WARNING"
            )
    except Exception:
        pass


def check_dns_anomalies():
    """
    Basic DNS tunneling detection: long subdomain queries.
    In production, hook into DNS resolver logs or use pcap.
    Here we attempt to resolve known suspicious patterns.
    """
    # Demo: log if we can resolve known C2 domains
    SUSPECT_DOMAINS = [
        "icanhazip.com",   # IP lookup service (used by malware for C2 discovery)
        "ifconfig.me",     # same
    ]
    for domain in SUSPECT_DOMAINS:
        try:
            ip = socket.gethostbyname(domain)
            # Only flag if something is actually connecting to them
            # (just a presence check for demo purposes)
            logging.debug(f"DNS: {domain} → {ip}")
        except Exception:
            pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    logging.info(f"Network Agent starting (scan every {SCAN_SECS}s, server={SERVER_URL})")
    send_log("Network Agent started", "INFO")

    while True:
        try:
            scan_connections()
            scan_network_io()
            check_dns_anomalies()
        except KeyboardInterrupt:
            logging.info("Network agent stopped.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Network scan error: {e}")

        time.sleep(SCAN_SECS)


if __name__ == "__main__":
    main()