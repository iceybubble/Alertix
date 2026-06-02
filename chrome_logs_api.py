from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from urllib.parse import urlparse
import os
import re
import logging

# ---- FIX 1: app was never defined in original file ----
app = Flask(__name__)

# ---- FIX 2: Correct log file path ----
# Original pointed to "siem-log-server/logs/server.log" (relative subfolder)
# but server.py writes to logs/server.log relative to its own location.
# Use an absolute path based on this file's location so it always resolves.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "server.log")

PRODUCTIVE_DOMAINS   = ["mail.google.com", "docs.google.com", "calendar.google.com",
                         "github.com", "gitlab.com", "stackoverflow.com"]
ENTERTAINMENT_DOMAINS = ["youtube.com", "netflix.com", "reddit.com", "twitch.tv",
                          "spotify.com", "hulu.com"]

# ---- FIX 3: Correct log line parser ----
# Original regex looked for "time: 2026-..." which never exists.
# Actual log format written by server.py:
#   2026-06-01 22:51:19,374 - INFO - [chrome-extension] Medium | Entertainment | Distractive | Tab updated: https://...
#
# Pattern: ^<timestamp> - <level> - <message containing "Tab updated:" or "Tab activated:">
LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - \w+ - .*?(Tab (?:updated|activated)): (https?://\S+)"
)

def parse_focus_logs(hours):
    """Parse server.log and return per-domain time in seconds."""
    cutoff       = datetime.now(timezone.utc) - timedelta(hours=hours)
    domain_times = defaultdict(float)

    if not os.path.exists(LOG_FILE_PATH):
        logging.warning(f"Log file not found: {LOG_FILE_PATH}")
        return domain_times

    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Could not read log file: {e}")
        return domain_times

    last_time   = None
    last_domain = None

    for line in lines:
        m = LOG_LINE_RE.match(line.strip())
        if not m:
            continue

        time_str, _action, url = m.group(1), m.group(2), m.group(3)

        try:
            # Parse "2026-06-01 22:51:19,374" → datetime
            log_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S,%f")
            log_time = log_time.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        if log_time < cutoff:
            continue

        domain = urlparse(url).netloc.lstrip("www.")

        if last_time is not None and last_domain is not None:
            delta = (log_time - last_time).total_seconds()
            # Only count if gap < 10 minutes (avoid counting idle time)
            if 0 < delta < 600:
                domain_times[last_domain] += delta

        last_time   = log_time
        last_domain = domain

    return domain_times


def summarize_domains(domain_times, category):
    """Filter and sort domain times by category."""
    def to_list(domains=None):
        items = domain_times.items() if domains is None else (
            (d, t) for d, t in domain_times.items() if d in domains
        )
        return sorted(
            [(d, round(t / 60, 1)) for d, t in items],
            key=lambda x: x[1], reverse=True
        )

    if category == "productive":
        return None, to_list(PRODUCTIVE_DOMAINS)
    elif category == "entertainment":
        return None, to_list(ENTERTAINMENT_DOMAINS)
    elif category == "all":
        return None, to_list()
    else:
        return {"error": "Invalid category. Use 'productive', 'entertainment', or 'all'."}, None


# ============ ROUTES ============

@app.route("/chrome-logs/focus/get", methods=["GET"])
def get_focus_logs():
    hours    = int(request.args.get("hours", 1))
    category = request.args.get("category", "all").strip().lower()

    domain_times = parse_focus_logs(hours)
    error, result = summarize_domains(domain_times, category)

    if error:
        return jsonify(error), 400

    result = result or []
    return jsonify({
        "category":       category,
        "total_minutes":  round(sum(t for _, t in result), 1),
        "domains":        result,
        "hours_analyzed": hours,
        "log_file":       LOG_FILE_PATH
    })


@app.route("/chrome-logs/focus/update", methods=["POST"])
def update_focus_logs():
    data = request.get_json(silent=True)
    if not data or "hours" not in data:
        return jsonify({"error": "Missing 'hours' in request body"}), 400

    hours    = int(data["hours"])
    category = data.get("category", "all").strip().lower()

    domain_times = parse_focus_logs(hours)
    error, result = summarize_domains(domain_times, category)

    if error:
        return jsonify(error), 400

    result = result or []
    return jsonify({
        "category":       category,
        "total_minutes":  round(sum(t for _, t in result), 1),
        "domains":        result,
        "hours_analyzed": hours
    })


@app.route("/chrome-logs/focus/clear", methods=["DELETE"])
def clear_focus_logs():
    if not os.path.exists(LOG_FILE_PATH):
        return jsonify({"status": "Log file not found, nothing to clear"}), 200

    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Keep only lines that are NOT chrome tab events
        kept = [
            line for line in lines
            if "Tab updated:" not in line and "Tab activated:" not in line
        ]

        with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
            f.writelines(kept)

        removed = len(lines) - len(kept)
        return jsonify({"status": f"Cleared {removed} chrome log lines"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/chrome-logs/debug", methods=["GET"])
def debug_log_path():
    """Helper endpoint to verify the log file path and line count."""
    exists     = os.path.exists(LOG_FILE_PATH)
    line_count = 0
    tab_count  = 0
    if exists:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        line_count = len(lines)
        tab_count  = sum(1 for l in lines if "Tab updated:" in l or "Tab activated:" in l)

    return jsonify({
        "log_file":   LOG_FILE_PATH,
        "exists":     exists,
        "total_lines": line_count,
        "tab_events": tab_count
    })


if __name__ == "__main__":
    app.run(debug=True, port=5001)