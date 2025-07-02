from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse
import os
import re

app = Flask(__name__)

LOG_FILE_PATH = os.path.join("siem-log-server", "logs", "server.log")
PRODUCTIVE_DOMAINS = ["mail.google.com", "docs.google.com", "calendar.google.com"]
ENTERTAINMENT_DOMAINS = ["youtube.com", "netflix.com", "reddit.com"]

def parse_focus_logs(hours):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    domain_times = defaultdict(float)

    try:
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return domain_times

    last_time = None
    last_domain = None

    for i in range(len(lines)):
        if "Tab updated:" not in lines[i]:
            continue

        time_match = re.search(r"time:\s([\d\-:, ]+)", lines[i - 1]) if i > 0 else None
        if not time_match:
            continue

        try:
            log_time = datetime.strptime(time_match.group(1).strip(), "%Y-%m-%d %H:%M:%S,%f")
        except ValueError:
            continue

        if log_time < cutoff:
            continue

        url_match = re.search(r'Tab updated:\s(.+)', lines[i])
        if not url_match:
            continue

        domain = urlparse(url_match.group(1)).netloc

        if last_time and last_domain:
            delta = (log_time - last_time).total_seconds()
            if 0 < delta < 600:
                domain_times[last_domain] += delta

        last_time = log_time
        last_domain = domain

    return domain_times


def summarize_domains(domain_times, category):
    def summarize(domains):
        return sorted(
            [(d, round(t / 60, 1)) for d, t in domain_times.items() if d in domains],
            key=lambda x: x[1], reverse=True
        )

    if category == "productive":
        result = summarize(PRODUCTIVE_DOMAINS)
    elif category == "entertainment":
        result = summarize(ENTERTAINMENT_DOMAINS)
    elif category == "all":
        result = sorted(
            [(d, round(t / 60, 1)) for d, t in domain_times.items()],
            key=lambda x: x[1], reverse=True
        )
    else:
        return {"error": "Invalid category. Use 'productive', 'entertainment', or 'all'."}, None

    return None, result


@app.route("/chrome-logs/focus/get", methods=["GET"])
def get_focus_logs():
    hours = int(request.args.get("hours", 1))
    category = request.args.get("category", "all").strip().lower()

    domain_times = parse_focus_logs(hours)
    error, result = summarize_domains(domain_times, category)
    if error:
        return jsonify(error), 400

    return jsonify({
        "category": category,
        "total_minutes": sum(t for _, t in result),
        "domains": result,
        "hours_analyzed": hours
    })


@app.route("/chrome-logs/focus/update", methods=["POST"])
def update_focus_logs():
    data = request.get_json(silent=True)
    if not data or "hours" not in data:
        return jsonify({"error": "Missing 'hours' in request"}), 400

    hours = int(data["hours"])
    category = data.get("category", "all").strip().lower()

    domain_times = parse_focus_logs(hours)
    error, result = summarize_domains(domain_times, category)
    if error:
        return jsonify(error), 400

    return jsonify({
        "category": category,
        "total_minutes": sum(t for _, t in result),
        "domains": result,
        "hours_analyzed": hours
    })


@app.route("/chrome-logs/focus/clear", methods=["DELETE"])
def clear_focus_logs():
    if not os.path.exists(LOG_FILE_PATH):
        return jsonify({"status": "Log file already cleared"}), 200

    with open(LOG_FILE_PATH, "r") as f:
        lines = f.readlines()

    with open(LOG_FILE_PATH, "w") as f:
        inside_block = False
        skip_block = False
        for line in lines:
            if line.strip() == "":
                if not skip_block:
                    f.write("\n")
                inside_block = False
                skip_block = False
            elif ": " in line:
                if not inside_block:
                    inside_block = True
                    skip_block = False
                if "chrome" in line.lower() or "google.com" in line.lower():
                    skip_block = True
                if not skip_block:
                    f.write(line)
            else:
                if not skip_block:
                    f.write(line)

    return jsonify({"status": "Chrome-related logs cleared"}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5001)
