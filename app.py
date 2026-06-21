# app.py
"""
Flask backend for Server Log Forensic Analyzer with real-time event simulation.
Exposes REST API for logs and Server-Sent Events (SSE) stream for live updates.
Uses pure Python standard libraries plus Flask.
"""

import json
import random
import threading
import time
import queue
from datetime import datetime
from flask import Flask, render_template, jsonify, Response

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Global state and configuration
# -----------------------------------------------------------------------------

# Storage for all logs (limited to last 200 entries to keep memory light)
logs = []
MAX_LOGS = 200

# Counters for dashboard widgets
counters = {
    "total_incidents": 0,
    "blocked_ips": 0,
    "critical_alerts": 0
}

# Set of IPs that have been blocked (due to brute‑force)
blocked_ips = set()

# Brute‑force tracker: IP -> list of timestamps (as float) of failed logins
bf_tracker = {}

# Thread‑safe queue for streaming new log events to SSE clients
log_queue = queue.Queue()

# Background thread control
simulation_running = False

# -----------------------------------------------------------------------------
# Mock log generation and anomaly detection
# -----------------------------------------------------------------------------

# Common IP pool (simulated internal network)
IP_POOL = [
    "192.168.1.{}".format(i) for i in range(10, 50)
] + [
    "10.0.0.{}".format(i) for i in range(10, 50)
]

# Paths for normal traffic
NORMAL_PATHS = [
    "/", "/index", "/about", "/contact", "/products", "/services",
    "/blog", "/login", "/dashboard", "/profile", "/settings"
]

# Methods
METHODS = ["GET", "POST", "PUT", "DELETE"]

def generate_normal_log():
    """Produce a benign log entry."""
    ip = random.choice(IP_POOL)
    method = random.choice(METHODS)
    path = random.choice(NORMAL_PATHS)
    status = random.choices([200, 404, 403, 500], weights=[0.7, 0.15, 0.1, 0.05])[0]
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "threat_level": "info",
        "attack_type": None,
        "message": f"{method} {path} → {status}"
    }

def generate_malicious_log():
    """
    Randomly create a log with a security anomaly.
    Returns (log_dict, is_critical) where is_critical indicates high severity.
    """
    attack_type = random.choices(
        ["sql_injection", "xss", "brute_force"],
        weights=[0.3, 0.3, 0.4]
    )[0]

    ip = random.choice(IP_POOL)
    method = "GET" if attack_type != "brute_force" else "POST"
    status = 200 if attack_type != "brute_force" else 401

    if attack_type == "sql_injection":
        path = "/products?id=1' OR '1'='1"
        msg = "SQL Injection attempt detected"
    elif attack_type == "xss":
        path = "/search?q=<script>alert(1)</script>"
        msg = "XSS attempt detected"
    else:  # brute_force
        path = "/login"
        msg = "Failed login attempt"

    threat = "critical" if attack_type != "brute_force" else "warning"  # brute force becomes critical only after threshold

    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "threat_level": threat,  # will be upgraded later if brute-force threshold met
        "attack_type": attack_type.replace("_", " ").title(),
        "message": msg
    }
    return log, (attack_type != "brute_force")  # initially only SQLi/XSS are critical

def update_brute_force_tracker(ip, timestamp):
    """
    Track failed logins per IP. If more than 5 in the last 60 seconds,
    mark as critical and block the IP.
    Returns True if a critical brute‑force alert is triggered.
    """
    now = timestamp
    if ip not in bf_tracker:
        bf_tracker[ip] = []
    # keep only recent entries
    bf_tracker[ip] = [t for t in bf_tracker[ip] if now - t < 60]
    bf_tracker[ip].append(now)

    if len(bf_tracker[ip]) >= 5:
        # Block IP and trigger critical alert
        blocked_ips.add(ip)
        counters["blocked_ips"] = len(blocked_ips)
        return True
    return False

def generate_mock_log():
    """
    Main log generator. With 30% probability creates an anomaly log,
    otherwise a normal log. It also updates brute‑force tracking and
    promotes warning to critical when threshold is reached.
    Returns a fully formed log dict.
    """
    # 30% chance of malicious, 70% normal
    if random.random() < 0.3:
        log, is_critical_init = generate_malicious_log()
    else:
        log = generate_normal_log()
        is_critical_init = False

    # If it's a brute‑force attempt (warning level), check threshold
    if log.get("attack_type") == "Brute Force" and log.get("threat_level") == "warning":
        # timestamp is already a string; convert to float
        ts = datetime.utcnow().timestamp()
        if update_brute_force_tracker(log["ip"], ts):
            log["threat_level"] = "critical"
            log["message"] = "Brute‑force attack detected and IP blocked"
            is_critical_init = True

    # If critical, increment critical alerts counter
    if is_critical_init or log.get("threat_level") == "critical":
        counters["critical_alerts"] += 1
        # For SQLi/XSS we also block IP (optional)
        if log.get("attack_type") in ["Sql Injection", "Xss"]:
            blocked_ips.add(log["ip"])
            counters["blocked_ips"] = len(blocked_ips)

    # Update total incidents (count every log as an incident)
    counters["total_incidents"] += 1

    return log

# -----------------------------------------------------------------------------
# Background simulation thread
# -----------------------------------------------------------------------------

def simulation_worker():
    """Continuously generate logs and put them into the queue."""
    global simulation_running
    simulation_running = True
    while simulation_running:
        # Generate a log
        log_entry = generate_mock_log()
        # Append to global logs list (limit size)
        logs.append(log_entry)
        if len(logs) > MAX_LOGS:
            logs.pop(0)
        # Push to SSE queue
        log_queue.put(log_entry)
        # Sleep between 1 and 3 seconds to simulate real‑time flow
        time.sleep(random.uniform(1.0, 3.0))

# Start the background thread when the first request arrives
@app.before_first_request
def start_simulation():
    if not simulation_running:
        thread = threading.Thread(target=simulation_worker, daemon=True)
        thread.start()

# -----------------------------------------------------------------------------
# Flask routes
# -----------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")

@app.route("/api/logs")
def get_logs():
    """Return the current list of all logs as JSON."""
    return jsonify(logs)

@app.route("/stream")
def stream_events():
    """
    Server‑Sent Events endpoint.
    Sends each new log as a JSON‑encoded data event.
    """
    def event_generator():
        while True:
            # Block until a new log arrives
            log_entry = log_queue.get()
            yield f"data: {json.dumps(log_entry)}\n\n"

    return Response(event_generator(), mimetype="text/event-stream")

# -----------------------------------------------------------------------------
# Run the application
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # For production, use a proper WSGI server; debug mode is for development only.
    app.run(debug=True, threaded=True, host="0.0.0.0", port=5000)