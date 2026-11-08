"""
Module 1 - Log Analysis
The user uploads a log file (authentication, web server or firewall log)
and we search it for attacks.
"""

from collections import Counter, defaultdict

from flask import Blueprint, request, jsonify

from utils import get_lines, find, matches_any

log_bp = Blueprint("log_analysis", __name__)


def analyze_auth_log(text):
    """Authentication log: failed logins, brute force, sudo commands."""
    failed = []
    success = []
    invalid = []
    sudo = []
    attempts = Counter()      # failed attempts for every IP

    lines = get_lines(text)
    for line in lines:
        ip = find(r"from (\d+\.\d+\.\d+\.\d+)", line)

        if "Failed password" in line:
            failed.append({"ip": ip, "line": line})
            attempts[ip] += 1
        elif "Accepted password" in line:
            success.append({"ip": ip, "line": line})
        elif "Invalid user" in line:
            invalid.append({"ip": ip, "line": line})
            attempts[ip] += 1
        elif "sudo" in line and "COMMAND" in line:
            sudo.append({"ip": "-", "line": line})

    # 5 or more failed attempts from one IP = brute force attack
    brute_force = []
    for ip in attempts:
        if attempts[ip] >= 5:
            brute_force.append({"ip": ip, "attempts": attempts[ip]})

    if len(brute_force) > 0:
        severity = "HIGH"
    elif len(failed) > 0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "log_type": "Authentication Log",
        "total_lines": len(lines),
        "severity": severity,
        "counts": {
            "Failed Logins": len(failed),
            "Successful Logins": len(success),
            "Invalid Users": len(invalid),
            "Sudo Commands": len(sudo),
        },
        "threat_total": len(failed) + len(invalid),
        "chart_title": "Failed attempts per IP",
        "chart": dict(attempts.most_common(8)),
        "brute_force_ips": brute_force,
        "suspicious_ips": list(attempts.keys()),
        "findings": {
            "Failed Logins": failed,
            "Invalid Users": invalid,
            "Sudo Commands": sudo,
        },
    }


def analyze_server_log(text):
    """Web server log (Apache / Nginx): SQL injection, path traversal, attack tools."""
    sql_patterns = [r"union.*select", r"or\s*'1'\s*=\s*'1", r"drop\s+table", r"sleep\(\d+\)", r"1=1"]
    traversal_patterns = [r"\.\./", r"%2e%2e", r"/etc/passwd", r"/etc/shadow"]
    sensitive_patterns = [r"\.env", r"\.git", r"backup", r"wp-admin", r"phpmyadmin", r"config\.php"]
    bad_agents = ["sqlmap", "nikto", "masscan", "nmap"]

    sql = []
    traversal = []
    sensitive = []
    tools = []
    requests_per_ip = Counter()
    bad_ips = []

    lines = get_lines(text)
    for line in lines:
        ip = find(r"^(\d+\.\d+\.\d+\.\d+)", line)
        requests_per_ip[ip] += 1

        # the requested url is inside the first quotes: "GET /index.php HTTP/1.1"
        url = find(r'"(?:GET|POST|PUT|DELETE|HEAD)\s+(.*?)\s+HTTP', line)
        if url == "unknown":
            url = ""

        # the user agent is the last thing inside quotes
        agent = find(r'"([^"]*)"$', line)
        if agent == "unknown":
            agent = ""

        entry = {"ip": ip, "line": line}
        found = False
        if matches_any(sql_patterns, url):
            sql.append(entry)
            found = True
        if matches_any(traversal_patterns, url):
            traversal.append(entry)
            found = True
        if matches_any(sensitive_patterns, url):
            sensitive.append(entry)
            found = True
        if matches_any(bad_agents, agent):
            tools.append(entry)
            found = True
        if found and ip not in bad_ips:
            bad_ips.append(ip)

    if len(sql) > 0 or len(traversal) > 0:
        severity = "HIGH"
    elif len(tools) > 0 or len(sensitive) > 0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "log_type": "Web Server Log",
        "total_lines": len(lines),
        "severity": severity,
        "counts": {
            "SQL Injection": len(sql),
            "Path Traversal": len(traversal),
            "Sensitive File Access": len(sensitive),
            "Attack Tools": len(tools),
        },
        "threat_total": len(sql) + len(traversal) + len(sensitive) + len(tools),
        "chart_title": "Requests per IP",
        "chart": dict(requests_per_ip.most_common(8)),
        "brute_force_ips": [],
        "suspicious_ips": bad_ips,
        "findings": {
            "SQL Injection": sql,
            "Path Traversal": traversal,
            "Sensitive File Access": sensitive,
            "Attack Tools (user-agent)": tools,
        },
    }


def parse_firewall_line(line):
    """Get (action, source ip, destination port) from one firewall log line."""
    upper = line.upper()

    # find the action word
    action = "OTHER"
    if "BLOCK" in upper or "DENY" in upper or "REJECT" in upper:
        action = "BLOCK"
    elif "DROP" in upper:
        action = "DROP"
    elif "ALLOW" in upper or "ACCEPT" in upper or "PERMIT" in upper:
        action = "ALLOW"

    if "SRC=" in line:
        # format: ... SRC=1.2.3.4 DST=10.0.0.1 SPT=5000 DPT=22
        src = find(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
        port_text = find(r"DPT=(\d+)", line)
    else:
        # Windows firewall log (pfirewall.log):
        # date time action protocol src-ip dst-ip src-port dst-port ...
        parts = line.split()
        if len(parts) > 7:
            src = parts[4]
            port_text = parts[7]
        else:
            src = "unknown"
            port_text = "0"

    if port_text.isdigit():
        port = int(port_text)
    else:
        port = 0
    return action, src, port


def analyze_firewall_log(text):
    """Firewall log: blocked traffic, port scans, dangerous ports."""
    dangerous_ports = [21, 22, 23, 25, 445, 3306, 3389]
    blocked = []
    risky = []
    blocked_per_ip = Counter()
    ports_per_ip = defaultdict(set)     # IP -> set of ports it tried
    actions = Counter()

    lines = []
    for line in get_lines(text):
        if not line.startswith("#"):    # lines starting with # are comments
            lines.append(line)

    for line in lines:
        action, src, port = parse_firewall_line(line)
        actions[action] += 1
        ports_per_ip[src].add(port)

        if action == "BLOCK" or action == "DROP":     # Windows firewall only writes DROP
            blocked_per_ip[src] += 1
            entry = {"ip": src, "port": port, "line": line}
            blocked.append(entry)
            if port in dangerous_ports:
                risky.append(entry)

    # one IP trying 5 or more different ports = port scan
    scanners = []
    for ip in ports_per_ip:
        if len(ports_per_ip[ip]) >= 5:
            scanners.append({"ip": ip, "ports": len(ports_per_ip[ip])})

    if len(scanners) > 0 or len(risky) > 5:
        severity = "HIGH"
    elif len(blocked) > 0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    scan_findings = []
    suspicious = list(blocked_per_ip.keys())
    for s in scanners:
        scan_findings.append({"ip": s["ip"], "line": s["ip"] + " tried " + str(s["ports"]) + " different ports"})
        if s["ip"] not in suspicious:
            suspicious.append(s["ip"])

    return {
        "log_type": "Firewall Log",
        "total_lines": len(lines),
        "severity": severity,
        "counts": {
            "Blocked": actions["BLOCK"],
            "Allowed": actions["ALLOW"],
            "Dropped": actions["DROP"],
            "Port Scanners": len(scanners),
        },
        "threat_total": len(blocked) + len(scanners),
        "chart_title": "Blocked packets per IP",
        "chart": dict(blocked_per_ip.most_common(8)),
        "brute_force_ips": [],
        "suspicious_ips": suspicious,
        "findings": {
            "Port Scan Suspects": scan_findings,
            "Dangerous Ports Blocked": risky,
        },
    }


def detect_log_type(text):
    """Guess the log type from keywords. Returns None if nothing matches."""
    t = text.lower()
    scores = {"auth": 0, "server": 0, "firewall": 0}

    for word in ["sshd", "failed password", "invalid user", "sudo", "accepted password"]:
        if word in t:
            scores["auth"] += 1
    for word in ["http/1", "get /", "post /", "mozilla"]:
        if word in t:
            scores["server"] += 1
    for word in ["firewall", "src=", "dst=", "dpt=", "pfirewall"]:
        if word in t:
            scores["firewall"] += 1

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return None
    return best


LOG_ANALYZERS = {
    "auth": analyze_auth_log,
    "server": analyze_server_log,
    "firewall": analyze_firewall_log,
}


@log_bp.route("/api/analyze-log", methods=["POST"])
def api_analyze_log():
    uploaded = request.files.get("logfile")
    log_type = request.form.get("log_type", "auto")

    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "Please choose a log file first."}), 400

    text = uploaded.read().decode("utf-8", errors="ignore")
    if text.strip() == "":
        return jsonify({"error": "The file is empty."}), 400

    if log_type == "auto":
        log_type = detect_log_type(text)
        if log_type is None:
            return jsonify({"error": "Could not recognise this log. Please select the log type yourself."}), 400
    if log_type not in LOG_ANALYZERS:
        return jsonify({"error": "Unknown log type."}), 400

    result = LOG_ANALYZERS[log_type](text)
    result["file_name"] = uploaded.filename
    return jsonify(result)
