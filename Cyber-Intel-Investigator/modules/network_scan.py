import socket
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, request, jsonify

from utils import PORT_NAMES

scan_bp = Blueprint("network_scan", __name__)


SCAN_TYPES = {
    "common": list(PORT_NAMES.keys()),
    "top20": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443, 27017],
    "full": list(range(1, 1025)),
}


HIGH_RISK_PORTS = [23, 445, 3389, 3306, 5900, 6379, 27017, 1433]


MEDIUM_RISK_PORTS = [21, 25, 110, 139, 143]


def scan_host(ip, ports):
    """Try to connect to every port. If the connection works, the port is open."""

    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))    # 0 means connected
        s.close()
        return result == 0

    # use many threads at the same time so the scan is fast
    with ThreadPoolExecutor(max_workers=100) as pool:
        states = list(pool.map(check_port, ports))

    open_ports = []
    for i in range(len(ports)):
        if states[i]:
            port = ports[i]
            if port in HIGH_RISK_PORTS:
                risk = "HIGH"
            elif port in MEDIUM_RISK_PORTS:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            open_ports.append({"port": port, "service": PORT_NAMES.get(port, "Unknown"), "risk": risk})
    return open_ports


@scan_bp.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("host", "").strip()
    scan_type = data.get("scan_type", "common")

    if target == "":
        return jsonify({"error": "Please enter a target host or IP address."}), 400
    if scan_type not in SCAN_TYPES:
        return jsonify({"error": "Unknown scan type."}), 400

    try:
        ip = socket.gethostbyname(target)
    except OSError:
        return jsonify({"error": "Cannot find the host '" + target + "'."}), 400

    ports = SCAN_TYPES[scan_type]
    start = time.time()
    open_ports = scan_host(ip, ports)

    return jsonify({
        "host": target,
        "ip": ip,
        "scanned": len(ports),
        "seconds": round(time.time() - start, 1),
        "open_ports": open_ports,
    })
