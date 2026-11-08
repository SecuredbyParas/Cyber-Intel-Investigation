import os
import socket
import time
from datetime import datetime

from flask import Blueprint, request, jsonify

from modules.packet_analysis import parse_packet, summarize_packets

live_bp = Blueprint("live_capture", __name__)


def get_local_ips():
    """Return the IP addresses of this computer (main one first)."""
    ips = []

    # the IP that is used to reach the internet (no data is really sent)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass

    # all other IPs of this computer (wifi, ethernet, ...)
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass

    if len(ips) == 0:
        ips.append("127.0.0.1")
    return ips


def open_capture_socket(adapter_ip):
    """
    Open a raw socket that receives packets.
    Windows : needs Command Prompt "Run as administrator".
    Linux   : needs sudo.
    Returns (socket, linktype).
    """
    if os.name == "nt":
        # Windows: bind to the IP of the network adapter, then switch on "receive all"
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        try:
            s.bind((adapter_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except OSError:
            s.close()
            raise
        return s, 101       # packets start directly with the IP header
    else:
        # Linux: AF_PACKET gives every packet with the Ethernet header
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        return s, 1


def capture_live(count, seconds, adapter_ip, filter_ip):
    """Capture packets until we have 'count' packets or 'seconds' have passed.
    If filter_ip is given, only packets from/to that IP are kept."""
    s, linktype = open_capture_socket(adapter_ip)
    s.settimeout(1)

    packets = []
    end_time = time.time() + seconds
    try:
        while len(packets) < count and time.time() < end_time:
            try:
                raw = s.recvfrom(65535)[0]
            except socket.timeout:
                continue                    # nothing received in 1 second, try again
            packet = parse_packet(raw, linktype)
            if packet is None:
                continue
            if filter_ip != "" and packet["src"] != filter_ip and packet["dst"] != filter_ip:
                continue                    # not the IP we are watching
            packet["time"] = datetime.now().strftime("%H:%M:%S")
            packets.append(packet)
    finally:
        if os.name == "nt":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        s.close()
    return packets


@live_bp.route("/api/interfaces")
def api_interfaces():
    return jsonify({"ips": get_local_ips()})


@live_bp.route("/api/capture", methods=["POST"])
def api_capture():
    data = request.get_json(silent=True) or {}
    filter_ip = data.get("ip", "").strip()
    adapter_ip = data.get("adapter", "").strip()

    try:
        count = int(data.get("count", 50))
        seconds = int(data.get("seconds", 10))
    except ValueError:
        return jsonify({"error": "Packet count and time must be numbers."}), 400
    count = min(max(count, 1), 1000)
    seconds = min(max(seconds, 1), 60)

    if adapter_ip == "":
        adapter_ip = get_local_ips()[0]

    try:
        packets = capture_live(count, seconds, adapter_ip, filter_ip)
    except PermissionError:
        return jsonify({"error": "Permission denied. Close the app and start it again as Administrator "
                                 "(Windows: right click Command Prompt > Run as administrator) "
                                 "or with sudo (Linux)."}), 403
    except (AttributeError, OSError) as error:
        return jsonify({"error": "Live capture failed: " + str(error)}), 400

    return jsonify(summarize_packets(packets))
