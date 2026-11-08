import os
import socket
import struct
from collections import Counter, defaultdict
from datetime import datetime

from flask import Blueprint, request, jsonify

from utils import PORT_NAMES, matches_any

packet_bp = Blueprint("packet_analysis", __name__)

# folder of the whole project (one level above the modules folder)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


ATTACK_RULES = {
    "SQL Injection": [r"union\s+select", r"or\s+1=1", r"drop\s+table", r"sleep\(\d+\)", r"'\s*--"],
    "XSS Attack": [r"<script", r"javascript:", r"onerror=", r"alert\(", r"document\.cookie"],
    "Malicious Payload": [r"wget\s+http", r"curl\s+http", r"/bin/sh", r"cmd\.exe", r"eval\(", r"base64"],
}


PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def check_payload(text):
    """Return the names of the attacks found inside a payload."""
    found = []
    for name in ATTACK_RULES:
        if matches_any(ATTACK_RULES[name], text):
            found.append(name)
    return found


def new_packet(src, dst, proto, sport="", dport="", flags="", length=0, payload=""):
    """Make one packet record (dictionary). Used by pcap and live capture."""
    service = PORT_NAMES.get(dport, "")
    if service == "":
        service = PORT_NAMES.get(sport, "")
    return {
        "time": "",
        "src": src,
        "dst": dst,
        "proto": proto,
        "sport": sport,
        "dport": dport,
        "service": service,
        "flags": flags,
        "length": length,
        "payload": payload,
        "threats": check_payload(payload),
    }


def parse_packet(raw, linktype):
    """Read the raw bytes of one packet. Returns None if it can not be read."""

    # step 1 - skip the first header to reach the IP packet
    if linktype == 1:                       # Ethernet
        if len(raw) < 14:
            return None
        ethertype = struct.unpack("!H", raw[12:14])[0]
        start = 14
        if ethertype == 0x8100:             # VLAN tag
            ethertype = struct.unpack("!H", raw[16:18])[0]
            start = 18
        if ethertype == 0x0806:
            return new_packet("-", "-", "ARP", length=len(raw))
        if ethertype != 0x0800:             # not IPv4 (for example IPv6)
            return new_packet("-", "-", "Other", length=len(raw))
        ip = raw[start:]
    elif linktype == 101:                   # raw IP (used by Windows capture)
        ip = raw
    elif linktype == 113:                   # Linux cooked capture
        ip = raw[16:]
    elif linktype == 0:                     # loopback
        ip = raw[4:]
    else:
        return None

    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None

    # step 2 - read the IP header
    header_len = (ip[0] & 15) * 4
    proto_number = ip[9]
    proto = PROTOCOL_NAMES.get(proto_number, "IP-" + str(proto_number))
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    body = ip[header_len:]

    # step 3 - read the TCP / UDP / ICMP part
    sport = ""
    dport = ""
    flags = ""
    data = b""
    if proto == "TCP" and len(body) >= 20:
        sport, dport = struct.unpack("!HH", body[:4])
        flag_byte = body[13]
        flag_list = []
        if flag_byte & 1:
            flag_list.append("FIN")
        if flag_byte & 2:
            flag_list.append("SYN")
        if flag_byte & 4:
            flag_list.append("RST")
        if flag_byte & 8:
            flag_list.append("PSH")
        if flag_byte & 16:
            flag_list.append("ACK")
        if flag_byte & 32:
            flag_list.append("URG")
        flags = " ".join(flag_list)
        data = body[(body[12] >> 4) * 4:]
    elif proto == "UDP" and len(body) >= 8:
        sport, dport = struct.unpack("!HH", body[:4])
        data = body[8:]
    elif proto == "ICMP":
        data = body[8:]

    # step 4 - change the payload into readable text
    text = ""
    for ch in data.decode("latin-1"):
        if 32 <= ord(ch) < 127:
            text += ch
        else:
            text += "."
    return new_packet(src, dst, proto, sport, dport, flags, len(raw), text[:300])


def read_pcap(data):
    """Read a normal .pcap file. Returns (list of (time, bytes), linktype)."""
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1" or magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"                        # little endian file
    elif magic == b"\xa1\xb2\xc3\xd4" or magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"                        # big endian file
    else:
        raise ValueError("not a pcap file")

    nanoseconds = magic == b"\x4d\x3c\xb2\xa1" or magic == b"\xa1\xb2\x3c\x4d"
    linktype = struct.unpack(endian + "I", data[20:24])[0]

    packets = []
    pos = 24                                # the file header is 24 bytes
    while pos + 16 <= len(data):
        seconds, fraction, caplen, origlen = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        raw = data[pos:pos + caplen]
        pos += caplen
        if nanoseconds:
            packet_time = seconds + fraction / 1e9
        else:
            packet_time = seconds + fraction / 1e6
        packets.append((packet_time, raw))
    return packets, linktype


def read_pcapng(data):
    """Read a .pcapng file (Wireshark saves this format by default)."""
    if data[8:12] == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    else:
        endian = ">"

    linktype = 1
    packets = []
    pos = 0
    while pos + 12 <= len(data):
        block_type, block_len = struct.unpack(endian + "II", data[pos:pos + 8])
        if block_len < 12:
            break
        body = data[pos + 8:pos + block_len - 4]

        if block_type == 1:                 # interface description block
            linktype = struct.unpack(endian + "H", body[:2])[0]
        elif block_type == 6:               # enhanced packet block (one packet)
            ts_high, ts_low, caplen = struct.unpack(endian + "III", body[4:16])
            packet_time = ((ts_high << 32) | ts_low) / 1e6
            packets.append((packet_time, body[20:20 + caplen]))
        pos += block_len
    return packets, linktype


def summarize_packets(packets):
    """Count protocols, ports, attacks and port scans in a list of packets."""
    protocols = Counter()
    talkers = Counter()
    ports = Counter()
    attack_counts = Counter()
    syn_ports = defaultdict(set)            # source IP -> ports it sent SYN to
    threat_packets = []

    for p in packets:
        protocols[p["proto"]] += 1
        if p["src"] != "-":
            talkers[p["src"]] += 1
        if p["dport"] != "":
            ports[(str(p["dport"]) + " " + p["service"]).strip()] += 1
        if p["flags"] == "SYN":
            syn_ports[p["src"]].add(p["dport"])
        for name in p["threats"]:
            attack_counts[name] += 1
        if len(p["threats"]) > 0:
            threat_packets.append(p)

    # one IP sending SYN packets to 10 or more ports = port scan
    scanners = []
    for ip in syn_ports:
        if len(syn_ports[ip]) >= 10:
            scanners.append({"ip": ip, "ports": len(syn_ports[ip])})

    bad_ips = []
    for p in threat_packets:
        if p["src"] not in bad_ips:
            bad_ips.append(p["src"])
    for s in scanners:
        if s["ip"] not in bad_ips:
            bad_ips.append(s["ip"])

    return {
        "total": len(packets),
        "protocols": dict(protocols),
        "top_ports": dict(ports.most_common(8)),
        "top_talkers": dict(talkers.most_common(8)),
        "attack_counts": dict(attack_counts),
        "threat_packets": threat_packets[:100],
        "port_scanners": scanners,
        "suspicious_ips": bad_ips,
        "packets": packets[:300],           # send only the first 300 to the browser
    }


@packet_bp.route("/api/analyze-pcap", methods=["POST"])
def api_analyze_pcap():
    # the user uploads a file, or presses the "sample" button
    if request.args.get("sample"):
        f = open(os.path.join(BASE_DIR, "sample_data", "sample.pcap"), "rb")
        data = f.read()
        f.close()
    else:
        uploaded = request.files.get("pcap")
        if uploaded is None or uploaded.filename == "":
            return jsonify({"error": "Please choose a pcap file first."}), 400
        data = uploaded.read()

    try:
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            raw_packets, linktype = read_pcapng(data)
        else:
            raw_packets, linktype = read_pcap(data)
    except (ValueError, struct.error):
        return jsonify({"error": "This file is not a valid .pcap or .pcapng file."}), 400

    packets = []
    for packet_time, raw in raw_packets:
        packet = parse_packet(raw, linktype)
        if packet is not None:
            packet["time"] = datetime.fromtimestamp(packet_time).strftime("%H:%M:%S")
            packets.append(packet)

    if len(packets) == 0:
        return jsonify({"error": "No readable packets were found in this file."}), 400
    return jsonify(summarize_packets(packets))
