"""
utils.py - small things that are used by more than one module.
"""

import re

# port number -> service name (used by the scanner and the packet pages)
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def get_lines(text):
    """Split the text into lines and remove the empty ones."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line != "":
            lines.append(line)
    return lines


def find(pattern, line):
    """Return the first group found by the regex, or 'unknown'."""
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    return "unknown"


def matches_any(patterns, text):
    """True if any of the regex patterns is found in the text."""
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False
