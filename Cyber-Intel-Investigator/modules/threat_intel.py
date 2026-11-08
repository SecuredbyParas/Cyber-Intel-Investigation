import re
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Blueprint, request, jsonify

threat_bp = Blueprint("threat_intel", __name__)


SECURITY_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


TECH_SIGNS = {
    "WordPress": "wp-content", "Joomla": "joomla", "Drupal": "drupal",
    "jQuery": "jquery", "Bootstrap": "bootstrap", "React": "react",
    "Angular": "ng-version", "PHP": ".php", "ASP.NET": "asp.net",
}


def scrape_website(url):
    """Download a web page and collect security information from it."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    response = requests.get(url, timeout=10, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    final_url = response.url
    host = urlparse(final_url).hostname or ""

    # basic information
    title = soup.find("title")
    if title:
        page_title = title.get_text(strip=True)
    else:
        page_title = "-"
    info = {
        "Final URL": final_url,
        "Status Code": response.status_code,
        "Page Title": page_title,
        "Server": response.headers.get("Server", "Not shown"),
        "Powered By": response.headers.get("X-Powered-By", "Not shown"),
        "Content Type": response.headers.get("Content-Type", "-"),
        "Page Size": str(len(response.content)) + " bytes",
    }
    try:
        info["Server IP"] = socket.gethostbyname(host)
    except OSError:
        pass

    # security headers
    sec_headers = {}
    missing = []
    for name in SECURITY_HEADERS:
        value = response.headers.get(name, "MISSING")
        sec_headers[name] = value
        if value == "MISSING":
            missing.append(name)

    # links
    links = []
    seen = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href == "" or href == "#" or href in seen:
            continue
        seen.append(href)
        if href.startswith("http") and host not in href:
            link_type = "external"
        else:
            link_type = "internal"
        links.append({"href": href, "type": link_type})

    # forms
    forms = []
    for form in soup.find_all("form"):
        fields = []
        for field in form.find_all(["input", "textarea", "select"]):
            fields.append(field.get("type", field.name) + ":" + (field.get("name") or "-"))
        forms.append({
            "action": form.get("action", ""),
            "method": form.get("method", "GET").upper(),
            "fields": fields,
        })

    # cookies
    cookies = []
    for c in response.cookies:
        cookies.append({"name": c.name, "secure": bool(c.secure), "httponly": c.has_nonstandard_attr("HttpOnly")})

    # scripts, emails, technologies
    scripts = []
    for s in soup.find_all("script", src=True):
        scripts.append(s["src"])
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", response.text)))
    technologies = []
    page_lower = response.text.lower()
    for name in TECH_SIGNS:
        if TECH_SIGNS[name] in page_lower:
            technologies.append(name)

    # simple risk checks
    risks = []
    is_https = final_url.startswith("https://")
    if not is_https:
        risks.append("The site does not use HTTPS, so data is sent without encryption.")
    if len(missing) > 0:
        risks.append(str(len(missing)) + " security header(s) are missing: " + ", ".join(missing) + ".")
    server = response.headers.get("Server", "")
    if re.search(r"\d", server):
        risks.append("The server shows its version number (" + server + "), which helps attackers.")
    for f in forms:
        has_password = "password" in " ".join(f["fields"])
        if has_password and f["method"] == "GET":
            risks.append("A login form sends the password using GET, so it appears in the URL.")
        if has_password and not is_https:
            risks.append("A login form is used on a page without HTTPS.")
    for c in cookies:
        if not c["secure"] or not c["httponly"]:
            risks.append("Cookie '" + c["name"] + "' is missing the Secure or HttpOnly flag.")
    if len(emails) > 0:
        risks.append(str(len(emails)) + " email address(es) are visible on the page.")

    return {
        "url": final_url,
        "info": info,
        "security_headers": sec_headers,
        "risks": risks,
        "links": links[:100],
        "forms": forms,
        "cookies": cookies,
        "scripts": scripts[:50],
        "emails": emails,
        "technologies": technologies,
        "html": response.text[:5000],
        "counts": {
            "Links": len(links),
            "Forms": len(forms),
            "Cookies": len(cookies),
            "Scripts": len(scripts),
            "Risks Found": len(risks),
        },
    }


@threat_bp.route("/api/scrape", methods=["POST"])
def api_scrape():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if url == "":
        return jsonify({"error": "Please enter a URL."}), 400
    try:
        return jsonify(scrape_website(url))
    except requests.RequestException as error:
        message = "Could not open the website. Check the URL and your internet connection. ("
        message += type(error).__name__ + ")"
        return jsonify({"error": message}), 400
