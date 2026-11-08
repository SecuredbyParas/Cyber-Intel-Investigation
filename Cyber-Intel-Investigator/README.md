# CyberIntel Investigator

**CyberIntel Investigator** is a Python Flask-based web application developed as a cybersecurity project to investigate and analyze potential cyber threats.

It provides multiple tools for analyzing security logs, scanning networks, inspecting packets, checking website security and monitoring live network traffic.

## Features

### 1. Log Analysis
- Upload authentication, web server and firewall logs.
- Detect SSH brute-force attempts.
- Identify SQL injection and path traversal patterns.
- Detect suspicious activity and possible port scans.

### 2. Network Scanning
- Scan a target IP address or hostname.
- Identify open ports.
- Detect running services.
- Assign risk levels to open ports.

### 3. Packet Analysis
- Upload `.pcap` and `.pcapng` files.
- Analyze network packets.
- Identify suspicious payloads, SQL injection and XSS patterns.
- Detect possible port scanning activity.

### 4. Threat Intelligence
- Analyze website information using web scraping.
- Collect security headers, links, forms and cookies.
- Identify potential website security risks.

### 5. Live Network Capture
- Capture real network packets using Python raw sockets.
- Monitor network traffic.
- Display source IP, destination IP and protocol information.

### 6. Dashboard
- View security analysis results from different modules.
- Monitor alerts and investigation activity.
- View statistics and investigation timelines.
- Download analysis results in JSON format.

## Technologies Used

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Libraries:** Requests, BeautifulSoup4
- **Networking:** Python Raw Sockets, TCP/IP
- **File Analysis:** PCAP and PCAPNG

## Installation and Setup

### Prerequisites
- Python 3.8 or newer
- Git

### Step 1: Clone the repository


git clone https://github.com/your-username/Cyber-Intel-Investigator.git


### Step 2: Open the project directory


cd Cyber-Intel-Investigator


### Step 3: Install dependencies


pip install -r requirements.txt

### Step 4: Run the application

python app.py

### Step 5: Open in your browser

Visit:

http://127.0.0.1:5000


## Sample Data

A sample PCAP file is provided in the `sample_data/` folder to test the Packet Analysis module.

The application analyzes the files uploaded by the user. It does not require predefined fake log data.

## Detection Logic

The application uses rule-based detection techniques:

- Brute Force: Detects 5 or more failed login attempts from one IP address.
- Port Scanning: Identifies suspicious activity based on multiple blocked ports or SYN packets.
- SQL Injection and XSS:Uses regular-expression patterns to identify suspicious payloads.
- Port Risk Assessment: Assigns risk levels to selected open ports and services.

## Limitations

- This project is developed for educational and learning purposes.
- Detection is primarily rule-based.
- Detailed packet analysis focuses on IPv4 traffic.
- Network scanning uses TCP connect scanning.
- Detection results require manual verification and should not be treated as confirmed attacks.

## Security Disclaimer

This project is intended for educational and authorized security testing only.

Only scan networks and capture traffic on systems that you own or have explicit permission to test.

