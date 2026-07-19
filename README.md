# Network Traffic Analyzer & Packet Inspection Tool

A Python-based network traffic analyzer built using **Scapy** that captures and inspects live network packets, extracts protocol information across the TCP/IP stack, generates traffic statistics, detects basic suspicious network activity, and exports analysis reports.

---

## Features

- Capture live network traffic using Scapy
- Analyze IPv4, IPv6, and ARP packets
- Inspect TCP, UDP, and ICMP protocols
- Identify application protocols including:
  - DNS
  - HTTP
  - HTTPS
  - SSH
  - FTP
  - SMTP
  - DHCP
  - NTP
- Extract:
  - Source/Destination IP Address
  - Source/Destination Port
  - Packet Size
  - DNS Query Name
- Generate:
  - Network Layer Statistics
  - Transport Layer Statistics
  - Application Layer Statistics
  - Top Packet Senders
  - Top Bandwidth Senders
  - Packet Size Statistics
  - Bandwidth Estimation
- Detect basic security events:
  - Potential ICMP Flood
  - Potential TCP Port Scan
- Export captured traffic to CSV
- Generate protocol distribution charts using Matplotlib

---

## Project Structure

```
NetworkTrafficAnalyzer/
│
├── exports/
│   └── network_traffic.csv
│
├── graphs/
│   ├── application_distribution.png
│   ├── network_distribution.png
│   └── transport_distribution.png
│
├── modules/
│   ├── analyzer.py
│   ├── capture.py
│   ├── exporter.py
│   ├── security.py
│   └── visualizer.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

## Technologies Used

- Python
- Scapy
- Pandas
- Matplotlib

---

## How It Works

```
Live Packet Capture
        │
        ▼
Packet Analysis
(Network → Transport → Application)
        │
        ▼
Traffic Statistics
        │
        ▼
Security Analysis
        │
        ▼
CSV Export & Visualizations
```

---

## Sample Output

```
Network Layer Statistics

IPv4 : 50
IPv6 : 150

Transport Layer Statistics

TCP : 194
UDP : 6

Application Layer Statistics

HTTPS : 194
DNS : 6

Top Packet Senders

2606:4700:... : 96 packets

Top Bandwidth Senders

2606:4700:... : 131712 bytes

Packet Size Statistics

Average Packet Size : 850.37 bytes

Bandwidth Estimation

Capture Duration : 0.51 seconds
Bandwidth : 2.647 Mbps

Security Analysis

ICMP Flood : Not Detected
Port Scan : Not Detected
```
<img width="800" height="800" alt="transport_distribution" src="https://github.com/user-attachments/assets/438ad441-b467-4142-b196-1e7038f610c9" />

---

## Installation

Clone the repository

```bash
git clone https://github.com/<your-username>/<repository-name>.git
```

Move into the project directory

```bash
cd <repository-name>
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Run the analyzer

```bash
python main.py
```

The program will:

- Capture live packets
- Analyze traffic
- Display network statistics
- Perform basic security analysis
- Export results to CSV
- Generate protocol distribution graphs

---

## Security Analysis

The project performs lightweight heuristic-based detection for:

- ICMP Flood Activity
- TCP Port Scanning

These checks are intended for educational purposes and provide basic traffic analysis rather than full intrusion detection capabilities.

---

## Project Limitations

- HTTPS traffic is identified using well-known port numbers rather than decrypting encrypted payloads.
- Application protocol identification (except DNS) relies primarily on standard port mappings.
- Security detection uses simple heuristics and is not intended to replace enterprise IDS solutions.

---

## Future Improvements

- Support offline PCAP file analysis
- Add packet filtering options
- Improve protocol detection accuracy
- Expand security detection rules
- Enhance reporting and visualization

---

## Author

**Omsai Gulhane**
