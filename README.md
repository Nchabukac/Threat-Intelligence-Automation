# Threat Intelligence Automation

A Python security analysis tool that extracts and analyzes PCAP network traffic, detects threats, and correlates findings against multiple threat intelligence feeds.

## Features

- **PCAP Analysis** — Extracts source/destination IPs, protocols (TCP/UDP/HTTP/DNS), User-Agent strings, DNS queries, file objects, and **reconstructs full HTTP requests** from TCP streams using `scapy`.
- **Threat Detection** — Heuristic/signature-based scanning for malicious User-Agents (sqlmap, nmap, nikto, etc.), suspicious DNS domains, dangerous file extensions, and common attack patterns in log files (SQLi, XSS, path traversal, command injection, brute force, port scanning).
- **Threat Intelligence Correlation** — Queries 4 threat feeds against extracted IPs and domains (DNS queries + HTTP Host headers):
  - [AlienVault OTX](https://otx.alienvault.com/)
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [URLhaus (Abuse.ch)](https://urlhaus.abuse.ch/)
  - [ThreatFox (Abuse.ch)](https://threatfox.abuse.ch/)
- **Markdown Reporting** — Generates a structured `security_report.md` with introduction, scope, findings, recommendations, references, and conclusion.

## Prerequisites

- Python 3.10+
- `pip` (Python package manager)

## Installation
Recommended to use a virtual environment because of pip

```bash
# Clone or navigate to the project directory
cd "Threat Intelligence Automation"

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration — API Keys

API keys are loaded from a `.env` file in the project root. Copy the example and fill in the keys for the feeds you want to query. At least one is recommended.

```bash
cp .env.example .env
# Edit .env with your keys:
#   OTX_API_KEY=your-key           # https://otx.alienvault.com/
#   ABUSEIPDB_API_KEY=your-key     # https://www.abuseipdb.com/
#   ABUSE_CH_API_KEY=your-key      # https://urlhaus.abuse.ch/ + https://threatfox.abuse.ch/
```
URLhaus and ThreatFox share the same Auth-Key from Abuse.ch — set `ABUSE_CH_API_KEY` once for both. You can obtain a key at [auth.abuse.ch](https://auth.abuse.ch/).

Keys can also be set as traditional environment variables if preferred — they take precedence over `.env` values.

## Testing Connectivity

Before running the main tool, verify your threat feed connectivity:

```bash
python test_ti_feeds.py
```

This sends a safe test query to each feed and reports which ones are reachable and which are missing API keys.

## Usage

```bash
# Basic — analyze a PCAP file
python threat_intel_tool.py --pcap capture.pcap

# With additional log file (PCAP HTTP requests are already scanned automatically)
python threat_intel_tool.py --pcap capture.pcap --log access.log

# Custom output path
python threat_intel_tool.py --pcap capture.pcap --output my_report.md

# Offline mode — skip API queries (PCAP analysis + heuristics only)
python threat_intel_tool.py --pcap capture.pcap --skip-ti
```

## Example PCAP Files

PCAP used is from https://www.malware-traffic-analysis.net/2026/02/28/index.html

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

## Output

The tool generates a Markdown report (`security_report.md` by default) containing:

1. **Introduction** — overview of the analysis
2. **Scope & Objective** — files analyzed, feeds queried
3. **Findings** — network summary, detected threats, threat intel matches
4. **Recommendations** — actionable remediation steps
5. **References** — threat intelligence feeds used
6. **Conclusion** — summary and next steps

## Some content from security_report.md
<img width="1042" height="641" alt="image" src="https://github.com/user-attachments/assets/4805dd35-a652-46eb-90af-b2e529de7727" />
<img width="1046" height="570" alt="image" src="https://github.com/user-attachments/assets/31f22c04-db55-480b-b3e9-3ffe19c34e34" />
<img width="1083" height="689" alt="image" src="https://github.com/user-attachments/assets/91f7bf1e-6254-454d-ae5d-d138ee57426e" />
<img width="1070" height="524" alt="image" src="https://github.com/user-attachments/assets/72180c57-cba9-4fc7-9ac5-b30ed40f57c2" />
<img width="1065" height="621" alt="image" src="https://github.com/user-attachments/assets/1c466d46-4ebc-4378-9780-f1aed1cc1664" />
<img width="1063" height="328" alt="image" src="https://github.com/user-attachments/assets/3a247dad-6be1-481f-8575-f75bc2dfb6bf" />

## Project Structure

```
├── threat_intel_tool.py   # Main analysis script
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── security_report.md      # Generated report (output)
```
