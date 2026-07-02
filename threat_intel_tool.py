#!/usr/bin/env python3
BANNER = r"""
┌─────────────────────────────────────────────────────────────────────────────┐
│   _____ _                    _   ___       _       _                        │
│  |_   _| |__  _ __ ___  __ _| |_|_ _|_ __ | |_ ___| |                       │
│    | | | '_ \| '__/ _ \/ _` | __|| || '_ \| __/ _ \ |                       │
│    | | | | | | | |  __/ (_| | |_ | || | | | ||  __/ |                       │
│    |_| |_| |_|_|  \___|\__,_|\__|___|_| |_|\__\___|_|                       │
│    ==================== AUTOMATION TOOL ====================                │
│                                                                             │
│   [>] Extracts and analyzes PCAP network traffic for suspicious activity.   │
│   [>] Parses network traffic to detect threats.                             │
│   [>] Correlates findings with multiple Threat Intelligence Feeds.          │
│   [>] Generates a detailed Markdown security report.                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
"""

print(BANNER)

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import textwrap
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional dependency checks
# ---------------------------------------------------------------------------
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import magic as mgc
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

# ---------------------------------------------------------------------------
# Configuration — Threat Intelligence Feeds
# ---------------------------------------------------------------------------

# Load API keys from .env file (if present), falling back to environment variables.
# Copy .env.example → .env and fill in your keys.

try:
    from dotenv import load_dotenv
    _ENV_PATH = Path(__file__).resolve().parent / ".env"
    if _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)
except ImportError:
    pass  # python-dotenv not installed; keys must be set as env vars

OTX_API_KEY      = os.environ.get("OTX_API_KEY", "")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSE_CH_KEY    = os.environ.get("ABUSE_CH_API_KEY", "")
URLHAUS_KEY      = os.environ.get("URLHAUS_API_KEY", "") or ABUSE_CH_KEY
THREATFOX_KEY    = os.environ.get("THREATFOX_API_KEY", "") or ABUSE_CH_KEY
# VIRUSTOTAL_KEY   = os.environ.get("VIRUSTOTAL_API_KEY", "")  # 4 req/min — too restrictive

# API endpoints / URLs
OTX_IP_URL       = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_DOMAIN_URL   = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
ABUSEIPDB_URL    = "https://api.abuseipdb.com/api/v2/check"
# VT_IP_URL        = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"  # rate-limited: 4/min
URLHAUS_URL      = "https://urlhaus-api.abuse.ch/v1/url/"
THREATFOX_URL    = "https://threatfox-api.abuse.ch/api/v1/"

# User-Agent for HTTP requests
HEADERS_DEFAULT = {
    "User-Agent": "ThreatIntelAutomation/1.0 (security-research@localhost)"
}

# Known-benign domain patterns — skipped during TI correlation to avoid wasting quotas 

BENIGN_DOMAIN_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        # Major tech / cloud
        r"\.?microsoft\.com$", r"\.?microsoftonline\.com$", r"\.?office(?:365)?\.com$",
        r"\.?azure\.com$", r"\.?azureedge\.net$", r"\.?visualstudio\.com$",
        r"\.?github\.com$", r"\.?githubusercontent\.com$", r"\.?npmjs\.com$",
        r"\.?google\.com$", r"\.?googleapis\.com$", r"\.?google-?analytics\.com$",
        r"\.?googletagmanager\.com$", r"\.?gstatic\.com$", r"\.?googleusercontent\.com$",
        r"\.?youtube\.com$", r"\.?ytimg\.com$", r"\.?doubleclick\.net$",
        r"\.?chromium\.org$", r"\.?android\.com$",
        r"\.?apple\.com$", r"\.?icloud\.com$", r"\.?aaplimg\.com$", r"\.?mzstatic\.com$",
        r"\.?(?:s3\.)?amazonaws\.com$", r"\.?amazon\.com$", r"\.?cloudfront\.net$",
        r"\.?facebook\.com$", r"\.?fbcdn\.net$", r"\.?instagram\.com$",
        r"\.?whatsapp\.(?:com|net)$",
        r"\.?(?:twitter|x)\.com$", r"\.?twimg\.com$",
        r"\.?linkedin\.com$", r"\.?licdn\.com$",
        r"\.?netflix\.com$", r"\.?nflxvideo\.net$", r"\.?nflxext\.com$",
        r"\.?spotify\.com$", r"\.?scdn\.co$",
        r"\.?adobe\.com$", r"\.?adobe\.io$", r"\.?typekit\.net$",
        r"\.?oracle\.com$", r"\.?salesforce\.com$", r"\.?servicenow\.com$",
        r"\.?ibm\.com$", r"\.?intel\.com$", r"\.?cisco\.com$", r"\.?broadcom\.com$",
        # CDN / infrastructure
        r"\.?akamai(?:edge)?\.net$", r"\.?edgesuite\.net$",
        r"\.?fastly(?:lb)?\.net$",
        r"\.?cloudflare\.com$", r"\.?cloudflareinsights\.com$",
        r"\.?jsdelivr\.net$", r"\.?cdnjs\.com$", r"\.?unpkg\.com$",
        r"\.?quic\.cloud$", r"\.?litespeedtech\.com$",
        # Certificate authorities / registrars
        r"\.?digicert\.com$", r"\.?letsencrypt\.org$", r"\.?sectigo\.com$",
        r"\.?globalsign\.com$", r"\.?godaddy\.com$", r"\.?namecheap\.com$",
        # Common open-source infra
        r"\.?ubuntu\.com$", r"\.?debian\.org$", r"\.?redhat\.com$",
        r"\.?fedoraproject\.org$", r"\.?docker\.com$", r"\.?docker\.io$",
        r"\.?pypi\.org$", r"\.?python\.org$", r"\.?pythonhosted\.org$",
        r"\.?nodejs\.org$", r"\.?npmjs\.org$",
        r"\.?stackoverflow\.com$", r"\.?stackexchange\.com$",
        r"\.?wikipedia\.org$", r"\.?wikimedia\.org$", r"\.?archive\.org$",
        r"\.?gravatar\.com$",
        # Payments / SaaS
        r"\.?paypal\.com$", r"\.?paypalobjects\.com$", r"\.?stripe\.com$",
        r"\.?dropbox\.com$", r"\.?dropboxstatic\.com$",
        r"\.?slack\.com$", r"\.?slack-edge\.com$",
        r"\.?zoom\.us$", r"\.?zoom\.com$", r"\.?webex\.com$",
        r"\.?zoho\.com$", r"\.?zohocdn\.com$",
        # Monitoring / error tracking
        r"\.?datadoghq\.com$", r"\.?datadog\.com$", r"\.?newrelic\.com$",
        r"\.?sentry\.io$", r"\.?sentry-cdn\.com$",
        # NTP / infrastructure
        r"\.?ntp\.org$", r"\.?pool\.ntp\.org$", r"\.?root-servers\.net$",
        # Microsoft update services
        r"\.?windows\.com$", r"\.?windowsupdate\.com$", r"\.?msftncsi\.com$",
        r"\.?msn\.com$", r"\.?bing\.com$",
    ]
]


def is_benign_domain(domain: str) -> bool:
    """Return True if *domain* matches a known-benign domain pattern."""
    domain = domain.lower().rstrip(".")
    return any(p.search(domain) for p in BENIGN_DOMAIN_PATTERNS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a private / reserved / loopback address."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True  # treat unparseable as private (skip)


def sha256_file(path: str) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def api_get(url: str, headers: dict | None = None, timeout: int = 15) -> dict | None:
    """Thin GET wrapper; returns parsed JSON dict or None on failure."""
    if not HAS_REQUESTS:
        return None
    try:
        r = requests.get(url, headers=headers or HEADERS_DEFAULT, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def api_get_with_key(url: str, api_key: str, extra_headers: dict | None = None) -> dict | None:
    """GET with an API-Key header."""
    if not api_key:
        return None
    headers = {**HEADERS_DEFAULT, **(extra_headers or {})}
    headers[api_key.get("header", "Key")] = api_key.get("value", "")
    return api_get(url, headers)


def api_post(url: str, json_data: dict, headers: dict | None = None, timeout: int = 15) -> dict | None:
    """Thin POST wrapper for JSON APIs (e.g. ThreatFox); returns parsed dict or None."""
    if not HAS_REQUESTS:
        return None
    try:
        r = requests.post(url, json=json_data, headers=headers or HEADERS_DEFAULT, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PCAP Analysis
# ---------------------------------------------------------------------------

def _reassemble_http_requests(packets) -> list[dict]:
    """
    Reassemble TCP streams from *packets* and parse HTTP requests.
    Returns a list of dicts with keys: method, uri, host, user_agent, raw_request.
    """
    # Group TCP packets with payload by 5-tuple
    streams: dict[tuple, list] = defaultdict(list)

    for pkt in packets:
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue
        try:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                payload = payload
            else:
                payload = bytes(payload, "utf-8", errors="ignore")
        except Exception:
            continue
        if not payload:
            continue

        # Key by (src, sport, dst, dport) — bidirectional grouping
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams[key].append((pkt[TCP].seq, payload))

    # Direction hint: client→server usually has lower port numbers as dst
    http_requests: list[dict] = []

    for (src, sport, dst, dport), segments in streams.items():
        # Sort by TCP sequence number
        segments.sort(key=lambda x: x[0])

        # Concatenate payloads (deduplicating overlapping segments by sequence)
        stream_data = b""
        last_seq = None
        for seq, data in segments:
            if last_seq is None:
                stream_data = data
            else:
                # Simple append — overlap handling is best-effort
                stream_data += data
            last_seq = seq

        # Decode and parse HTTP requests
        try:
            text = stream_data.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # Split on HTTP request boundaries — a request line starts a new request
        # Pattern: METHOD /path HTTP/1.x
        request_bodies = re.split(
            r"(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP/\d\.\d)",
            text
        )

        for body in request_bodies:
            body = body.strip()
            if not body:
                continue

            # Parse request line
            req_match = re.match(
                r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)",
                body
            )
            if not req_match:
                continue

            method = req_match.group(1)
            uri = req_match.group(2)

            # Parse headers
            host = ""
            ua = ""
            content_type = ""

            host_match = re.search(r"[Hh]ost:\s*(.+)", body)
            if host_match:
                host = host_match.group(1).strip()

            ua_match = re.search(r"[Uu]ser-[Aa]gent:\s*(.+)", body)
            if ua_match:
                ua = ua_match.group(1).strip()

            ct_match = re.search(r"[Cc]ontent-[Tt]ype:\s*(.+)", body)
            if ct_match:
                content_type = ct_match.group(1).strip()

            http_requests.append({
                "method": method,
                "uri": uri,
                "http_version": req_match.group(3),
                "host": host,
                "user_agent": ua,
                "content_type": content_type,
                "raw_request": body[:2000],  # cap for memory
            })

    return http_requests


def analyze_pcap(pcap_path: str) -> dict:
    """
    Parse a PCAP file and return a structured dictionary of extracted
    metadata and indicators, including reconstructed HTTP requests.
    """
    if not HAS_SCAPY:
        return {"error": "scapy is not installed.  pip install scapy",
                "pcap_path": pcap_path}

    packets = rdpcap(pcap_path)

    src_ips      : Counter = Counter()
    dst_ips      : Counter = Counter()
    protocols    : Counter = Counter()
    user_agents  : list[str] = []
    dns_queries  : list[str] = []
    file_objects : list[dict] = []        # {filename, size, sha256 (best-effort)}

    # Protocol counters
    proto_map = {TCP: "TCP", UDP: "UDP"}

    for pkt in packets:
        # IP layer
        if IP in pkt:
            sip = pkt[IP].src
            dip = pkt[IP].dst
            if not is_private_ip(sip):
                src_ips[sip] += 1
            if not is_private_ip(dip):
                dst_ips[dip] += 1

        # Protocol
        proto = "Other"
        for layer, name in proto_map.items():
            if layer in pkt:
                proto = name
                break
        protocols[proto] += 1

        # HTTP User-Agent extraction from raw payload
        if Raw in pkt:
            try:
                payload = pkt[Raw].load
                if isinstance(payload, bytes):
                    payload_str = payload.decode("utf-8", errors="ignore")
                else:
                    payload_str = str(payload)

                # Hunt for User-Agent header
                ua_match = re.search(
                    r"[Uu]ser-[Aa]gent:\s*(.+)", payload_str
                )
                if ua_match:
                    ua = ua_match.group(1).strip()
                    user_agents.append(ua)

                # Hunt for file names / content-disposition
                file_match = re.search(
                    r'filename="?([^"\r\n;]+)"?', payload_str
                )
                if file_match:
                    fname = file_match.group(1)
                    file_objects.append(
                        {"filename": fname, "size": len(payload), "sha256": None}
                    )
            except Exception:
                pass

        # DNS queries
        if DNS in pkt and pkt[DNS].qr == 0:  # query
            try:
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                dns_queries.append(qname)
            except Exception:
                pass

    # --- Reconstruct HTTP requests from TCP streams ---
    http_requests = _reassemble_http_requests(packets)

    # Also collect any User-Agents found during reassembly
    for req in http_requests:
        if req["user_agent"]:
            user_agents.append(req["user_agent"])

    return {
        "pcap_path": pcap_path,
        "packet_count": len(packets),
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "protocols": protocols,
        "user_agents": user_agents,
        "dns_queries": dns_queries,
        "file_objects": file_objects,
        "http_requests": http_requests,
    }


# ---------------------------------------------------------------------------
# Threat Detection (heuristic / signature-based)
# ---------------------------------------------------------------------------

# Suspicious User-Agent patterns (known malicious tools, scanners, etc.)
SUSPICIOUS_UA_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        r"sqlmap",
        r"nmap",
        r"nikto",
        r"gobuster",
        r"dirb",
        r"hydra",
        r"burpsuite",
        r"zgrab",
        r"masscan",
        r"nessus",
        r"openvas",
        r"acunetix",
        r"metasploit",
        r"curl/",           
        r"wget/",
        r"python-requests",
        r"python-urllib",
        r"go-http-client",
        r"libwww-perl",
        r"zgrab/",
        r"censys",
        r"shodan",
    ]
]

SUSPICIOUS_DNS_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        r"\.(?:tk|ml|ga|cf|gq)$",           # free TLDs can be abused
        r"\.ddns\.net$",
        r"\.hopto\.org$",
        r"dns(?:-)?exfil",
        r"pastebin\.com",
        r"\.onion$",
        r"bit\.ly",
        r"tinyurl",
        r"ngrok",
        r"requestbin",
        r"webhook\.site",
    ]
]

# Common malware / C2 ports
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 8080, 8443, 4443, 5555, 9999}

SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd",
    ".scr", ".pif", ".msi", ".hta", ".jar", ".js",
    ".docm", ".xlsm", ".pptm", ".pdf", ".zip", ".rar",
}


def detect_threats(pcap_data: dict, log_lines: list[str] = None) -> dict:
    """
    Run heuristic / signature-based detection across PCAP extract and
    optional log lines.  Returns a structured dict of findings.
    """
    findings: list[dict] = []

    # --- User-Agent checks ---
    for ua in pcap_data.get("user_agents", []):
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua):
                findings.append({
                    "type": "suspicious_user_agent",
                    "indicator": ua,
                    "detail": f"User-Agent matched suspicious pattern: {pattern.pattern}",
                    "source": "pcap",
                })
                break   # one match per UA is enough

    # --- DNS checks ---
    for qname in pcap_data.get("dns_queries", []):
        for pattern in SUSPICIOUS_DNS_PATTERNS:
            if pattern.search(qname):
                findings.append({
                    "type": "suspicious_dns",
                    "indicator": qname,
                    "detail": f"DNS query matched suspicious pattern: {pattern.pattern}",
                    "source": "pcap",
                })
                break

    # --- File extension checks ---
    for fobj in pcap_data.get("file_objects", []):
        ext = Path(fobj["filename"]).suffix.lower()
        if ext in SUSPICIOUS_FILE_EXTENSIONS:
            findings.append({
                "type": "suspicious_file",
                "indicator": fobj["filename"],
                "detail": f"Potentially dangerous file extension: {ext}",
                "source": "pcap",
            })

    # --- Log-based threat detection ---
    if log_lines:
        log_threats = _detect_log_threats(log_lines)
        findings.extend(log_threats)

    return {
        "total_findings": len(findings),
        "findings": findings,
    }


def _detect_log_threats(log_lines: list[str]) -> list[dict]:
    """Scan log lines for common attack patterns."""
    log_findings = []
    patterns = {
        "sql_injection": re.compile(
            r"(?:SELECT|UNION|INSERT|DROP|ALTER)\s.*(?:FROM|INTO|TABLE)", re.IGNORECASE
        ),
        "xss": re.compile(
            r"<script|javascript:|onerror=|onload=|alert\(|eval\(|<img[^>]+onerror",
            re.IGNORECASE,
        ),
        "path_traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini"),
        "command_injection": re.compile(
            r"[;&|`$]\s*(?:ls|id|whoami|cat |uname|pwd|rm -rf|wget |curl )",
            re.IGNORECASE,
        ),
        "brute_force": re.compile(
            r"(?:failed|invalid|incorrect)\s*(?:login|auth|password)", re.IGNORECASE
        ),
        "port_scan": re.compile(
            r"scan|port.*scan|nmap|masscan", re.IGNORECASE
        ),
    }

    for line_no, line in enumerate(log_lines, start=1):
        for threat_type, pattern in patterns.items():
            if pattern.search(line):
                log_findings.append({
                    "type": threat_type,
                    "indicator": line.strip()[:200],
                    "detail": f"Line {line_no}: matched pattern '{threat_type}'",
                    "source": "log",
                })
    return log_findings


# ---------------------------------------------------------------------------
# Threat Intelligence Correlation
# ---------------------------------------------------------------------------

def _check_otx(ip: str) -> dict | None:
    """Query AlienVault OTX for an IPv4 indicator."""
    if not OTX_API_KEY:
        return None
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    return api_get(OTX_IP_URL.format(ip=ip), {**HEADERS_DEFAULT, **headers})


def _check_otx_domain(domain: str) -> dict | None:
    """Query AlienVault OTX for a domain indicator."""
    if not OTX_API_KEY:
        return None
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    return api_get(OTX_DOMAIN_URL.format(domain=domain), {**HEADERS_DEFAULT, **headers})


def _check_abuseipdb(ip: str) -> dict | None:
    """Query AbuseIPDB v2."""
    if not ABUSEIPDB_KEY:
        return None
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(ABUSEIPDB_URL, headers={**HEADERS_DEFAULT, **headers},
                         params=params, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# VirusTotal disabled — free tier limited to 4 requests/minute, impractical for
# batch IP lookups without paid plan.  Uncomment if you have an elevated API tier.
#
# def _check_virustotal_ip(ip: str) -> dict | None:
#     \"\"\"Query VirusTotal v3 for an IP address.\"\"\"
#     if not VIRUSTOTAL_KEY:
#         return None
#     headers = {"x-apikey": VIRUSTOTAL_KEY}
#     return api_get(VT_IP_URL.format(ip=ip), {**HEADERS_DEFAULT, **headers})


def _check_urlhaus(indicator: str) -> dict | None:
    """Query URLhaus for a URL / IP / domain (requires API key)."""
    if not URLHAUS_KEY:
        return None
    headers = {**HEADERS_DEFAULT, "Auth-Key": URLHAUS_KEY}
    data = {"url": indicator}
    try:
        r = requests.post(URLHAUS_URL, data=data, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _check_threatfox(indicator: str) -> dict | None:
    """Query ThreatFox for IOCs — IP or domain (requires API key)."""
    if not THREATFOX_KEY:
        return None
    headers = {**HEADERS_DEFAULT, "Auth-Key": THREATFOX_KEY}
    return api_post(THREATFOX_URL, {"query": "search_ioc", "search_term": indicator}, headers=headers)


def _correlate_indicator(indicator: str, indicator_type: str) -> dict:
    """
    Query all applicable threat feeds for a single indicator (IP or domain).
    Always returns an entry with every applicable feed — feeds that returned
    no data get a fallback status string so the report is comprehensive.
    """
    NO_DATA = "no_data"

    entry = {indicator_type: indicator, "feeds": {}}

    if indicator_type == "ip":
        # OTX IP
        otx = _check_otx(indicator)
        entry["feeds"]["AlienVault OTX"] = {
            "status": "ok" if otx else NO_DATA,
            "pulse_count": otx.get("pulse_info", {}).get("count", 0) if otx else 0,
            "reputation": otx.get("reputation", None) if otx else None,
        }

        # AbuseIPDB (IP only)
        abuse = _check_abuseipdb(indicator)
        if abuse:
            data = abuse.get("data", {})
            entry["feeds"]["AbuseIPDB"] = {
                "status": "ok",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", None),
            }
        else:
            entry["feeds"]["AbuseIPDB"] = {
                "status": NO_DATA,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "last_reported": None,
            }
    else:
        # OTX Domain
        otx_dom = _check_otx_domain(indicator)
        entry["feeds"]["AlienVault OTX"] = {
            "status": "ok" if otx_dom else NO_DATA,
            "pulse_count": otx_dom.get("pulse_info", {}).get("count", 0) if otx_dom else 0,
            "reputation": otx_dom.get("reputation", None) if otx_dom else None,
        }

    # URLhaus — Suitable for URLS and IPS
    urlhaus = _check_urlhaus(indicator)
    if urlhaus and urlhaus.get("query_status") == "ok":
        entry["feeds"]["URLhaus"] = {
            "status": "ok",
            "url_status": urlhaus.get("url_status", None),
            "threat": urlhaus.get("threat", None),
            "tags": urlhaus.get("tags", []),
            "first_seen": urlhaus.get("firstseen", None),
        }
    elif urlhaus and urlhaus.get("query_status") == "no_results":
        entry["feeds"]["URLhaus"] = {
            "status": "no_results",
            "url_status": None,
            "threat": None,
            "tags": [],
            "first_seen": None,
        }
    else:
        entry["feeds"]["URLhaus"] = {
            "status": NO_DATA,
            "url_status": None,
            "threat": None,
            "tags": [],
            "first_seen": None,
        }

    # ThreatFox — works for both IPs and domains (Malware IOCS)
    threatfox = _check_threatfox(indicator)
    if threatfox and threatfox.get("query_status") == "ok":
        iocs = threatfox.get("data", [])
        entry["feeds"]["ThreatFox"] = {
            "status": "ok",
            "ioc_count": len(iocs),
            "malware_families": list({ioc.get("malware", "unknown") for ioc in iocs if ioc.get("malware")}),
        }
    elif threatfox and threatfox.get("query_status") == "no_results":
        entry["feeds"]["ThreatFox"] = {
            "status": "no_results",
            "ioc_count": 0,
            "malware_families": [],
        }
    else:
        entry["feeds"]["ThreatFox"] = {
            "status": NO_DATA,
            "ioc_count": 0,
            "malware_families": [],
        }

    return entry


def correlate_threat_intel(pcap_data: dict) -> dict:
    """
    Take extracted PCAP data and correlate external IPs AND domains against
    four threat intelligence feeds.
    """
    # --- Collect IPs ---
    all_ips: set[str] = set()
    for ip, _ in pcap_data.get("src_ips", {}).most_common(200):
        if not is_private_ip(ip):
            all_ips.add(ip)
    for ip, _ in pcap_data.get("dst_ips", {}).most_common(200):
        if not is_private_ip(ip):
            all_ips.add(ip)

    # --- Collect domains from DNS queries and HTTP Host headers ---
    all_domains: set[str] = set()

    # DNS queries
    for qname in pcap_data.get("dns_queries", []):
        qname = qname.strip().rstrip(".")
        if qname and not is_private_ip(qname) and not is_benign_domain(qname):
            all_domains.add(qname)

    # HTTP Host headers
    for req in pcap_data.get("http_requests", []):
        host = req.get("host", "").strip().rstrip(".")
        if host and not is_private_ip(host) and not is_benign_domain(host):
            all_domains.add(host)

    # --- Correlate IPs and Domains in parallel ---
    # Build a list of (indicator, type) tuples for all indicators
    indicators: list[tuple[str, str]] = []
    for ip in sorted(all_ips):
        indicators.append((ip, "ip"))
    for domain in sorted(all_domains):
        indicators.append((domain, "domain"))

    ip_results: list[dict] = []
    domain_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_correlate_indicator, indicator, ind_type): (indicator, ind_type)
            for indicator, ind_type in indicators
        }
        for future in as_completed(futures):
            try:
                entry = future.result()
            except Exception:
                continue
            if not entry:
                continue
            indicator, ind_type = futures[future]
            if ind_type == "ip":
                ip_results.append(entry)
            else:
                domain_results.append(entry)

    def _has_hits(entry: dict) -> bool:
        """True if at least one feed returned actual data."""
        return any(
            feed.get("status") not in ("no_data",)
            for feed in entry.get("feeds", {}).values()
        )

    return {
        "total_ips_checked": len(all_ips),
        "ips_with_hits": sum(1 for e in ip_results if _has_hits(e)),
        "total_domains_checked": len(all_domains),
        "domains_with_hits": sum(1 for e in domain_results if _has_hits(e)),
        "ip_results": ip_results,
        "domain_results": domain_results,
    }


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_report(
    pcap_data: dict,
    threat_data: dict,
    intel_data: dict,
    log_lines: list[str] | None,
    output_path: str,
    pcap_path: str,
    log_path: str | None,
):
    """Generating a Markdown security report."""

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []

    # --- Title & Introduction ---
    lines.append(f"# Security Report — Threat Intelligence Automation")
    lines.append("")
    lines.append(f"**Generated:** {now_utc}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Introduction")
    lines.append("")
    lines.append(
        "This report presents the results of an automated security analysis "
        "performed on network traffic captures and (optionally) server log files. "
        "The goal is to identify suspicious or malicious activity by combining "
        "signature-based detection with threat intelligence correlation."
    )
    lines.append("")

    # --- Scope & Objective ---
    lines.append("## 2. Scope & Objective")
    lines.append("")
    lines.append(f"- **PCAP file analysed:** `{pcap_path}`")
    lines.append(f"  - Packets processed: {pcap_data.get('packet_count', 'N/A')}")
    http_req_count = len(pcap_data.get("http_requests", []))
    if http_req_count:
        lines.append(f"  - HTTP requests reconstructed from TCP streams: {http_req_count}")
    if log_path:
        lines.append(f"- **Log file analysed:** `{log_path}`")
        lines.append(f"  - Lines scanned: {len(log_lines) if log_lines else 0}")
    lines.append("- **Threat intelligence feeds queried:**")
    lines.append("  - AlienVault OTX")
    lines.append("  - AbuseIPDB")
    lines.append("  - URLhaus (Abuse.ch)")
    lines.append("  - ThreatFox (Abuse.ch)")
    lines.append("")

    # --- Findings: PCAP Summary ---
    lines.append("## 3. Findings")
    lines.append("")
    lines.append("### 3.1 PCAP — Network Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total packets | {pcap_data.get('packet_count', 0)} |")

    proto_counts = pcap_data.get("protocols", {})
    for proto, count in proto_counts.most_common():
        lines.append(f"| {proto} packets | {count} |")

    # Top IPs
    top_src = pcap_data.get("src_ips", Counter()).most_common(10)
    top_dst = pcap_data.get("dst_ips", Counter()).most_common(10)

    if top_src:
        lines.append("")
        lines.append("**Top 10 External Source IPs:**")
        lines.append("")
        lines.append("| IP Address | Packet Count |")
        lines.append("|------------|-------------|")
        for ip, cnt in top_src:
            if not is_private_ip(ip):
                lines.append(f"| {ip} | {cnt} |")

    if top_dst:
        lines.append("")
        lines.append("**Top 10 External Destination IPs:**")
        lines.append("")
        lines.append("| IP Address | Packet Count |")
        lines.append("|------------|-------------|")
        for ip, cnt in top_dst:
            if not is_private_ip(ip):
                lines.append(f"| {ip} | {cnt} |")

    # DNS
    dns = pcap_data.get("dns_queries", [])
    if dns:
        lines.append("")
        lines.append(f"**DNS Queries:** ({len(dns)} total)")
        lines.append("")
        uniq_dns = Counter(dns).most_common(20)
        for qname, cnt in uniq_dns:
            lines.append(f"- `{qname}` ({cnt}×)")

    # User-Agents
    uas = pcap_data.get("user_agents", [])
    if uas:
        lines.append("")
        lines.append(f"**User-Agent Strings Seen:** ({len(uas)} total)")
        lines.append("")
        for ua in sorted(set(uas))[:30]:
            lines.append(f"- `{ua}`")

    # --- Findings: Detected Threats ---
    lines.append("")
    lines.append("### 3.2 Detected Threats (Heuristic / Signature)")
    lines.append("")

    findings = threat_data.get("findings", [])
    if findings:
        lines.append(f"**{len(findings)} potential threat(s) identified.**")
        lines.append("")
        lines.append("| # | Type | Indicator | Source |")
        lines.append("|---|------|-----------|--------|")
        for i, f in enumerate(findings, 1):
            indicator = f["indicator"].replace("|", "\\|")[:120]
            lines.append(f"| {i} | {f['type']} | `{indicator}` | {f['source']} |")
    else:
        lines.append("*No heuristic threats detected in the provided data.*")

    # --- Findings: Threat Intelligence ---
    lines.append("")
    lines.append("### 3.3 Threat Intelligence Correlation")
    lines.append("")

    ip_results = intel_data.get("ip_results", [])
    domain_results = intel_data.get("domain_results", [])
    has_ip = bool(ip_results)
    has_domain = bool(domain_results)

    if has_ip or has_domain:
        lines.append(
            f"**IPs:** {intel_data.get('total_ips_checked', 0)} checked, "
            f"{intel_data.get('ips_with_hits', 0)} with matches.  "
            f"**Domains:** {intel_data.get('total_domains_checked', 0)} checked, "
            f"{intel_data.get('domains_with_hits', 0)} with matches."
        )
        lines.append("")

        if has_ip:
            lines.append("#### IP Matches")
            lines.append("")
            for entry in ip_results:
                ip = entry.get("ip", entry.get("domain", ""))
                lines.append(f"**IP:** `{ip}`")
                lines.append("")
                for feed_name, feed_data in entry["feeds"].items():
                    lines.append(f"- **{feed_name}:**")
                    for k, v in feed_data.items():
                        lines.append(f"  - {k}: `{v}`")
                lines.append("")

        if has_domain:
            lines.append("#### Domain Matches")
            lines.append("")
            for entry in domain_results:
                domain = entry.get("domain", "")
                lines.append(f"**Domain:** `{domain}`")
                lines.append("")
                for feed_name, feed_data in entry["feeds"].items():
                    lines.append(f"- **{feed_name}:**")
                    for k, v in feed_data.items():
                        lines.append(f"  - {k}: `{v}`")
                lines.append("")
    else:
        lines.append(
            "*No threat intelligence matches found for IPs or domains, "
            "or no API keys were configured to query feeds.*"
        )

    # --- Recommendations ---
    lines.append("## 4. Recommendations")
    lines.append("")

    ti_hits = (
        intel_data.get("ips_with_hits", 0)
        + intel_data.get("domains_with_hits", 0)
    )

    if findings or ti_hits:
        lines.append("Based on the findings above, the following actions are recommended:")
        lines.append("")
        if ti_hits:
            lines.append("1. **Investigate flagged indicators** — cross-reference IPs and "
                         "domains with threat intelligence matches against internal logs "
                         "and consider blocking at the firewall level.")
        else:
            lines.append("1. **Investigate suspicious IPs** — cross-reference flagged IPs "
                         "with internal logs and consider blocking at the firewall level.")
        lines.append("2. **Review detected tools/scanners** — User-Agent matches for tools "
                     "like sqlmap, nmap, or nikto indicate active reconnaissance or attack "
                     "attempts.")
        lines.append("3. **Validate DNS queries** — lookups to known-malicious or "
                     "suspicious domains should be investigated for potential C2 communication.")
        lines.append("4. **Quarantine suspicious files** — any files with dangerous "
                     "extensions transferred over the network should be isolated and "
                     "submitted for deeper malware analysis.")
        lines.append("5. **Harden detection rules** — add the identified IoCs to your "
                     "SIEM, IDS/IPS, and firewall blocklists.")
    else:
        lines.append("- No immediate threats detected.  Continue routine monitoring.")
    lines.append("")

    # --- References ---
    lines.append("## 5. References — Threat Intelligence Feeds Used")
    lines.append("")
    lines.append("| Feed | URL | API Required |")
    lines.append("|------|-----|:------------:|")
    lines.append("| AlienVault OTX | https://otx.alienvault.com/ | Yes (free) |")
    lines.append("| AbuseIPDB | https://www.abuseipdb.com/ | Yes (free tier) |")
    lines.append("| URLhaus (Abuse.ch) | https://urlhaus.abuse.ch/ | Yes (free) |")
    lines.append("| ThreatFox (Abuse.ch) | https://threatfox.abuse.ch/ | Yes (free) |")
    lines.append("")

    # --- Conclusion ---
    lines.append("## 6. Conclusion")
    lines.append("")
    lines.append(
        "The automated analysis pipeline combined PCAP extraction, heuristic threat "
        "detection, and multi-feed threat intelligence correlation to provide a "
        "holistic view of the network traffic.  Any indicators flagged above should "
        "be triaged by the security operations team.  This report was generated "
        "programmatically and should be regenerated after remediation steps have been "
        "taken to verify their effectiveness."
    )
    lines.append("")

    # Write
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Automation — PCAP analysis & TI correlation"
    )
    parser.add_argument(
        "--pcap", required=True, help="Path to the PCAP file to analyze."
    )
    parser.add_argument(
        "--log", default=None,
        help="(Optional) Path to a log file for additional threat scanning. "
             "HTTP requests are already reconstructed from the PCAP automatically."
    )
    parser.add_argument(
        "--output", default="security_report.md", help="Output Markdown report path."
    )
    parser.add_argument(
        "--skip-ti", action="store_true",
        help="Skip threat-intelligence API queries (offline mode)."
    )
    args = parser.parse_args()

    # Validate PCAP
    if not os.path.isfile(args.pcap):
        print(f"[!] PCAP file not found: {args.pcap}")
        sys.exit(1)

    # Load optional log
    log_lines = None
    if args.log:
        if os.path.isfile(args.log):
            with open(args.log, "r", encoding="utf-8", errors="ignore") as f:
                log_lines = f.readlines()
        else:
            print(f"[!] Log file not found: {args.log}")
            sys.exit(1)

    print("[*] Analyzing PCAP …")
    pcap_data = analyze_pcap(args.pcap)
    if "error" in pcap_data:
        print(f"[!] {pcap_data['error']}")
        sys.exit(1)

    print(f"     {pcap_data['packet_count']} packets processed")
    print(f"     {len(pcap_data['src_ips'])} unique source IPs")
    print(f"     {len(pcap_data['dst_ips'])} unique destination IPs")
    print(f"     {len(pcap_data['dns_queries'])} DNS queries extracted")
    print(f"     {len(pcap_data['user_agents'])} User-Agent strings found")
    print(f"     {len(pcap_data['http_requests'])} HTTP requests reconstructed")

    # Convert reconstructed HTTP requests into log-like lines for threat scanning
    pcap_log_lines: list[str] = []
    for req in pcap_data.get("http_requests", []):
        line = f'{req["method"]} {req["uri"]} HTTP/{req["http_version"]}'
        if req["host"]:
            line += f'  Host: {req["host"]}'
        if req["user_agent"]:
            line += f'  User-Agent: {req["user_agent"]}'
        pcap_log_lines.append(line)

    # Merge: --log lines (if any) + PCAP-reconstructed HTTP lines
    all_log_lines = (log_lines or []) + pcap_log_lines
    if not all_log_lines:
        all_log_lines = None  # keep None so detect_threats can skip log scanning

    print("[*] Running heuristic threat detection …")
    threat_data = detect_threats(pcap_data, all_log_lines)
    print(f"     {threat_data['total_findings']} potential threats found")

    intel_data = {}
    if args.skip_ti:
        print("[*] Skipping threat intelligence correlation (--skip-ti)")
        intel_data = {"total_ips_checked": 0, "ips_with_hits": 0,
                       "total_domains_checked": 0, "domains_with_hits": 0,
                       "ip_results": [], "domain_results": []}
    else:
        print("[*] Correlating with threat intelligence feeds …")
        if not HAS_REQUESTS:
            print("     [!] 'requests' not installed; skipping TI.  pip install requests")
            intel_data = {"total_ips_checked": 0, "ips_with_hits": 0,
                           "total_domains_checked": 0, "domains_with_hits": 0,
                           "ip_results": [], "domain_results": []}
        else:
            intel_data = correlate_threat_intel(pcap_data)
            print(f"     {intel_data['total_ips_checked']} IPs checked "
                  f"({intel_data['ips_with_hits']} hits), "
                  f"{intel_data['total_domains_checked']} domains checked "
                  f"({intel_data['domains_with_hits']} hits)")

    print(f"[*] Generating report → {args.output}")
    generate_report(
        pcap_data=pcap_data,
        threat_data=threat_data,
        intel_data=intel_data,
        log_lines=log_lines,
        output_path=args.output,
        pcap_path=args.pcap,
        log_path=args.log,
    )

    print(f"[✓] Report written to {args.output}")


if __name__ == "__main__":
    main()
