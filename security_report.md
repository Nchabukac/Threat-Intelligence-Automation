# Security Report — Threat Intelligence Automation

**Generated:** 2026-07-02 12:54:25 UTC

---

## 1. Introduction

This report presents the results of an automated security analysis performed on network traffic captures and (optionally) server log files. The goal is to identify suspicious or malicious activity by combining signature-based detection with threat intelligence correlation.

## 2. Scope & Objective

- **PCAP file analysed:** `2026-02-28-traffic-analysis-exercise.pcap`
  - Packets processed: 15512
  - HTTP requests reconstructed from TCP streams: 317
- **Threat intelligence feeds queried:**
  - AlienVault OTX
  - AbuseIPDB
  - URLhaus (Abuse.ch)
  - ThreatFox (Abuse.ch)

## 3. Findings

### 3.1 PCAP — Network Summary

| Metric | Value |
|--------|-------|
| Total packets | 15512 |
| TCP packets | 12544 |
| UDP packets | 2113 |
| Other packets | 855 |

**Top 10 External Source IPs:**

| IP Address | Packet Count |
|------------|-------------|
| 23.64.147.24 | 823 |
| 23.218.232.148 | 743 |
| 45.131.214.85 | 274 |
| 150.171.28.11 | 256 |
| 23.192.223.23 | 176 |
| 23.41.251.53 | 143 |
| 104.208.203.89 | 140 |
| 23.192.223.16 | 135 |
| 23.205.110.136 | 132 |
| 23.64.115.206 | 92 |

**Top 10 External Destination IPs:**

| IP Address | Packet Count |
|------------|-------------|
| 23.64.147.24 | 445 |
| 23.218.232.148 | 387 |
| 45.131.214.85 | 276 |
| 150.171.28.11 | 219 |
| 23.192.223.23 | 178 |
| 104.208.203.89 | 162 |
| 23.41.251.53 | 124 |
| 23.192.223.16 | 99 |
| 150.171.27.11 | 72 |
| 23.192.223.17 | 70 |

**DNS Queries:** (446 total)

- `wpad.mshome.net` (79×)
- `wpad.easyas123.tech` (78×)
- `login.microsoftonline.com` (31×)
- `edge.microsoft.com` (30×)
- `settings-win.data.microsoft.com` (25×)
- `v10.events.data.microsoft.com` (22×)
- `windows.msn.com` (12×)
- `www.msn.com` (11×)
- `_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech` (10×)
- `www.bing.com` (10×)
- `self.events.data.microsoft.com` (9×)
- `assets.msn.com` (8×)
- `msedge.b.tlu.dl.delivery.mp.microsoft.com` (8×)
- `ecs.office.com` (7×)
- `odc.officeapps.live.com` (6×)
- `th.bing.com` (6×)
- `ctldl.windowsupdate.com` (6×)
- `EASYAS123-DC.easyas123.tech` (6×)
- `_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net` (5×)
- `mobile.events.data.microsoft.com` (5×)

**User-Agent Strings Seen:** (634 total)

- `Microsoft BITS/7.8`
- `Microsoft NCSI`
- `Microsoft-CryptoAPI/10.0`
- `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)`
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0`
- `NetSupport Manager/1.3`

### 3.2 Detected Threats (Heuristic / Signature)

*No heuristic threats detected in the provided data.*

### 3.3 Threat Intelligence Correlation

**IPs:** 98 checked, 98 with matches.  **Domains:** 1 checked, 1 with matches.

#### IP Matches

**IP:** `13.89.179.8`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `12`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `27`
  - total_reports: `38`
  - last_reported: `2026-06-30T15:18:19+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.70.79.200`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `3`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `28`
  - total_reports: `27`
  - last_reported: `2026-07-02T07:30:55+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.107.246.57`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `31`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-09-30T11:41:36+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.89.179.13`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `16`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `27`
  - total_reports: `32`
  - last_reported: `2026-07-01T19:26:09+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.89.179.14`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `24`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `23`
  - total_reports: `38`
  - last_reported: `2026-07-02T08:16:59+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.89.178.27`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `23`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `19`
  - total_reports: `41`
  - last_reported: `2026-07-01T19:17:51+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.107.213.57`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `7`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2023-06-05T14:21:29+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.69.116.109`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `7`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `18`
  - total_reports: `12`
  - last_reported: `2026-07-01T18:54:40+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `104.46.162.224`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `15`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `25`
  - total_reports: `18`
  - last_reported: `2026-07-02T05:35:10+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `13.89.179.9`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `28`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `27`
  - total_reports: `38`
  - last_reported: `2026-06-30T16:03:51+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `142.250.138.94`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `4`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-10-14T15:19:44+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `135.234.160.246`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `6`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `11`
  - total_reports: `6`
  - last_reported: `2026-06-17T00:04:18+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `150.171.28.12`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `1`
  - total_reports: `1`
  - last_reported: `2026-06-04T17:37:25+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `150.171.28.11`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `22`
  - total_reports: `7`
  - last_reported: `2026-06-26T13:48:54+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `150.171.22.17`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `12`
  - total_reports: `4`
  - last_reported: `2026-06-03T08:18:22+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `150.171.27.11`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `24`
  - total_reports: `21`
  - last_reported: `2026-06-29T01:17:25+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `150.171.27.12`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `5`
  - total_reports: `4`
  - last_reported: `2026-06-30T16:36:09+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.189.173.1`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `28`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `24`
  - last_reported: `2026-05-31T06:00:37+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.106.86.13`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `3`
  - last_reported: `2026-05-06T14:03:04+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.189.173.2`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `13`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `19`
  - total_reports: `34`
  - last_reported: `2026-07-02T09:53:02+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.189.173.8`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `16`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `16`
  - total_reports: `18`
  - last_reported: `2026-06-01T03:30:09+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.135.16`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `37`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `17`
  - total_reports: `117`
  - last_reported: `2026-07-02T12:07:48+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.189.173.14`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `13`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `14`
  - last_reported: `2026-05-29T05:30:25+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.135.7`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `17`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `113`
  - last_reported: `2026-07-02T04:52:13+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.135.4`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `39`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `7`
  - total_reports: `114`
  - last_reported: `2026-07-02T00:49:06+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.157.14`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `37`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `113`
  - last_reported: `2026-07-02T06:01:10+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.135.3`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `26`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `17`
  - total_reports: `114`
  - last_reported: `2026-07-01T21:12:36+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `199.232.210.172`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `22`
  - last_reported: `2026-06-28T06:16:43+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.157.4`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `38`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `15`
  - total_reports: `117`
  - last_reported: `2026-07-02T00:05:13+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `184.29.31.84`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `4`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.42.65.84`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `21`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `24`
  - total_reports: `37`
  - last_reported: `2026-07-01T22:20:25+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.42.65.88`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `16`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `23`
  - total_reports: `34`
  - last_reported: `2026-07-01T17:51:06+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.190.157.9`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `109`
  - last_reported: `2026-07-02T05:35:16+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.42.73.30`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `1`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `27`
  - total_reports: `41`
  - last_reported: `2026-06-30T03:37:44+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.49.150.241`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `3`
  - last_reported: `2026-04-29T14:02:20+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.96.153.111`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `43`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2026-04-03T03:41:22+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.72.205.209`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `1`
  - last_reported: `2026-04-24T00:49:06+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `224.0.0.252`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `4`
  - last_reported: `2026-05-29T15:50:28+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.192.223.16`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `104.208.203.89`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `2`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `3`
  - total_reports: `4`
  - last_reported: `2026-07-01T15:31:57+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `204.79.197.203`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `24`
  - total_reports: `47`
  - last_reported: `2026-06-28T23:40:56+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `224.0.0.251`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-05-08T04:49:16+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.192.223.23`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `20.42.65.94`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `9`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `25`
  - total_reports: `36`
  - last_reported: `2026-06-30T21:08:49+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.192.223.5`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.192.223.17`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `4`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.142`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.136`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `3`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.145`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `9`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.151`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `6`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.140`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `5`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.205.110.155`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `8`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.213.232.101`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.142`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-08-25T22:53:19+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.213.232.198`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.148`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `19`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.156`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.166`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-02-27T19:05:03+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.170`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.161`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `20`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.174`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `1`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.41.251.53`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.55.178.219`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.47.50.182`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.64.115.206`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.64.147.24`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `239.255.255.250`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `1`
  - last_reported: `2026-05-28T01:50:05+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.60.174.202`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `2`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `4.149.160.182`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2026-03-10T16:53:44+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.119.249.228`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2026-04-02T00:37:18+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.28.12`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `110`
  - last_reported: `2026-07-02T12:28:16+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.29.10`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `7`
  - total_reports: `109`
  - last_reported: `2026-07-02T07:00:15+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.29.15`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `113`
  - last_reported: `2026-07-02T07:37:35+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.28.13`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `116`
  - last_reported: `2026-07-02T09:54:30+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.29.9`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `15`
  - total_reports: `115`
  - last_reported: `2026-07-02T00:03:28+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `45.131.214.85`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `ok`
  - ioc_count: `1`
  - malware_families: `['win.netsupportmanager_rat']`

**IP:** `40.126.29.5`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `15`
  - total_reports: `116`
  - last_reported: `2026-07-02T07:50:03+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `40.126.29.13`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `8`
  - total_reports: `121`
  - last_reported: `2026-07-02T08:28:40+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `51.105.71.136`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `17`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `14`
  - total_reports: `26`
  - last_reported: `2026-07-01T18:09:45+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `51.105.71.137`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `13`
  - total_reports: `28`
  - last_reported: `2026-06-06T18:32:58+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.218.232.183`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `51.116.246.106`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `8`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `16`
  - total_reports: `17`
  - last_reported: `2026-06-22T16:43:36+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.110.6.19`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `8`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `51.11.168.232`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `1`
  - last_reported: `2026-04-24T00:49:06+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.110.6.37`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `3`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.55.178.208`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.110.6.45`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.110.6.48`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `3`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.123.246.74`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `0`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.123.250.16`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `1`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.123.129.14`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `42`
  - total_reports: `218`
  - last_reported: `2026-06-30T04:40:03+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.123.250.27`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `16`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.167.17.97`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `1`
  - last_reported: `2026-04-27T02:58:27+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.137.106.217`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2026-02-10T02:01:41+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.183.220.149`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `2`
  - last_reported: `2026-05-06T14:03:04+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.168.112.67`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `14`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `15`
  - total_reports: `36`
  - last_reported: `2026-07-01T19:20:49+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `52.185.211.133`

- **AlienVault OTX:**
  - status: `ok`
  - pulse_count: `50`
  - reputation: `0`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `3`
  - last_reported: `2026-05-06T14:03:04+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

**IP:** `23.204.150.28`

- **AlienVault OTX:**
  - status: `no_data`
  - pulse_count: `0`
  - reputation: `None`
- **AbuseIPDB:**
  - status: `ok`
  - abuse_confidence_score: `0`
  - total_reports: `0`
  - last_reported: `2025-06-14T03:50:33+00:00`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `no_data`
  - ioc_count: `0`
  - malware_families: `[]`

#### Domain Matches

**Domain:** `45.131.214.85`

- **AlienVault OTX:**
  - status: `no_data`
  - pulse_count: `0`
  - reputation: `None`
- **URLhaus:**
  - status: `no_data`
  - url_status: `None`
  - threat: `None`
  - tags: `[]`
  - first_seen: `None`
- **ThreatFox:**
  - status: `ok`
  - ioc_count: `1`
  - malware_families: `['win.netsupportmanager_rat']`

## 4. Recommendations

Based on the findings above, the following actions are recommended:

1. **Investigate flagged indicators** — cross-reference IPs and domains with threat intelligence matches against internal logs and consider blocking at the firewall level.
2. **Review detected tools/scanners** — User-Agent matches for tools like sqlmap, nmap, or nikto indicate active reconnaissance or attack attempts.
3. **Validate DNS queries** — lookups to known-malicious or suspicious domains should be investigated for potential C2 communication.
4. **Quarantine suspicious files** — any files with dangerous extensions transferred over the network should be isolated and submitted for deeper malware analysis.
5. **Harden detection rules** — add the identified IoCs to your SIEM, IDS/IPS, and firewall blocklists.

## 5. References — Threat Intelligence Feeds Used

| Feed | URL | API Required |
|------|-----|:------------:|
| AlienVault OTX | https://otx.alienvault.com/ | Yes (free) |
| AbuseIPDB | https://www.abuseipdb.com/ | Yes (free tier) |
| URLhaus (Abuse.ch) | https://urlhaus.abuse.ch/ | Yes (free) |
| ThreatFox (Abuse.ch) | https://threatfox.abuse.ch/ | Yes (free) |

## 6. Conclusion

The automated analysis pipeline combined PCAP extraction, heuristic threat detection, and multi-feed threat intelligence correlation to provide a holistic view of the network traffic.  Any indicators flagged above should be triaged by the security operations team.  This report was generated programmatically and should be regenerated after remediation steps have been taken to verify their effectiveness.
