# Threat Hunting: Tor Browser Detection

## Summary

Conducted a hypothesis-driven threat hunt to identify unauthorized Tor Browser usage across endpoint telemetry. Built detection queries in KQL and SPL, documented the full hunting workflow from hypothesis formation through confirmed findings, and produced an incident report with remediation recommendations. This project demonstrates proactive threat hunting methodology aligned to MITRE ATT&CK.

## Technologies Used

- Microsoft Sentinel / Log Analytics
- Kusto Query Language (KQL)
- Splunk (SPL queries)
- Windows Event Logs (Sysmon, Security)
- MITRE ATT&CK Framework
- VirusTotal / OSINT tools

## Threat Hunting Methodology

```
┌──────────────────┐
│  1. HYPOTHESIS    │  "An insider is using Tor Browser to bypass network controls"
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  2. DATA SOURCES  │  Sysmon (Process Creation, Network), DNS logs, Proxy logs
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  3. HUNT QUERIES  │  KQL/SPL queries for Tor artifacts
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  4. ANALYSIS      │  Correlate findings, eliminate false positives
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  5. FINDINGS      │  Confirmed Tor usage on 1 endpoint
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  6. REPORT        │  Incident report + detection rule deployment
└──────────────────┘
```

## Walkthrough

### Step 1: Hypothesis Formation

**Hypothesis:** An employee or insider is using Tor Browser on a corporate endpoint to bypass web filtering and exfiltrate data or access restricted content.

**Rationale:** Tor Browser is commonly used to evade network monitoring. Its presence on a corporate endpoint is almost always a policy violation and potentially indicative of malicious activity.

**MITRE ATT&CK Mapping:**
- T1090.003 — Proxy: Multi-hop Proxy
- T1071.001 — Application Layer Protocol: Web Protocols
- T1048 — Exfiltration Over Alternative Protocol

### Step 2: Identify Data Sources

| Data Source | What It Reveals |
|---|---|
| Sysmon Event ID 1 (Process Creation) | Tor Browser executable launches (tor.exe, firefox.exe from Tor directory) |
| Sysmon Event ID 3 (Network Connection) | Connections to known Tor entry/guard nodes |
| DNS Logs | DNS queries for .onion-related infrastructure |
| Proxy/Firewall Logs | Blocked or allowed connections to Tor relay IPs |
| File System Audit | Tor Browser bundle files on disk |

### Step 3: Detection Queries

**KQL — Tor Process Detection**
```kql
DeviceProcessEvents
| where FileName in~ ("tor.exe", "tor-browser.exe")
    or (FileName == "firefox.exe" and FolderPath has "Tor Browser")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

**KQL — Connections to Known Tor Nodes**
```kql
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9050, 9051, 9150)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

**KQL — Tor-Related File Artifacts**
```kql
DeviceFileEvents
| where FileName has_any ("tor.exe", "torrc", "tor-browser", "pluggable_transports")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
| order by Timestamp desc
```

**SPL — Tor Detection in Splunk**
```spl
index=sysmon EventCode=1 
(Image="*\\tor.exe" OR Image="*\\Tor Browser\\*" OR CommandLine="*tor*")
| stats count by Computer, User, Image, CommandLine, _time
| sort -_time
```

**SPL — Network Connections to Tor Ports**
```spl
index=sysmon EventCode=3 
(DestinationPort=9001 OR DestinationPort=9030 OR DestinationPort=9050 OR DestinationPort=9150)
| stats count by Computer, User, DestinationIp, DestinationPort, Image
| sort -count
```

### Step 4: Analysis and Correlation

Executed hunting queries across 30 days of endpoint telemetry. Findings were correlated across multiple data sources:

1. **Process Creation logs** confirmed `tor.exe` execution on one workstation
2. **Network logs** showed outbound connections on port 9001 to known Tor relay IPs
3. **File system audit** revealed the full Tor Browser bundle installed in the user's AppData directory
4. **DNS logs** showed no .onion queries (expected — Tor handles DNS internally)
5. **Cross-referenced** Tor relay IPs against public Tor node lists via OSINT

### Step 5: Findings

| Finding | Detail |
|---|---|
| Affected endpoint | WORKSTATION-PC07 |
| User account | jsmith (standard user) |
| First observed | Day 12 of hunting window |
| Tor Browser version | 12.5.x (installed in %AppData%) |
| Network activity | 47 connections to Tor relays over 5 days |
| Data exfiltration indicators | No confirmed exfil, but 2.3 GB transferred over Tor |
| Policy violation | Yes — unauthorized software, bypass of web filtering |

### Step 6: Incident Report

**Severity:** Medium (Policy Violation + Potential Data Exfiltration)

**Summary:** Unauthorized Tor Browser installation and usage detected on WORKSTATION-PC07 by user jsmith. The software was used to bypass corporate web filtering over a 5-day period with 2.3 GB of data transferred through Tor circuits.

**Recommendations:**
1. Escalate to HR and the user's manager for policy enforcement
2. Conduct forensic imaging of the endpoint for further analysis
3. Review DLP logs for any sensitive data access during the Tor usage window
4. Deploy the detection queries as persistent analytics rules in Sentinel
5. Add Tor relay IPs to the firewall block list
6. Update the Acceptable Use Policy to explicitly prohibit anonymization tools

## Results

| Metric | Value |
|---|---|
| Hunting window | 30 days |
| Endpoints analyzed | 150+ |
| True positive findings | 1 confirmed Tor installation |
| Detection queries created | 5 (3 KQL, 2 SPL) |
| Time from hypothesis to finding | 4 hours |
| Outcome | Incident escalated, detection rules deployed |

## What I Learned

This hunt reinforced that proactive threat hunting is fundamentally different from reactive alert triage. Starting with a hypothesis and methodically working through data sources reveals activity that signature-based detection would miss entirely — the Tor Browser installation never triggered an existing alert because it wasn't flagged as malware.

The most important lesson was the value of correlating across multiple data sources. Process creation logs alone could produce false positives, but when combined with network connection data and file system artifacts, the confidence level jumps significantly. This multi-source correlation approach is what separates effective threat hunting from simple log searching.
