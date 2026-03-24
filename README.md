# soc-analyst-lab

# SOC Analyst Home Lab

A hands-on security operations lab built from scratch to simulate real-world SOC analyst workflows including phishing detection, log triage, threat hunting, and incident response.

## Lab Environment

| Component | Technology |
|-----------|-----------|
| SIEM | Splunk Enterprise |
| Endpoint Telemetry | Sysmon (SwiftOnSecurity config) |
| Host OS | CachyOS Linux |
| Windows VM | Windows 10 (VirtualBox) |
| Phishing Simulation | GoPhish |
| IDS | Suricata (BOTS dataset) |
| Threat Intel | VirusTotal, AbuseIPDB |

## Skills Demonstrated

- Splunk deployment, configuration, and pipeline administration
- SPL query writing, field extraction, and correlation search development
- Windows Event Log and Sysmon analysis
- Phishing simulation and credential harvesting detection
- Persistence and lateral movement simulation and detection
- MySQL transaction log analysis for SQL injection detection
- Palo Alto firewall log parsing and threat analysis
- Suricata IDS alert analysis and correlation
- osquery endpoint telemetry analysis on macOS
- Hex to decimal IP conversion and IOC enrichment
- Threat intelligence enrichment using VirusTotal and AbuseIPDB
- Independent threat hunting using real-world attack datasets
- Structured incident reporting with MITRE ATT&CK mapping
- Cross-source log correlation across SIEM, IDS, firewall, and endpoint data

## Detection Rules

| Alert | Technique | MITRE ID |
|-------|-----------|----------|
| Office application spawning PowerShell | Phishing payload execution | T1566 |
| Scheduled task with PowerShell command | Persistence | T1053.005 |
| Registry run key with PowerShell | Persistence | T1547.001 |
| Explicit credential lateral movement | Lateral Movement | T1021.006 |

## Incident Reports

| Report | Scenario | Severity |
|--------|----------|----------|
| [IR-2026-001](incidents/IR-2026-001.md) | Phishing simulation and credential harvesting | Medium |
| [IR-2026-002](incidents/IR-2026-002.md) | Scheduled task persistence and brute force | High |
| [IR-2026-003](incidents/IR-2026-003.md) | Registry persistence and lateral movement | High |
| [IR-2026-004](incidents/IR-2026-004.md) | Cerber ransomware infection — BOTS v1 dataset | Critical |
| [IR-2026-005](incidents/IR-2026-005.md) | Web application attack and data exfiltration — BOTS v2 | Critical |

## Threat Hunting

Independent investigation of the Splunk BOTS v1 dataset identifying a Cerber ransomware infection through anomaly detection, network traffic analysis, and Suricata IDS correlation. Full methodology documented in IR-2026-004.

## MITRE ATT&CK Coverage

- T1566 — Phishing
- T1056 — Input Capture
- T1078 — Valid Accounts
- T1053.005 — Scheduled Task
- T1110 — Brute Force
- T1547.001 — Registry Run Keys
- T1059.001 — PowerShell
- T1021.006 — Windows Remote Management
- T1036 — Masquerading
- T1189 — Drive-by Compromise
- T1486 — Data Encrypted for Impact
- T1090.003 — Multi-hop Proxy (Tor)
- T1071 — Application Layer Protocol
- T1046 — Network Service Scanning
- T1190 — Exploit Public Facing Application
- T1203 — Exploitation for Client Execution
- T1543 — Create or Modify System Process
- T1048 — Exfiltration Over Alternative Protocol
- T1595 — Active Scanning
- T1592 — Gather Victim Host Information
