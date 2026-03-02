# Threat Hunting — BOTS v1 Dataset Investigation

## Scenario
A workstation on the network appears to have been compromised via a web-based attack. Identify the affected host, the attack vector, and any malware activity.

## Methodology

### Step 1 — Establish Baseline
Start broad. Identify all hosts and their event volumes to find anomalies.
```spl
index=botsv1 | stats count by host | sort -count
```

**Finding:** `we9748srv` (192.168.250.100) showed significantly higher event volume than comparable workstations — immediate red flag.

### Step 2 — Temporal Analysis
Determine if the anomalous volume was sustained or a spike.
```spl
index=botsv1 host="we9748srv" | timechart count
```

**Finding:** Sustained elevated activity from August 1–28, 2016 — consistent with persistent malware infection rather than a one-time event.

### Step 3 — Log Source Analysis
Identify which log sources were generating the anomalous volume.
```spl
index=botsv1 host="we9748srv" earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:59" 
| stats count by sourcetype
```

**Finding:** 146,421 Security log events dominated — abnormal for a standard workstation.

### Step 4 — EventCode Analysis
Identify which specific events were driving the Security log volume.
```spl
index=botsv1 host="we9748srv" source="WinEventLog:Security" 
earliest="08/01/2016:00:00:00" latest="08/28/2016:23:59:59" 
| stats count by EventCode | sort -count
```

**Finding:** 
- 44,453 EventCode 4703 (token right adjustments) — abnormal
- 37,905 EventCode 4688 (process creation) — consistent with automated malware execution

### Step 5 — Network Connection Analysis
Investigate external connections from the host using Sysmon EventCode 3.
```spl
index=botsv1 host="we9748srv" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
"<EventID>3</EventID>" 
| rex "Name='DestinationIp'>(?<DestinationIp>[^<]+)<" 
| rex "Name='DestinationPort'>(?<DestinationPort>[^<]+)<" 
| search DestinationIp!=192.168.250.* DestinationIp!=239.255.255.250 DestinationIp!=127.0.0.1 
| stats count by DestinationIp, DestinationPort | sort -count
```

**Finding:** Mostly port 443 traffic to Microsoft/CDN infrastructure. No conclusive C2 identified from network connections alone — pivoted to IDS data.

### Step 6 — IDS Correlation
Pivot to Suricata IDS alerts for the affected host IP.
```spl
index=botsv1 host="suricata-ids.waynecorpinc.local" "192.168.250.100" 
sourcetype="suricata" 
| stats count by alert.signature | sort -count
```

**Finding — Smoking Gun:**
- ETPRO TROJAN Ransomware/Cerber Checkin
- ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup
- ET TOR Known Tor Relay Traffic (22 hits)
- ET SCAN Unusual Port 445 — internal network scanning

## Conclusion

Host `we9748srv` was confirmed infected with **Cerber ransomware**. The malware established C2 communication via Tor hidden services to evade detection and scanned the internal network on port 445 for lateral movement targets.

## Key Investigative Pivots

| Step | Data Source | Finding |
|------|------------|---------|
| 1 | All hosts | Anomalous event volume on we9748srv |
| 2 | Timechart | Sustained 4-week infection period |
| 3 | Sourcetype analysis | Security log domination |
| 4 | EventCode analysis | Massive process creation activity |
| 5 | Sysmon EventCode 3 | External connections — inconclusive |
| 6 | Suricata IDS | Cerber ransomware confirmed |

## Lessons Learned

- Always start broad and narrow down — don't assume the attack vector
- Event volume anomalies are a reliable first indicator
- Network connection analysis alone may not identify C2 if traffic blends with legitimate services
- IDS correlation is the fastest path to confirmed malware identification
- Pivoting between data sources is the core skill of effective threat hunting

## Full Incident Report
See [IR-2026-004](../incidents/IR-2026-004.md)
