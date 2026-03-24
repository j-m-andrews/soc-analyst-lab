# Threat Hunting — BOTS v2 Dataset Investigation

## Scenario
Frothly Inc. has been targeted by an attacker. Identify the affected systems, attack vector, and any malicious activity.

## Methodology

### Step 1 — Establish Baseline
Identify all hosts and event volumes to find anomalies.
```spl
index=botsv2 | stats count by host, source | sort -count
```

**Finding:** MACLORY-AIR13, cassiopeia, and growler showed the highest event volumes warranting further investigation.

### Step 2 — Identify Available Data Sources
Understand what log sources are available for investigation.
```spl
index=botsv2 | stats count by sourcetype | sort -count
```

**Finding:** Rich dataset including MySQL transactions, Palo Alto firewall, Suricata IDS, stream data, and Windows event logs.

### Step 3 — MySQL Transaction Analysis
Investigate anomalous database activity on cassiopeia.
```spl
index=botsv2 sourcetype="mysql:transaction:details" ("SLEEP" OR "BENCHMARK") 
| stats count by SQL_TEXT | sort -count
```

**Finding:** Time-based blind SQL injection attacks using `SLEEP(12)` payloads targeting the MyBB forum search function. Shellshock exploit attempted via User-Agent header.

### Step 4 — Attacker Identification
Extract and decode attacker IP from MySQL session data.

**Finding:** Attacker IP `2d4d41d3` (hex) decoded to `45.77.65.211` — Vultr VPS, Frankfurt Germany. Tool identified as w3af via User-Agent string.

### Step 5 — IDS Correlation
Pivot to Suricata for additional attack signatures.
```spl
index=botsv2 sourcetype="suricata" ("Quimitchin" OR "TOR") 
| stats count by src_ip, dest_ip, alert.signature | sort -count
```

**Finding:** Quimitchin Mac backdoor DNS lookup detected. Sustained Tor relay C2 communication from internal host `10.0.2.101`.

### Step 6 — Firewall Log Analysis
Pivot to Palo Alto firewall for threat and traffic data.
```spl
index=botsv2 host="growler" sourcetype="pan:threat" | head 10
```

**Finding — Smoking Gun:**
- Malicious PDF `American Microbrewery Ale #1.pdf` delivered via FTP exploiting Adobe Reader vulnerability — Critical severity
- Exfiltration attempt — `topsecretyeast.pdf` sent via FTP to `160.153.91.7` (GoDaddy, Phoenix AZ)
- Compromised user: `frothly\billy.tun`
- Exfiltration blocked by Palo Alto firewall

## Conclusion

Frothly Inc. was targeted in a corporate espionage operation. The attacker exploited a SQL injection vulnerability in the MyBB forum, delivered a malicious PDF to user `billy.tun`, deployed a Mac backdoor, used Tor for C2 communication, and attempted to exfiltrate proprietary brewery recipe data. The Palo Alto firewall blocked the final exfiltration attempt.

## Key Investigative Pivots

| Step | Data Source | Finding |
|------|------------|---------|
| 1 | Host baseline | MACLORY-AIR13 and cassiopeia anomalous |
| 2 | Sourcetype analysis | MySQL, Palo Alto, Suricata available |
| 3 | MySQL transactions | SQL injection SLEEP payloads confirmed |
| 4 | IP decoding | Attacker at 45.77.65.211 — Vultr VPS |
| 5 | Suricata IDS | Quimitchin backdoor and Tor C2 confirmed |
| 6 | Palo Alto firewall | Malicious PDF delivery and exfiltration attempt |

## Lessons Learned

- MySQL transaction logs are a valuable source for detecting SQL injection
- Palo Alto firewall pan:threat logs provide high fidelity threat detection
- Hex encoded IPs in logs require manual or tool-assisted decoding
- Corporate espionage attacks often target specific high value data
- Firewall blocks don't mean the attacker failed — earlier stages may have succeeded
- Cross-source correlation across database, IDS, and firewall logs reveals the full attack chain

## Full Incident Report
See [IR-2026-005](../incidents/IR-2026-005.md)
