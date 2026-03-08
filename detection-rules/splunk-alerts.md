# Splunk Detection Rules

Detection alerts built and validated in Splunk Enterprise as part of the SOC analyst home lab.

## Alert 1 — Office Application Spawning PowerShell

**Technique:** T1566 — Phishing payload execution  
**Severity:** High
```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" 
Image="*powershell.exe"
```

## Alert 2 — Scheduled Task with PowerShell Command

**Technique:** T1053.005 — Scheduled Task Persistence  
**Severity:** High
```spl
index=* source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s+(?<TaskName>[^\n]+)"
| rex field=Message "Command>(?<Command>[^<]+)"
| search Command="*powershell*"
| table _time, TaskName, Command
```

## Alert 3 — Suspicious Registry Run Key with PowerShell

**Technique:** T1547.001 — Registry Run Keys  
**Severity:** High
```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
TargetObject="*CurrentVersion\\Run*" Details="*powershell*"
| table _time, TargetObject, Details, Image
```

## Alert 4 — Explicit Credential Lateral Movement

**Technique:** T1021.006 — Windows Remote Management  
**Severity:** High
```spl
index=* source="WinEventLog:Security" EventCode=4648
Account_Name=* Target_Server_Name=*
| where Account_Name!="WINDOWS$"
| table _time, Account_Name, Target_Server_Name, Process_Name
```

## Alert 5 — Multi-Technique Attack Chain Detection

**Technique:** Multiple  
**Severity:** Critical  
**Description:** Detects hosts triggering two or more suspicious techniques within the same time window — high confidence attack chain indicator.
```spl
index=* (EventCode=4698 OR EventCode=4648 OR EventCode=13) 
| eval technique=case(EventCode=4698, "Scheduled Task Created", EventCode=4648, "Explicit Credential Logon", EventCode=13, "Registry Run Key Modified") 
| stats dc(EventCode) as distinct_techniques values(technique) as techniques_observed count as total_events by host 
| where distinct_techniques>=2
| sort -distinct_techniques
```

**Why this matters:** A single suspicious event could be a false positive. Multiple suspicious techniques on the same host within a short timeframe is a high confidence indicator of an active attack chain. This search correlates across persistence, lateral movement, and privilege abuse techniques simultaneously.
