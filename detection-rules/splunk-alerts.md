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
