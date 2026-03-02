# Lab Setup Documentation

Complete build documentation for the SOC analyst home lab environment.

## Host System

| Component | Details |
|-----------|---------|
| OS | CachyOS Linux (Arch-based) |
| CPU | AMD Ryzen 9 9800X3D |
| SIEM | Splunk Enterprise |
| Virtualization | VirtualBox |

## Architecture Overview
```
Windows 10 VM (VirtualBox)
    └── Sysmon (SwiftOnSecurity config)
    └── Splunk Universal Forwarder
        └── Ships logs to CachyOS host on port 9997
            └── Splunk Enterprise (localhost:8000)
                └── Indexes: main, botsv1
                └── 4 Detection Alerts
                └── SOC Monitoring Dashboard
```

## Component 1 — Splunk Enterprise

**Installation:**
```bash
tar -xvzf splunk-*.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
sudo systemctl enable splunk
```

**Known Issues on CachyOS:**
- Splunk bundles its own libcrypto.so.3 which conflicts with system OpenSSL
- Fix: rename bundled libraries to force fallback to system OpenSSL
```bash
sudo mv /opt/splunk/lib/libcrypto.so.3 /opt/splunk/lib/libcrypto.so.3.bak
sudo mv /opt/splunk/lib/libssl.so.3 /opt/splunk/lib/libssl.so.3.bak
```
- chkconfig not available on Arch — use systemd service manually
- inotify watch limit requires increase for stable operation
```bash
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl fs.inotify.max_user_instances=512
```

## Component 2 — Windows 10 VM

**VirtualBox Installation on CachyOS:**
```bash
sudo pacman -S virtualbox virtualbox-host-dkms linux-cachyos-headers
sudo dkms autoinstall
sudo modprobe vboxdrv
sudo modprobe vboxnetflt
sudo modprobe vboxnetadp
sudo usermod -aG vboxusers $USER
```

**VM Configuration:**
- RAM: 4GB
- Storage: 50GB dynamic
- Network: Bridged adapter

## Component 3 — Sysmon

**Installation on Windows VM:**
1. Download Sysmon from Microsoft Sysinternals
2. Download SwiftOnSecurity config from GitHub
3. Install via PowerShell as Administrator:
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

**Verify running:**
```powershell
Get-Service Sysmon64
```

## Component 4 — Splunk Universal Forwarder

**Installation on Windows VM:**
1. Download from splunk.com
2. Install MSI as Administrator
3. Configure receiving indexer — CachyOS IP on port 9997

**inputs.conf configuration:**
```
[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
```

**Location:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

**Known Issues:**
- Universal Forwarder requires Local System account to read Sysmon logs
- Fix: Services → SplunkForwarder → Properties → Log On → Local System account
- UFW on CachyOS must allow port 9997
```bash
sudo ufw allow 9997/tcp
sudo ufw reload
```

## Component 5 — GoPhish

**Installation on CachyOS:**
```bash
tar -xvzf gophish-*.tgz -C ~/gophish
cd ~/gophish
chmod +x gophish
sudo ./gophish
```

**Configuration:**
- Admin panel: `https://localhost:3333`
- Phishing server: `http://0.0.0.0:80`
- config.json phish_server listen_url must be set to `0.0.0.0:80` for VM access
- UFW must allow port 80
```bash
sudo ufw allow 80/tcp
```

## Component 6 — BOTS v1 Dataset

**Installation:**
```bash
wget https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz
tar -xvzf botsv1_data_set.tgz -C /opt/splunk/etc/apps/
sudo systemctl restart splunk
```

**Verify:**
```
index=botsv1 | head 10
```

## Splunk Receiving Configuration

Enable port 9997 for Universal Forwarder ingestion:
- Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port → 9997

## Dashboard

Five panel SOC monitoring dashboard — **SOC Lab - Threat Detection:**

| Panel | SPL Focus | EventCode |
|-------|-----------|-----------|
| Suspicious Scheduled Tasks | PowerShell in scheduled tasks | 4698 |
| Failed Logon Attempts | Authentication failures | 4625 |
| Successful Logons | Authentication success | 4624 |
| Suspicious Registry Run Keys | PowerShell in run keys | Sysmon 13 |
| Lateral Movement | Explicit credential logons | 4648 |
