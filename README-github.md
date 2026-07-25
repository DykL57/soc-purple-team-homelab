# SOC / Purple Team Home Lab

A self-built enterprise-style Security Operations Center lab — Active Directory, pfSense-segmented networking, Splunk Enterprise Security, and a validated detection-engineering workflow spanning both Red Team (attack simulation) and Blue Team (detection + investigation).

## Why this exists

Built to go beyond "I know what a SIEM is" — this lab documents real detections I wrote, real attacks I ran against my own environment to trigger them, and the actual troubleshooting behind getting an IT network + SIEM pipeline working end to end (including bugs most tutorials skip over, like ZFS boot failures and timezone-induced timestamp corruption).

## Architecture

```
Zone 2 (SERVERS, 10.0.20.0/24)  ── DC01 (Active Directory, lab.local)
Zone 3 (CLIENTS, 10.0.30.0/24)  ── WIN-CL01, WIN-CL02
Zone 6 (Gateway)                ── PFSENSE01 (routes + firewalls between zones)
Zone 1 (MGMT/SIEM)              ── Splunk Enterprise Security
Zone 5 (SENSOR/ATTACK)          ── KALI-OPS01 (isolated Red Team platform)
```

All zones are isolated VMware Host-Only networks; pfSense is the only path between them, with explicit firewall rules per zone.

*(Add your network diagram image here — screenshots/network-architecture.png)*

## Stack

| Component | Role |
|---|---|
| Windows Server 2022 | Active Directory Domain Services + DNS (DC01) |
| pfSense CE 2.8.1 | Inter-zone routing + firewall |
| Splunk Enterprise | SIEM — log aggregation, correlation, alerting |
| Splunk Universal Forwarder + Sysmon | Endpoint telemetry (DC01, WIN-CL01, WIN-CL02) |
| Kali Linux | Red Team attack platform |
| VMware Workstation | Virtualization + network segmentation |

## Detection Rules

Each rule below follows the same format: detection logic, SPL, how it was triggered, and proof it fired.

| # | Rule | MITRE ATT&CK | Status |
|---|---|---|---|
| 1 | Failed Login Brute Force | T1110.001 | ✅ Validated |
| 2 | Successful Login After Multiple Failures | T1078 | 🔄 In progress |
| 3–50 | See [detection-rules/](detection-rules/) | — | ⏳ Planned |

### Rule 1 — Failed Login Brute Force

**Detection logic:** 3+ failed authentication attempts (Event 4625) from a single host within a 5-minute window.

**SPL:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625 earliest=-10m
| bin _time span=5m
| stats count as failed_attempts dc(Account_Name) as unique_users by _time, host
| where failed_attempts >= 3
| eval severity=case(failed_attempts>=20,"CRITICAL", failed_attempts>=10,"HIGH", 1=1,"MEDIUM")
| table _time, host, failed_attempts, unique_users, severity
```

**Simulation used to trigger it:**
```powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class LogonTest {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider, out IntPtr phToken);
}
"@

1..5 | ForEach-Object {
    $token = [IntPtr]::Zero
    [LogonTest]::LogonUser("Administrator", "LAB", "WrongPass$_", 3, 0, [ref]$token)
    Start-Sleep -Milliseconds 500
}
```

**Result:** 5/5 attempts logged as individual Event 4625 entries, correctly aggregated by the detection query into a single MEDIUM-severity alert.

![Rule 1 Alert](screenshots/rule01-alert.png)

**What I'd tune in production:** raise the threshold to 5–10 (3 is intentionally low for lab-scale testing); add a lookup-based allowlist for known vulnerability scanners.

---

## Notable troubleshooting (worth reading if you're building something similar)

- **pfSense wouldn't boot after install (`No /boot/loader`)** — root cause was FreeBSD's ZFS bootloader misbehaving on a BIOS-mode VMware VM. Fixed by reinstalling with UFS instead of ZFS.
- **Splunk showed 0 events for "Last 7 days" despite data existing under "All time"** — DC01's timezone was set to Pacific Time by default instead of Israel Standard Time, causing Windows Event Log timestamps to be logged with the wrong UTC offset. Fixing the timezone alone wasn't enough — the underlying system clock also needed to be corrected (`Set-Date`), since changing timezone only reinterprets the same UTC instant, it doesn't fix a clock that was already wrong.
- **VMs on different Host-Only networks (VMnet3/VMnet4) couldn't reach each other by design** — this is intentional VMware network isolation, not a bug; solved by building pfSense as the router between zones, with explicit per-zone firewall rules (deny-by-default).

## Roadmap

- [x] Active Directory (DC01) + 2 domain-joined endpoints
- [x] pfSense inter-zone routing
- [x] Splunk + Universal Forwarder + Sysmon pipeline
- [x] Rule 1 (Brute Force) — validated end-to-end
- [ ] Rules 2–10 (Authentication category)
- [ ] Rules 11–40 (Lateral Movement, Exfil/C2, Malware)
- [ ] Full attack scenarios (phishing → lateral movement → exfil)
- [ ] IBM QRadar (next SIEM platform after Splunk)

## About

Built by [your name] as a hands-on SOC Analyst / Detection Engineering skills project.
Currently a SOC Analyst working with Splunk, QRadar CE, Security Onion, and Wazuh in a "SIEM of SIEMs" IT/OT environment.
