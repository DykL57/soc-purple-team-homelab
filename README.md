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
| Splunk Common Information Model (CIM) Add-on | Normalizes raw events into standard data models for `tstats`-accelerated searching |
| Kali Linux | Red Team attack platform |
| VMware Workstation | Virtualization + network segmentation |

## Detection Rules

Each rule below follows the same format: detection logic, SPL, how it was triggered, and proof it fired.

| # | Rule | MITRE ATT&CK | Category | Search Method | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Detection (Authentication) | T1110 | Credential Access | `tstats` (CIM Authentication) | ✅ Validated |
| 2 | Successful Login After Multiple Failures | T1078 | Credential Access / Initial Access | `tstats` (CIM Authentication) | ✅ Validated |
| 3 | Lateral Movement via Remote Service Creation (PsExec) | T1021.002 / T1569.002 | Lateral Movement | Raw search (`rex` extraction) | ✅ Validated |
| 4–50 | See [detection-rules/](detection-rules/) | — | — | — | ⏳ Planned |

### Rule 1 — Brute Force Detection (Authentication)

**Detection logic:** 3+ failed authentication attempts from a single host within a 5-minute window, with severity scored by volume (MEDIUM / HIGH / CRITICAL).

**SPL (tstats, CIM Authentication data model):**
```spl
| tstats count as failed_attempts, dc(Authentication.user) as unique_users 
    from datamodel=Authentication 
    where nodename=Authentication.Failed_Authentication 
    by Authentication.dest, _time span=5m
| where failed_attempts >= 3
| eval severity=case(failed_attempts>=20,"CRITICAL", failed_attempts>=10,"HIGH", true(),"MEDIUM")
| rename Authentication.dest as host
| table _time, host, failed_attempts, unique_users, severity
```

**Original raw-search version** (kept for reference — functionally equivalent, but scans raw events instead of the accelerated summary):
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

### Rule 2 — Successful Login After Multiple Failures

**Detection logic:** An account with 5+ failed logon attempts followed by a successful logon within the same 10-minute window — a pattern consistent with brute-force attempts that eventually succeed, or credential guessing against a privileged account.

**SPL (tstats, CIM Authentication data model):**
```spl
| tstats count(eval(Authentication.action="failure")) as fail_count,
         count(eval(Authentication.action="success")) as success_count,
         earliest(_time) as first_seen, latest(_time) as last_seen
    from datamodel=Authentication
    by Authentication.user, _time span=10m
| where fail_count >= 5 AND success_count > 0
| rename Authentication.user as Account_Name
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, Account_Name, fail_count, success_count
```

> **Note:** `Source_Network_Address` was dropped in this version — it isn't a standard field in the CIM `Authentication` data model by default. This is a deliberate tradeoff of a small amount of context for a large gain in search performance. If source-IP correlation is needed in production, either add a custom field extension to the data model or fall back to the raw-search version below for that specific investigation step.

**Original raw-search version** (kept for reference, and for cases where `Source_Network_Address` is needed):
```spl
index=wineventlog sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4625, "failure", "success")
| bin _time span=10m
| stats count(eval(status="failure")) as fail_count, 
        count(eval(status="success")) as success_count,
        values(Source_Network_Address) as src_ips,
        earliest(_time) as first_seen,
        latest(_time) as last_seen
        by Account_Name, _time
| where fail_count >= 5 AND success_count > 0
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, Account_Name, fail_count, success_count, src_ips
| sort -last_seen
```

**Simulation used to trigger it (run locally on DC01):**
```powershell
$domain = "lab.local"
$user   = "simtest"
$badPassword = "WrongPassword123"
$goodPassword = "P@ssw0rd2026!"

# 5 failed attempts
1..5 | ForEach-Object {
    $securePwd = ConvertTo-SecureString $badPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("$domain\$user", $securePwd)
    Start-Process cmd.exe -Credential $cred -ArgumentList "/c exit" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Final successful logon
$securePwd = ConvertTo-SecureString $goodPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$domain\$user", $securePwd)
Start-Process cmd.exe -Credential $cred -ArgumentList "/c exit"
```

**Result:** 5 consecutive failed logon events followed by a single successful logon for the `simtest` account, correctly correlated by the detection query into one alert.

![Rule 2 Alert Results](screenshots/rule02-alert-results.png)

**What I'd tune in production:** exclude known noisy service accounts (`NOT Authentication.user IN ("svc_*", "krbtgt")`); raise the fail-count threshold in high-turnover/shared-workstation environments.

---

### Rule 3 — Lateral Movement via Remote Service Creation (PsExec)

**Detection logic:** Detects installation of a new Windows service (Event 7045) on a domain-joined host — the mechanism PsExec and PsExec-style tools use to execute code remotely after obtaining valid credentials on another host. An attacker uses SMB admin shares (`ADMIN$`/`C$`) to drop a binary, then remotely creates and starts a service to run it.

**SPL:**
```spl
index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| rex field=_raw "Service Name:\s+(?<ServiceName>\S+)"
| rex field=_raw "Service File Name:\s+(?<ServiceFileName>.+?)\s+Service Type:"
| rex field=_raw "Service Account:\s+(?<ServiceAccount>\S+)"
| search ServiceName="PSEXESVC" OR ServiceFileName="*PSEXESVC*"
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceAccount, Sid
```

*(Not yet converted to `tstats` — Event 7045's mapping into the CIM `Change` data model depends on Windows TA tagging that hasn't been verified yet. See CIM Migration notes below.)*

**Simulation used to trigger it (WIN-CL01 → DC01, using Sysinternals PsExec):**
```powershell
# On DC01 — disposable test account + required rights
New-ADUser -Name "sim.lateral" -SamAccountName "simlateral" `
  -AccountPassword (ConvertTo-SecureString "<TestAccountPassword>" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "simlateral"
# Grant "Log on as a service" to simlateral/Domain Admins via
# Default Domain Controllers Policy → User Rights Assignment, then gpupdate /force

# On WIN-CL01 — remote execution
.\PsExec.exe \\DC01 -u lab.local\simlateral -p "<TestAccountPassword>" cmd.exe /c "whoami"
```

**Result:** PsExec authenticated as `simlateral`, installed `PSEXESVC.exe` as a service on DC01, executed `whoami` remotely (returned `lab\simlateral`), and cleaned up automatically. The detection query correctly captured all service-installation events, extracting `ServiceName`, `ServiceFileName`, `ServiceAccount` (`LocalSystem`), and the installing account's `Sid` from raw event text.

**Notable finding:** the service always runs as `LocalSystem` regardless of who launched it — the `Sid` field, not `ServiceAccount`, is what identifies the actual installer. This matters for triage: `ServiceAccount=LocalSystem` alone is not suspicious, since nearly all legitimate services also run that way.

![Rule 3 Alert](screenshots/rule03-alert.png)

**What I'd tune in production:** allowlist known legitimate remote-deployment accounts/hosts (SCCM, help desk tooling); use the broader `ServiceName`-agnostic version of the query, since real attackers rename the binary; pair with Sysmon Event ID 1 and Event 5145 (admin share access) for a full kill-chain view in one notable event.

---

## CIM / tstats Migration

Rules 1 and 2 were converted from raw `index=` searches to `tstats` against Splunk's Common Information Model (CIM), for two reasons: `tstats` searches an accelerated summary rather than scanning raw events, and it's the standard, portable approach Splunk Enterprise Security itself relies on for correlation searches.

**What this involved:**
1. Installed the **Splunk Common Information Model (CIM) Add-on** (`Splunk_SA_CIM`) — my lab initially only had Splunk's built-in sample data models, not `Authentication`/`Change`/etc.
2. Constrained the `Authentication` and `Change` data models to my actual index (`index=wineventlog`) via their `cim_Authentication_indexes` / `cim_Change_indexes` search macros (`Settings → Advanced Search → Search Macros`) — not by editing the data model's own constraints directly, which define CIM's field-tagging logic and shouldn't be touched.
3. Verified the Windows TA was correctly tagging events into CIM fields:
   ```spl
   | tstats count from datamodel=Authentication where nodename=Authentication.Failed_Authentication by Authentication.dest, Authentication.user
   ```
   This returned real results (181 events across 7 accounts/hosts, matching data from Rules 1–3 testing) — confirming the standard Windows TA's tagging was working correctly, despite one individual event initially showing `tag=error` instead of `tag=authentication` during investigation.
4. Rewrote Rules 1 and 2's SPL to use `tstats` (shown above); kept the original raw-search versions in the docs for reference and for the one field (`Source_Network_Address`) that CIM's default `Authentication` model doesn't expose.

**Rule 3 was left as a raw search** — Event 7045's mapping into the CIM `Change` data model wasn't verified before writing this section, and confirming that tagging is next on the list before converting it.

## Notable troubleshooting (worth reading if you're building something similar)

- **pfSense wouldn't boot after install (`No /boot/loader`)** — root cause was FreeBSD's ZFS bootloader misbehaving on a BIOS-mode VMware VM. Fixed by reinstalling with UFS instead of ZFS.
- **Splunk showed 0 events for "Last 7 days" despite data existing under "All time"** — DC01's timezone was set to Pacific Time by default instead of Israel Standard Time, causing Windows Event Log timestamps to be logged with the wrong UTC offset. Fixing the timezone alone wasn't enough — the underlying system clock also needed to be corrected (`Set-Date`), since changing timezone only reinterprets the same UTC instant, it doesn't fix a clock that was already wrong.
- **VMs on different Host-Only networks (VMnet3/VMnet4) couldn't reach each other by design** — this is intentional VMware network isolation, not a bug; solved by building pfSense as the router between zones, with explicit per-zone firewall rules (deny-by-default).
- **PsExec failed with "the user has not been granted the requested logon type at this computer," even with correct credentials and Domain Admin membership** — turned out to be the wrong GPO right entirely. PsExec's default mode installs and runs a remote service *as* the target account (Logon Type 5, service logon), which requires the "Log on as a service" right — a completely different setting from "Access this computer from the network" (network logon, Type 3), which was the first (wrong) place I checked. Confirmed via Event 4625's `Sub_Status 0xC000015B` alongside `Logon_Type 5` in the raw event — the sub-status/logon-type pair is the fastest way to identify exactly which User Rights Assignment setting is actually missing, instead of guessing.
- **Event 7045 (service installation) returned 0 results when searched under `sourcetype=WinEventLog:Security`** — Service Control Manager events log to the **System** event log, not Security. Also, once found under `WinEventLog:System`, the relevant fields (`ServiceName`, `ServiceFileName`, `ServiceAccount`) weren't auto-extracted by the default Windows TA the way Security log fields are — required `rex` against `_raw` to pull them out manually.
- **New CIM data models showed "no explicit index constraint" warnings, and editing the Data Model's own Constraints box didn't fix it** — the constraint box referenced a macro (`` `cim_Authentication_indexes` ``) rather than a literal index name. The actual fix was editing the macro's *definition* under `Settings → Advanced Search → Search Macros`, not the data model's constraint field itself.

## Lab Hygiene

Every simulation follows the same pattern: snapshot both VMs before testing, create a disposable, clearly-named test account (`simtest`, `simlateral`) for the simulation, and remove both the account and any elevated group membership immediately after validation is complete and screenshots are captured. No test account is left provisioned longer than the testing session that needed it.

## Roadmap

- [x] Active Directory (DC01) + 2 domain-joined endpoints
- [x] pfSense inter-zone routing
- [x] Splunk + Universal Forwarder + Sysmon pipeline
- [x] Rule 1 (Brute Force Detection) — validated end-to-end, converted to `tstats`
- [x] Rule 2 (Successful Login After Multiple Failures) — validated end-to-end, converted to `tstats`
- [x] Rule 3 (Lateral Movement via PsExec) — validated end-to-end
- [x] CIM Add-on installed, Authentication/Change data models configured and verified
- [ ] Convert Rule 3 to `tstats` (pending CIM `Change` tagging verification)
- [ ] Rules 4–10 (Authentication / Lateral Movement category)
- [ ] Rules 11–40 (Exfil/C2, Malware, Persistence)
- [ ] Full attack scenarios (phishing → lateral movement → exfil)
- [ ] IBM QRadar (next SIEM platform after Splunk)

## About

Built by Daniel Luchter as a hands-on SOC Analyst / Detection Engineering skills project.
Currently a SOC Analyst working with Splunk, QRadar CE, Security Onion, and Wazuh in a "SIEM of SIEMs" IT/OT environment.
