# Rule 03 — Lateral Movement via Remote Service Creation (PsExec)

**MITRE ATT&CK:** T1021.002 – Remote Services: SMB/Windows Admin Shares, paired with T1569.002 – System Services: Service Execution
**Category (SIEM taxonomy):** Lateral Movement
**Severity:** High
**Data Source:** Windows System Event Log (DC01) — EventCode 7045 (Service Control Manager)
**Platform:** Windows / Active Directory

## Detection Logic

Detects installation of a new Windows service on a domain-joined host — the mechanism PsExec (and PsExec-style tools like Cobalt Strike's `psexec` module) uses to execute code remotely. An attacker with valid credentials on one host uses SMB admin shares (`ADMIN$`/`C$`) to drop a binary on a target, then remotely creates and starts a service to execute it. Event 7045 fires on the target host every time this happens, regardless of which tool is used.

## SPL Query

```spl
index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| rex field=_raw "Service Name:\s+(?<ServiceName>\S+)"
| rex field=_raw "Service File Name:\s+(?<ServiceFileName>.+?)\s+Service Type:"
| rex field=_raw "Service Account:\s+(?<ServiceAccount>\S+)"
| search ServiceName="PSEXESVC" OR ServiceFileName="*PSEXESVC*"
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceAccount, Sid
```

**Broader version** — catches renamed binaries too, since real attackers rarely use the default `PSEXESVC` name:

```spl
index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| rex field=_raw "Service Name:\s+(?<ServiceName>\S+)"
| rex field=_raw "Service File Name:\s+(?<ServiceFileName>.+?)\s+Service Type:"
| rex field=_raw "Service Account:\s+(?<ServiceAccount>\S+)"
| stats count values(ServiceName) as services values(ServiceFileName) as paths by ComputerName, Sid
```

### Field extraction note
Event 7045 is logged to the **System** log, not Security — a common early mistake when building this rule. Its fields (`Service Name:`, `Service File Name:`, `Service Account:`) also aren't extracted automatically by the default Windows TA the way Security log fields are, so `rex` is used above to pull them from `_raw`.

## Simulation Used to Trigger It

Run from **WIN-CL01**, targeting **DC01**, using Sysinternals PsExec (legitimate Microsoft tool):

**1. Snapshot both VMs first** (`WIN-CL01` and `DC01`) before testing — service creation and account changes can leave residue.

**2. Create a disposable domain test account on DC01:**
```powershell
New-ADUser -Name "sim.lateral" -SamAccountName "simlateral" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Add-ADGroupMember -Identity "Domain Admins" -Members "simlateral"
```

**3. Grant "Log on as a service" right** on DC01 (Default Domain Controllers Policy → User Rights Assignment) to `simlateral`/`Domain Admins`, then `gpupdate /force`. This right is separate from — and easily confused with — "Access this computer from the network"; PsExec's default mode installs and runs a service *as* the target account (Logon Type 5), which specifically requires this right.

**4. Run PsExec from WIN-CL01:**
```powershell
.\PsExec.exe \\DC01 -u lab.local\simlateral -p "P@ssw0rd2026!" cmd.exe /c "whoami"
```

**5. Cleanup after testing:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "simlateral" -Confirm:$false
Remove-ADUser -Identity "simlateral"
```

## Result

PsExec successfully authenticated as `simlateral`, copied `PSEXESVC.exe` to DC01's `ADMIN$` share, installed and started it as a Windows service, executed `whoami` remotely (returning `lab\simlateral`), and cleaned up automatically. The detection query correctly captured all 5 service-installation events generated during testing, extracting `ServiceName` (`PSEXESVC`), `ServiceFileName` (`%SystemRoot%\PSEXESVC.exe`), `ServiceAccount` (`LocalSystem`), and the installing account's SID from raw event text.

**Notable finding:** the service itself always runs as `LocalSystem` regardless of which account launched it — the `Sid` field is what identifies *who actually installed it*. This distinction (installer identity vs. service run-as account) is the key data point an analyst needs when triaging this alert, since `ServiceAccount` alone won't tell you who to investigate.

![Rule 3 Alert](../../screenshots/rule03-alert.png)

## Alert Configuration

| Setting | Value |
|---|---|
| Alert type | Scheduled |
| Cron schedule | `*/5 * * * *` |
| Time range | Last 10 minutes (overlap for boundary safety) |
| Trigger condition | Number of Results > 0 |
| Trigger | Once |
| Throttling | Suppress by `ComputerName`, 15 minutes |

## False Positive Notes
- Legitimate IT administration tools (SCCM, remote software deployment, some backup agents) also install services remotely via the same mechanism — baseline known admin source hosts/accounts and exclude them, or route those to a lower-severity queue instead of full suppression
- `ServiceAccount=LocalSystem` alone is not suspicious — nearly all legitimately-installed services also run as LocalSystem; the accompanying `Sid` (installer identity) and `ComputerName` are the fields that matter for triage
- Renamed PsExec binaries (common in real intrusions) will bypass the narrow `ServiceName="PSEXESVC"` filter — use the broader version of the query in production, and consider correlating with Sysmon Event ID 1 (process creation) for the dropped binary as a second detection layer
- Consider excluding known patch/deployment windows if this fires frequently during scheduled software rollouts

## What I'd Tune in Production
- Add a lookup-based allowlist for known legitimate remote administration accounts/hosts (SCCM service accounts, help desk admin accounts)
- Pair with Sysmon Event ID 1 for `PSEXESVC.exe` or renamed equivalents spawning child processes, to catch the execution stage as well as the installation stage
- Correlate with Event 5145 (`ADMIN$`/`C$` share access) immediately preceding the 7045 event, to build a full lateral-movement kill-chain view in a single notable event
