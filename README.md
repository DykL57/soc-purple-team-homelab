# SOC / Purple Team Home Lab

A self-built enterprise-style Security Operations Center lab — Active Directory, pfSense-segmented networking, Splunk Enterprise Security, and a validated detection-engineering workflow spanning both Red Team (attack simulation) and Blue Team (detection + investigation).

## Why this exists

Built to go beyond "I know what a SIEM is" — this lab documents real detections I wrote, real attacks I ran against my own environment to trigger them, and the actual troubleshooting behind getting an IT network + SIEM pipeline working end to end (including bugs most tutorials skip over, like ZFS boot failures and timezone-induced timestamp corruption).

## Architecture

```
Zone 2 (SERVERS, 10.0.20.0/24)  ── DC01 (Active Directory, lab.local)
                                  ── SPLUNK01 (Splunk Enterprise, 10.0.20.100 — static DHCP mapping)
Zone 3 (CLIENTS, 10.0.30.0/24)  ── WIN-CL01, WIN-CL02
Zone 5 (SENSOR/ATTACK, 10.0.50.0/24) ── KALI-OPS01 (Red Team platform)
Zone 6 (Gateway)                ── PFSENSE01 (Bridged WAN → real ISP-assigned IP; routes + firewalls between zones)
```

All internal zones are isolated VMware Host-Only networks; pfSense is the only path between them, with explicit firewall rules per zone (deny-by-default). WAN is Bridged directly to a physical adapter on the host, giving pfSense a real, ISP-routable IP address instead of a NAT-translated one — this was a deliberate change to enable genuine inbound/outbound traffic visibility (see Notable Troubleshooting below for what that migration broke, and how it was fixed). Zone 5 (Kali) was initially isolated with no route to any other zone by design; a dedicated `OPT2` interface and firewall rule were added later specifically to support Rule 5's port-scan simulation.

*(Add your network diagram image here — screenshots/network-architecture.png)*

## Stack

| Component | Role |
|---|---|
| Windows Server 2022 | Active Directory Domain Services + DNS (DC01) |
| pfSense CE 2.8.1 | Inter-zone routing + firewall, Bridged WAN with real ISP IP |
| Splunk Enterprise (Rocky Linux) | SIEM — log aggregation, correlation, alerting |
| Splunk Universal Forwarder + Sysmon | Endpoint telemetry (DC01, WIN-CL01, WIN-CL02) |
| Splunk Common Information Model (CIM) Add-on | Normalizes raw events into standard data models for `tstats`-accelerated searching |
| Splunk `iplocation` (built-in) | Geo-IP enrichment for network-based detections, no add-on required |
| Kali Linux | Red Team attack platform |
| VMware Workstation | Virtualization + network segmentation |

## Detection Rules

Each rule below follows the same format: detection logic, SPL, how it was triggered, and proof it fired.

| # | Rule | MITRE ATT&CK | Category | Search Method | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Detection (Authentication) | T1110 | Credential Access | `tstats` (CIM Authentication) | ✅ Validated |
| 2 | Successful Login After Multiple Failures | T1078 | Credential Access / Initial Access | `tstats` (CIM Authentication) | ✅ Validated |
| 3 | Lateral Movement via Remote Service Creation (PsExec) | T1021.002 / T1569.002 | Lateral Movement | Raw search (`rex` extraction) | ✅ Validated |
| 4 | Outbound Traffic to High-Risk Countries | T1071 / TA0011 | Network — Anomalous Outbound Traffic | Raw search (`rex` + `iplocation`) | ✅ Validated (see limitations) |
| 5 | Port Scan Detection (High Port-Touch Volume) | T1046 | Network — Reconnaissance | Raw search (`rex` + `stats`) | ✅ Validated |
| 6–50 | See [detection-rules/](detection-rules/) | — | — | — | ⏳ Planned |

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
$goodPassword = Read-Host "Enter lab password" -AsSecureString

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

**Deliberately kept as a raw search, not converted to `tstats`.** Investigated converting this to the CIM `Change` data model and hit a real limitation worth documenting: the `All_Changes` node's constraint only requires `tag=change`, so I created a narrow, dedicated event type (`windows_service_installed`, scoped to `EventCode=7045` only — critically *not* the broader `windows_endpoint_services` event type, which also covers noisy EventCode 7036 service state-change events at ~1,500 events vs. 53 for 7045) and tagged it `change`. The tag applied successfully, but `tstats` against the model still returned 0 results when filtered to the actual service name (`PSEXESVC`) — confirmed via `All_Changes.object`. Broader querying showed the model was populated almost entirely with `object_category=user` events (account creation/logoff/modification, ~5,700 events) and an `unknown` bucket, with no `service` category present at all. Conclusion: a `Settings → Tags` entry alone tags the *event*, but the CIM `Change` model also requires field-level extraction (`object`, `object_category`, `dvc`, etc.) that the standard Windows TA doesn't provide for Service Control Manager events out of the box — that would require `props.conf`/`transforms.conf`-level field extraction work, not just tagging. Given the raw-search version already works reliably, this was judged not worth the additional TA-level configuration for a lab environment, and the rule stays as a raw search.

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

### Rule 4 — Outbound Traffic to High-Risk Countries

**Detection logic:** Flags outbound connections from the lab network to public IPs geolocated in a configurable list of high-risk countries (e.g., countries associated with known APT activity against Israeli critical infrastructure — Iran, Russia, North Korea, Syria, China). Uses Splunk's built-in `iplocation` command (bundled MaxMind GeoLite2 database — no add-on install required) against pfSense's `filterlog` firewall events.

**SPL:**
```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4" AND direction="out"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| where dst_ip!="127.0.0.1" AND NOT match(dst_ip, "^10\.") AND NOT match(dst_ip, "^192\.168\.")
| iplocation dst_ip
| search Country IN ("Iran", "Russia", "North Korea", "Syria", "China")
| stats count, values(dst_ip) as dest_ips, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, Country
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, Country, count, dest_ips
```

**Field extraction note:** pfSense's `filterlog` sourcetype arrives as unstructured, positional CSV inside the syslog message, with no default Splunk TA field extraction. Rather than parsing by fixed column position (which breaks across TCP/UDP/ICMP, since each logs a different number of fields), this query extracts the fixed-position header fields (rule, interface, action, direction, ipver) with one `rex`, then matches the `src_ip,dst_ip` pattern directly as two adjacent dotted-quad values with a second `rex` — robust regardless of protocol. `dedup _raw` was added defensively after discovering pfSense duplicates some syslog event types at the source (see Notable Troubleshooting) — investigation confirmed `filterlog` itself was not actually affected, but the safeguard is kept in place.

**Result:** Validated against ~8,300 real, organic outbound events (DNS resolution, Windows Update, telemetry, etc.) collected over several hours of normal lab operation. The query correctly aggregated hits by source IP and country, surfacing 4 connections geolocated to Iran and 2 to Russia — counts confirmed unchanged after adding `dedup`.

**Known limitation — both flagged IPs confirmed as false positives:** both the Iran- and Russia-geolocated IPs were manually checked against VirusTotal and found to be legitimate infrastructure, not actually associated with either country. This isn't a statement that Iran/Russia are the wrong countries to monitor — both remain valid entries given known APT activity against Israeli critical infrastructure — it's a statement about Splunk's bundled MaxMind GeoLite2 database misattributing these two specific IPs. Root cause: the free database is a point-in-time snapshot that isn't automatically kept current, and IP block ownership/geolocation changes frequently (RIR reassignment, cloud/CDN churn). **Geo-IP alone is not sufficient grounds for escalation** — every hit from this rule must be manually cross-referenced against a live threat-intel source (VirusTotal, AbuseIPDB) before being treated as credible. In this validation run, doing so caught a 100% false-positive rate (2 for 2), which is itself the most useful finding from building this rule. It's intentionally scoped as a low-confidence supporting signal, not a standalone confirmed-threat detection.

![Rule 4 Alert](screenshots/rule04-alert.png)

**What I'd tune in production:** replace/supplement the bundled GeoLite2 database with a regularly-updated MaxMind subscription, or pair with a live IP reputation API (VirusTotal/AbuseIPDB) instead of relying on geolocation alone — a 100% false-positive rate in validation makes this a hard requirement, not a nice-to-have; build a maintained allowlist for known-legitimate infrastructure (root DNS servers, major cloud/CDN ASNs) to cut expected noise before it reaches an analyst; correlate with destination port/protocol, since outbound HTTPS to a flagged country is far less notable than traffic on an unusual port; track ASN alongside country, since ASN ownership tends to be more stable than country-level geolocation.

---

### Rule 5 — Port Scan Detection (High Port-Touch Volume)

**Detection logic:** Flags a single source IP touching an unusually high number of distinct destination ports on the same destination host within a 1-minute window — the classic signature of a port scan. Deliberately does **not** filter on `action="block"` — the rule detects the pattern of many-ports-from-one-source regardless of whether pfSense's firewall rules pass or block the traffic, since a permissive rule (or a scan against an open service range) would otherwise hide a real scan from a block-only detection.

**SPL:**
```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<src_port>\d+),(?<dst_port>\d+)"
| bin _time span=1m
| stats dc(dst_port) as unique_ports_tried, count as attempts by src_ip, dst_ip, _time
| where unique_ports_tried >= 10
| stats sum(attempts) as total_attempts, max(unique_ports_tried) as max_ports_per_min, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, dst_ip
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, dst_ip, max_ports_per_min, total_attempts
```

**Simulation used to trigger it:** required extending the lab topology to allow this test — `KALI-OPS01` (Zone 5, `10.0.50.0/24`) had no route to Zone 2 prior to this rule, by design (pfSense deny-by-default). Added a 4th virtual NIC on `PFSENSE01` bridged to Kali's VMnet, a new `OPT2` interface (`10.0.50.1/24`), a deliberately permissive firewall rule (`Pass`, any protocol, source Any, destination `10.0.20.0/24`) to test detection regardless of block/pass, and a default route on Kali.
```bash
nmap -sS -p 1-1000 10.0.20.1
```

**Result:** nmap reported 3 open ports (53/domain, 80/http, 443/https — pfSense's own resolver and WebGUI) and 997 filtered against `10.0.20.1`. The detection query correctly identified the scan: **759 unique destination ports touched by `10.0.50.60` against `10.0.20.1`** within a single one-minute window, with 2,266 total connection attempts across the scan — far exceeding the 10-port threshold.

![Rule 5 Alert](screenshots/rule05-alert.png)

**What I'd tune in production:** raise the threshold significantly (the lab's `>= 10` is deliberately sensitive for validation; production typically uses 15–50+ depending on baseline); allowlist known vulnerability scanner infrastructure (Nessus/OpenVAS/Qualys will trigger this identically to a malicious scan); correlate with whether scanned ports actually returned open/closed/filtered, since a scan against a mostly-filtered host is a stronger anomaly than one against a host with many legitimately open services; add a companion horizontal-scan detection (many hosts, few ports each) since this rule only catches vertical scans.

---

## Network Traffic Monitoring

pfSense forwards Firewall, System, and DHCP events to Splunk via syslog (UDP 5514), indexed separately from Windows telemetry (`index=pfsense`, sourcetype `pfsense:firewall`). This gives visibility into real inbound/outbound traffic at the network edge — allow/block decisions, source/destination IPs and ports, and (via Rule 4) geo-IP context — complementing the Windows-endpoint-focused detections in Rules 1–3. Getting this pipeline working end-to-end (WAN topology, DHCP, and forwarding) surfaced a substantial troubleshooting exercise; see below.

A device inventory lookup (built from an `nmap -sn` sweep of the local network) enriches traffic queries with device names/types instead of raw IPs — e.g. `| lookup device_inventory.csv ip AS src_ip OUTPUT hostname AS device_name`.

**Next planned detections built on this data:**
- Outbound connections to unusual/non-standard ports (possible C2 or data exfiltration)
- Horizontal port scan (many hosts, low ports-per-host) as a companion to Rule 5's vertical scan detection

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

**Rule 3 was investigated and deliberately left as a raw search.** Unlike Authentication, mapping Event 7045 into the CIM `Change` model required more than a `Settings → Tags` entry — the standard Windows TA doesn't extract the field-level data (`object`, `object_category`, `dvc`) that model needs, only tagging gets an event *considered*, not correctly categorized. Confirmed this by creating a narrow, correctly-scoped event type for just EventCode 7045, tagging it `change`, and finding `tstats` still returned 0 results when filtered to the actual installed service name — the model was populated by unrelated `object_category=user` events instead. Fixing this properly would mean editing `props.conf`/`transforms.conf` for the TA, which was judged out of scope for a working, validated raw-search rule in a lab context. Full detail in Rule 3's write-up above.

## Notable troubleshooting (worth reading if you're building something similar)

- **pfSense wouldn't boot after install (`No /boot/loader`)** — root cause was FreeBSD's ZFS bootloader misbehaving on a BIOS-mode VMware VM. Fixed by reinstalling with UFS instead of ZFS.
- **Splunk showed 0 events for "Last 7 days" despite data existing under "All time"** — DC01's timezone was set to Pacific Time by default instead of Israel Standard Time, causing Windows Event Log timestamps to be logged with the wrong UTC offset. Fixing the timezone alone wasn't enough — the underlying system clock also needed to be corrected (`Set-Date`), since changing timezone only reinterprets the same UTC instant, it doesn't fix a clock that was already wrong.
- **VMs on different Host-Only networks (VMnet3/VMnet4) couldn't reach each other by design** — this is intentional VMware network isolation, not a bug; solved by building pfSense as the router between zones, with explicit per-zone firewall rules (deny-by-default).
- **PsExec failed with "the user has not been granted the requested logon type at this computer," even with correct credentials and Domain Admin membership** — turned out to be the wrong GPO right entirely. PsExec's default mode installs and runs a remote service *as* the target account (Logon Type 5, service logon), which requires the "Log on as a service" right — a completely different setting from "Access this computer from the network" (network logon, Type 3), which was the first (wrong) place I checked. Confirmed via Event 4625's `Sub_Status 0xC000015B` alongside `Logon_Type 5` in the raw event — the sub-status/logon-type pair is the fastest way to identify exactly which User Rights Assignment setting is actually missing, instead of guessing.
- **Event 7045 (service installation) returned 0 results when searched under `sourcetype=WinEventLog:Security`** — Service Control Manager events log to the **System** event log, not Security. Also, once found under `WinEventLog:System`, the relevant fields (`ServiceName`, `ServiceFileName`, `ServiceAccount`) weren't auto-extracted by the default Windows TA the way Security log fields are — required `rex` against `_raw` to pull them out manually.
- **New CIM data models showed "no explicit index constraint" warnings, and editing the Data Model's own Constraints box didn't fix it** — the constraint box referenced a macro (`` `cim_Authentication_indexes` ``) rather than a literal index name. The actual fix was editing the macro's *definition* under `Settings → Advanced Search → Search Macros`, not the data model's constraint field itself.
- **Migrating pfSense's WAN from NAT (VMnet8) to Bridged broke GUI access, syslog delivery to Splunk, and host-to-LAN DHCP — all from one adapter change, with the true root cause only surfacing days later.** Moving WAN off the NAT network removed pfSense's only route to the subnet where the Splunk server lived, which silently broke syslog forwarding with no error on either side; fixed by relocating the Splunk server into pfSense's own LAN network. That relocation then hit a DHCP failure (APIPA fallback) that looked like VMware's built-in DHCP service competing with pfSense's — disabling it was a correct hygiene fix but turned out to be coincidental, not the actual cause. The real root cause, found only when the identical symptom recurred on a second, unrelated host (the Splunk server itself): pfSense's DHCP **Address Pool Range was misconfigured to `192.168.1.x`, entirely unrelated to the LAN's actual `10.0.20.0/24` subnet** — meaning the DHCP server could never hand out a lease to anyone on that interface, regardless of client or VMware settings. Corrected the pool to `10.0.20.101–200`, added a static DHCP mapping for the Splunk server (`10.0.20.100`) to keep its address permanent for the forwarders and syslog target that reference it by IP. Full writeup: [troubleshooting-pfsense-bridged-wan-dhcp-conflict.md](docs/troubleshooting-pfsense-bridged-wan-dhcp-conflict.md)
- **pfSense's `dpinger` (WAN gateway monitor) syslog events arrive duplicated in Splunk** — identical `_raw` content, identical microsecond timestamp, roughly double the expected volume. Investigated as a possible overlap between `Remote Syslog Contents` categories (`System Events` and `Gateway Monitor Events` both checked, and `dpinger` may log to a facility both match), but disabling `System Events` didn't resolve it. Confirmed via `| stats count by _raw | where count > 1` that **`filterlog` (the Firewall Events data Rules 4/5 depend on) is not affected** — only `dpinger`/gateway-monitor-related events showed the duplication. Root cause not fully diagnosed given it doesn't impact any current detection rule; worked around with `dedup _raw` at search time as a defensive habit for any future `index=pfsense` query, rather than continuing to chase a root cause with no practical impact on the lab.
- **CIM `Change` data model tagging looked successful but `tstats` still returned nothing usable for Rule 3** — see Rule 3's write-up and the CIM/tstats Migration section above. Root cause: `Settings → Tags` only tags an *event*; the CIM `Change` model separately requires field-level extraction (`object`, `object_category`) that the standard Windows TA doesn't provide for Service Control Manager events, so a correctly-tagged event still lands in the model without the fields needed to actually filter for it.
- **Kali (`KALI-OPS01`, Zone 5) had no route to any other lab zone** — this was intentional pfSense isolation, not a bug, but had to be deliberately undone to validate Rule 5's port-scan simulation. Required adding a 4th NIC to `PFSENSE01`, a new `OPT2` interface, and an explicit firewall rule, since pfSense's deny-by-default posture blocks inter-zone traffic until a rule is added — the same principle documented earlier for VMnet3/VMnet4 isolation.

## Lab Hygiene

Every simulation follows the same pattern: snapshot both VMs before testing, create a disposable, clearly-named test account (`simtest`, `simlateral`) for the simulation, and remove both the account and any elevated group membership immediately after validation is complete and screenshots are captured. No test account is left provisioned longer than the testing session that needed it.

## Roadmap

- [x] Active Directory (DC01) + 2 domain-joined endpoints
- [x] pfSense inter-zone routing
- [x] Splunk + Universal Forwarder + Sysmon pipeline
- [x] Rule 1 (Brute Force Detection) — validated end-to-end, converted to `tstats`
- [x] Rule 2 (Successful Login After Multiple Failures) — validated end-to-end, converted to `tstats`
- [x] Rule 3 (Lateral Movement via PsExec) — validated end-to-end
- [x] Rule 4 (Outbound Traffic to High-Risk Countries) — validated end-to-end, false-positive limitation documented (2/2 confirmed false positives)
- [x] Rule 5 (Port Scan Detection) — validated end-to-end, required extending lab topology to Zone 5
- [x] CIM Add-on installed, Authentication/Change data models configured and verified
- [x] pfSense WAN migrated from VMware NAT to Bridged mode, receiving a private IP directly from the upstream Cellcom router
- [x] pfSense syslog → Splunk integration (Firewall/System/DHCP events)
- [x] pfSense DHCP root cause fixed (Address Pool Range corrected); static mapping added for Splunk server
- [x] Device inventory lookup built from nmap sweep, integrated into traffic queries
- [x] Rule 3 `tstats`/CIM `Change` conversion investigated — deliberately kept as raw search (TA field-extraction gap documented)
- [x] Zone 5 (Kali) connected to Zone 2 via new pfSense interface, for controlled attack-simulation testing
- [ ] Add live IP reputation lookup (VirusTotal/AbuseIPDB) to Rule 4 to reduce geo-IP false positives
- [ ] Horizontal port scan detection (companion to Rule 5)
- [ ] Diagnose root cause of pfSense `dpinger` syslog duplication (non-blocking)
- [ ] Rules 6–10 (Authentication / Lateral Movement / Network category)
- [ ] Rules 11–40 (Exfil/C2, Malware, Persistence)
- [ ] Full attack scenarios (phishing → lateral movement → exfil)
- [ ] IBM QRadar (next SIEM platform after Splunk)

## About

Built by Daniel Luchter as a hands-on SOC Analyst / Detection Engineering skills project.
Currently a SOC Analyst working with Splunk, QRadar CE, Security Onion, and Wazuh in a "SIEM of SIEMs" IT/OT environment.
