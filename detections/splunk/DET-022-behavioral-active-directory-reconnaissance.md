# DET-022 — Behavioral Active Directory Reconnaissance

## Overview

Detects high-volume Active Directory reconnaissance by correlating Sysmon endpoint network behavior, Zeek LDAP/LDAPS network telemetry, and Windows Security share-access telemetry from DC01. The validated logic uses matching `source_ip` values in one-minute event-time buckets and requires all three signals.

The detection is behavioral: it does not require the process filename to equal `SharpHound.exe`. A controlled run of the same binary renamed to `ADInventory.exe` was detected successfully. This result does not establish universal rename resistance, detection of every AD-reconnaissance tool, AV/EDR bypass, compromise, or production readiness.

## Detection Objective

Identify short, high-volume bursts of LDAP/LDAPS and SMB activity that are simultaneously visible from the endpoint, passive network sensor, and Domain Controller. Preserve the source, process, user, volume, destination, service, share, and target context needed for analyst triage.

## Detection Summary

| Field | Value |
|---|---|
| Detection ID | DET-022 |
| Detection name | Behavioral Active Directory Reconnaissance |
| Status | Validated |
| Validation date | 2026-09-23 |
| Detection platform | Splunk Enterprise |
| Validated source | WIN-REDTEAM01 / `10.0.50.50` |
| Domain Controller | DC01 / `10.0.20.10` |
| Network sensor | ZEEK01 |
| Correlation | Matching `source_ip` and one-minute event-time bucket |
| MITRE ATT&CK | T1087.002 / T1069.002 |
| Scheduled alert | Validated |

## Lab Context and Data Sources

| Signal | Validated source | Purpose |
|---|---|---|
| Endpoint | `index=sysmon`, EventCode 3, `Initiated=true` | Process-attributed LDAP, LDAPS, and SMB connections |
| Network | `index=zeek`, `sourcetype="zeek:conn:json"` | LDAP/LDAPS connection volume and response-byte context |
| Domain Controller | `index=win_dc`, `host="DC01"`, EventCode 5145 | SMB share and target access from the source |
| Correlation / alerting | Splunk Enterprise at `10.0.20.100` | Multi-source aggregation and scheduled alerting |

The lab uses private RFC1918 addressing. ZEEK01 provides partial passive visibility into VMnet6 as documented in the current architecture notes.

## Detection Concept

### Endpoint signal

Within a one-minute bucket, the Sysmon signal requires:

- EventCode 3 with `Initiated=true`.
- Destination port 389 or 636, and destination port 445.
- At least three unique destinations.
- At least 100 endpoint connections.

### Network signal

Within the same type of event-time bucket, the Zeek signal requires:

- Destination port 389 or 636.
- At least 100 connections.
- At least 10,000,000 response bytes.

### Domain Controller signal

The DC signal uses EventCode 5145. The required `source_ip`, `dc_user`, `dc_share`, and `dc_target` values are extracted from raw XML using `rex`.

### Final correlation

The three aggregated streams are correlated by `_time` and `source_ip`. A final result is returned only when endpoint, network, and Domain Controller signals are all present.

The thresholds are tuned to this lab and are not universal production thresholds.

## Final Validated SPL

```spl
index=sysmon EventCode=3 Initiated=true
(DestinationPort=389 OR DestinationPort=636 OR DestinationPort=445)
| eval ad_port=if(DestinationPort IN (389,636), DestinationPort, null())
| eval smb_port=if(DestinationPort=445, DestinationPort, null())
| where match(SourceIp,"^\d{1,3}(\.\d{1,3}){3}$")
| bin _time span=1m
| stats
    count AS endpoint_connections
    dc(DestinationIp) AS unique_destinations
    dc(ad_port) AS ad_port_count
    dc(smb_port) AS smb_port_count
    values(DestinationIp) AS endpoint_destination_ips
    values(DestinationPort) AS endpoint_ports
    by _time SourceIp host Image User
| where ad_port_count>=1
    AND smb_port_count>=1
    AND unique_destinations>=3
    AND endpoint_connections>=100
| rename SourceIp AS source_ip
| append [
    search index=zeek sourcetype="zeek:conn:json"
        ("id.resp_p"=389 OR "id.resp_p"=636)
    | bin _time span=1m
    | stats
        count AS zeek_connections
        sum(orig_bytes) AS bytes_sent
        sum(resp_bytes) AS bytes_received
        values("id.resp_p") AS zeek_destination_ports
        values(service) AS zeek_services
        values("id.resp_h") AS zeek_destination
        by _time "id.orig_h"
    | where zeek_connections>=100
        AND bytes_received>=10000000
    | rename "id.orig_h" AS source_ip
]
| append [
    search index=win_dc host="DC01" EventCode=5145
    | rex field=_raw "Name=['\"]IpAddress['\"]>(?<source_ip>[^<]+)"
    | rex field=_raw "Name=['\"]SubjectUserName['\"]>(?<dc_user>[^<]+)"
    | rex field=_raw "Name=['\"]ShareName['\"]>(?<dc_share>[^<]+)"
    | rex field=_raw "Name=['\"]RelativeTargetName['\"]>(?<dc_target>[^<]+)"
    | where source_ip!="::1"
    | bin _time span=1m
    | stats
        count AS dc_events
        values(dc_user) AS dc_users
        values(dc_share) AS dc_shares
        values(dc_target) AS dc_targets
        by _time source_ip
]
| stats
    values(host) AS host
    values(Image) AS Image
    values(User) AS User
    max(endpoint_connections) AS endpoint_connections
    max(unique_destinations) AS unique_destinations
    values(endpoint_ports) AS endpoint_ports
    max(zeek_connections) AS zeek_connections
    max(bytes_received) AS bytes_received
    values(zeek_services) AS zeek_services
    values(zeek_destination) AS zeek_destination
    max(dc_events) AS dc_events
    values(dc_users) AS dc_users
    values(dc_shares) AS dc_shares
    values(dc_targets) AS dc_targets
    by _time source_ip
| where isnotnull(endpoint_connections)
    AND isnotnull(zeek_connections)
    AND isnotnull(dc_events)
| table
    _time source_ip host Image User
    endpoint_connections unique_destinations endpoint_ports
    zeek_connections bytes_received zeek_services zeek_destination
    dc_events dc_users dc_shares dc_targets
| sort - _time
```

The SPL above preserves the validated correlation logic. The following optional analyst view was validated for concise display and is not a replacement for the authoritative search:

```spl
| eval endpoint_summary=endpoint_connections." conn / ".unique_destinations." dst / ports ".mvjoin(endpoint_ports,",")
| eval zeek_summary=zeek_connections." conn / ".round(bytes_received/1024/1024,2)." MB / ".mvjoin(zeek_services,",")
| eval dc_summary=dc_events." events / ".mvjoin(dc_shares,",")." / ".mvjoin(dc_targets,",")
| table _time source_ip host Image User endpoint_summary zeek_summary zeek_destination dc_summary
| sort - _time
```

## Validation Methodology

### Native AD discovery baseline

Native discovery was performed first to observe baseline behavior. The commands actually executed included:

```powershell
whoami
$env:COMPUTERNAME
nltest /dsgetdc:$env:USERDNSDOMAIN
net user /domain
net group "Domain Admins" /domain
```

The test confirmed `lab\administrator` on WIN-REDTEAM01, domain `lab.local`, and Domain Controller `\\DC01.lab.local` at `10.0.20.10`. Domain enumeration returned lab accounts including Administrator, alice.finance, bob.user, daniel.it, Guest, and krbtgt; Domain Admins included Administrator.

`Get-ADDomain` and `Get-ADForest` were attempted but failed because the ActiveDirectory PowerShell module was not installed. RSAT was intentionally not installed merely to make these commands work, and they are not represented as successful validation steps.

### Controlled SharpHound validation

SharpHound v2.14.0 was executed from the lab path `C:\RedTeam\AD\BloodHound\SharpHound\v2.14.0\SharpHound.exe` with `-c Default`. The successful run collected 314 objects in approximately 10.9 seconds.

SharpHound reported the following collection methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices, LdapServices, WebClientService, and SmbInfo. This does not mean that every possible SharpHound collection method was independently validated.

### Validated telemetry

- Sysmon produced approximately 118–121 initiated connections per one-minute bucket across four unique destinations using ports 389, 445, and 636.
- Zeek produced approximately 111–114 LDAP/LDAPS connections per one-minute bucket and approximately 15.7 MB of response traffic. Services included `ldap_tcp` and `ssl`; one run also showed `ldap_udp`.
- DC01 EventCode 5145 telemetry from `10.0.50.50` included `\\*\IPC$` access and observed targets NETLOGON, srvsvc, samr, and DAV RPC SERVICE.

## Validated Correlated Results

| Time | Image | User | Endpoint connections | Unique destinations | Zeek connections | Bytes received | DC events |
|---|---|---|---:|---:|---:|---:|---:|
| 14:35 | `ADInventory.exe` | `LAB\Administrator` | 118 | 4 | 111 | 16,457,012 | 5 |
| 14:00 | `SharpHound.exe` | `LAB\Administrator` | 120 | 4 | 114 | 16,470,761 | 5 |
| 13:59 | `SharpHound.exe` | `LAB\Administrator` | 120 | 4 | 113 | 16,490,179 | 4 |
| 11:11 | `SharpHound.exe` | `LAB\daniel.it` | 118 | 4 | 112 | 16,460,386 | 4 |

All four controlled findings correlated on `source_ip=10.0.50.50`.

## Rename-Resistance Validation

The binary was copied to the temporary lab path `C:\DET022-RenameTest\ADInventory.exe`. Microsoft Defender detected and quarantined it before execution as `HackTool:MSIL/SharpHound!rfn` and `Trojan:MSIL/SharpHound.VD!MTB`. This was not a Defender bypass.

For the controlled validation only, a temporary Defender exclusion was added for `C:\DET022-RenameTest`. The renamed binary was then executed, and DET-022 correlated its Sysmon, Zeek, and DC01 behavior as `ADInventory.exe` from `10.0.50.50`.

The demonstrated conclusion is limited: DET-022 did not require the filename `SharpHound.exe` for this tested behavior. It does not prove universal rename resistance, EDR or AV bypass, detection of every AD-reconnaissance tool, or production-grade evasion resistance.

## Controlled Cleanup

After testing, the temporary Defender exclusion was removed:

```powershell
Remove-MpPreference -ExclusionPath "C:\DET022-RenameTest"
```

`(Get-MpPreference).ExclusionPath` returned no configured exclusion for the path. The temporary directory was removed, and `Test-Path "C:\DET022-RenameTest"` returned `False`.

## Scheduled Alert

| Setting | Validated value |
|---|---|
| Alert name | `DET-022 - Behavioral Active Directory Reconnaissance` |
| Description | Correlates high-volume Sysmon, Zeek LDAP/LDAPS, and DC SMB-share activity by source IP and time window |
| Type | Scheduled |
| Cron | `*/5 * * * *` |
| Earliest / latest | `-10m@m` / `now` |
| Trigger condition | Number of Results > 0 |
| Trigger mode | For each result |
| Severity | High |
| Permissions | Shared in App |
| Action | Add to Triggered Alerts |
| Suppression field / duration | `source_ip` / 10 minutes |

The alert runs every five minutes over an overlapping ten-minute search window. Suppression by `source_ip` reduces repeated alerts for the same source while allowing another source IP to generate its own alert.

## Final End-to-End Validation

The final renamed-binary run completed at `2026-09-23 15:26:40 IDT`. SharpHound reported 314 objects and completed in `00:00:10.9187171`. The scheduled alert fired at `15:30:05 IDT` as a High-severity, scheduled, per-result alert.

The result showed WIN-REDTEAM01 / `10.0.50.50`, `ADInventory.exe`, `LAB\Administrator`, 121 endpoint connections, four unique destinations, endpoint ports 389/445/636, 114 Zeek connections, approximately 15.71 MB, Zeek destination `10.0.20.10`, and five DC events.

This validates the lab chain from controlled AD reconnaissance through Sysmon, Zeek, DC01 telemetry, Splunk correlation, scheduled execution, and Triggered Alerts.

## Evidence

1. [Zeek pre-attack telemetry validation](../../screenshots/DET-022-01-Zeek-PreAttack-Telemetry-Validation.png)
2. [Native AD reconnaissance Zeek telemetry](../../screenshots/DET-022-02-Native-AD-Recon-Zeek-Telemetry.png)
3. [SharpHound Zeek network footprint](../../screenshots/DET-022-03-SharpHound-Zeek-Network-Footprint.png)
4. [SharpHound Sysmon process creation](../../screenshots/DET-022-04-SharpHound-Sysmon-Process-Creation.png)
5. [DC01 SharpHound SMB access](../../screenshots/DET-022-05-DC01-SharpHound-SMB-Access.png)
6. [LDAP enumeration threshold validation](../../screenshots/DET-022-06-LDAP-Enumeration-Threshold-Validation.png)
7. [Behavioral AD reconnaissance in Sysmon](../../screenshots/DET-022-07-Behavioral-AD-Recon-Sysmon.png)
8. [Renamed-binary behavioral detection](../../screenshots/DET-022-08-Rename-Resistant-Behavioral-Detection.png)
9. [Final behavioral AD reconnaissance results](../../screenshots/DET-022-09-Final-Behavioral-AD-Recon-Detection.png)
10. [Triple-source correlated AD reconnaissance](../../screenshots/DET-022-10-Triple-Source-Correlated-AD-Recon.png)
11. [Source-IP triple correlation](../../screenshots/DET-022-11-SourceIP-Triple-Correlation.png)
12. [Final triggered-alert validation result](../../screenshots/DET-022-13-Triggered-Alert-Validated.png)

## MITRE ATT&CK

- [T1087.002 — Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [T1069.002 — Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/)

These mappings are limited to the validated domain-account and domain-group discovery behavior. Additional techniques are not inferred merely from SharpHound's broader capabilities.

## Potential False Positives

- Administrative inventory and directory-reporting workflows.
- Identity-management operations.
- Vulnerability and security scanning.
- Authorized AD administration or assessment tooling.

Requiring simultaneous endpoint, network, and DC signals raises confidence but does not eliminate legitimate high-volume behavior.

## Tuning Guidance

- Baseline expected LDAP/LDAPS and SMB activity.
- Tune by endpoint and server role.
- Adjust thresholds to the environment rather than copying the lab values unchanged.
- Allowlist known administrative systems only after validating their behavior.
- Monitor high-volume directory-enumeration patterns and changes in normal volume.

The following are lab-specific thresholds: `endpoint_connections>=100`, `unique_destinations>=3`, `zeek_connections>=100`, and `bytes_received>=10000000`.

## Known Limitations

- The current implementation requires matching one-minute event-time buckets and `source_ip` across all three sources.
- Ingestion latency and clock differences may justify a wider correlation tolerance in another environment; the validated query is not silently changed here.
- NAT or shared source addresses can weaken source-IP attribution.
- ZEEK01 has documented partial passive visibility on VMnet6.
- High thresholds can miss slower or distributed reconnaissance.
- The logic was validated against native discovery and controlled SharpHound behavior, not every AD-reconnaissance technique or BloodHound implementation.
- Renamed-binary validation covers one controlled rename of the same binary and is not a universal evasion-resistance claim.
- The detection is lab-tuned and not represented as production-ready.

## Analyst Triage

1. Review the source host, user, process path, and one-minute event bucket.
2. Confirm whether the endpoint role reasonably requires high-volume LDAP/LDAPS and SMB activity.
3. Review endpoint destinations and ports, Zeek service and byte context, and DC share/target names.
4. Search surrounding Sysmon process and network events for parent process and command-line context.
5. Review relevant authentication and account activity on DC01.
6. Check approved administration, inventory, identity-management, and security-scanning schedules.
7. Escalate only when the correlated behavior and environment context support suspicious reconnaissance.

## Detection Engineering Lessons Learned

- Behavioral multi-source correlation is more resilient than a filename-only condition.
- Baseline collection is necessary before selecting volume thresholds.
- Endpoint, network, and Domain Controller signals provide complementary context.
- Event-time bucketing is deterministic in the lab but should be tested against real ingestion and clock behavior.
- Suppression should preserve distinct sources while reducing duplicate alerts from overlapping scheduled windows.
- Temporary security-control changes require explicit cleanup and validation.

## Interview Summary

> I built an Active Directory reconnaissance detection that does not depend on a known filename such as SharpHound.exe. I correlated Sysmon endpoint behavior, Zeek LDAP/LDAPS network telemetry, and Windows Security telemetry from the Domain Controller using source IP and an event-time window. After baselining and tuning the lab, I renamed SharpHound to ADInventory.exe and confirmed that the behavioral detection and scheduled alert still fired. I then removed the temporary Defender exclusion and test directory.

## Related Documentation

- [Splunk Detection Catalog](README.md)
- [ZEEK01 Deployment and Telemetry](../../docs/zeek01-deployment-and-telemetry.md)
- [Lab Architecture — ASCII Reference](../../docs/lab-architecture-ascii.md)

## Status

**Validated** — the final lab search correlated Sysmon, Zeek, and DC01 telemetry for four controlled runs, including a renamed-binary run, and the scheduled High-severity alert produced a Triggered Alert result. The detection remains lab-tuned and is not represented as universal, evasive-resistant, or production-ready.
