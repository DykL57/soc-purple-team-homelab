# DET-001 — Brute-Force Authentication

## Overview

Detects three or more failed authentication attempts from one destination host in a five-minute window and assigns severity based on volume.

## Threat Behavior

Repeated password guessing may indicate brute-force access attempts against one or more accounts.

## Data Sources

- Windows Security Event 4625
- Splunk CIM Authentication data model

## MITRE ATT&CK

- T1110 — Brute Force

## Detection Logic

Aggregate failed authentications by destination and five-minute window. Report at three failures; score 10 or more as High and 20 or more as Critical.

## SPL

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

## Validation

Five intentionally failed authentication attempts were generated and recorded as five Event 4625 entries.

## Attack Simulation

A PowerShell `LogonUser` loop submitted five invalid passwords against the lab Administrator account. The original command is preserved in repository history; no password was committed.

## Detection Result

The search aggregated all five failures into one Medium-severity result.

![DET-001 alert](../../screenshots/rule01-alert.png)

## False Positives

Mistyped passwords, stale service credentials, vulnerability scanners, and misconfigured applications can produce repeated failures.

## Investigation Steps

Confirm the affected host and accounts, determine the source activity, review adjacent successful logons, and check whether the failures align with known administration.

## Tuning Recommendations

Raise the threshold to 5–10 after baselining and allowlist verified scanners or service accounts.

## Known Limitations

The lab threshold is intentionally sensitive. This version groups by destination and does not preserve a source IP.

## Evidence

- [Alert screenshot](../../screenshots/rule01-alert.png)

## Status

**Validated** — validated in the lab; not represented as production-ready.
