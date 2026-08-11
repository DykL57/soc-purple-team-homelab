# DET-006 — Local Administrator SMB Brute Force

## Overview

Detects sustained failed SMB authentication against the built-in local Administrator account.

## Threat Behavior

An attacker can repeatedly guess a known local Administrator password over SMB. Windows treats the RID 500 account differently from standard accounts, which can allow many failures without lockout under default policy.

## Data Sources

- Windows Security Event 4625 from WIN-CL01

## MITRE ATT&CK

- T1110.001 — Password Guessing

## Detection Logic

Extract source IP, target user, logon type, and substatus from raw XML; return more than ten failures against the local Administrator account.

## SPL

```spl
index=wineventlog EventCode=4625 Channel=Security host=WIN-CL01
| rex field=_raw "Name='TargetUserName'>(?<TargetUserName>[^<]*)"
| rex field=_raw "Name='IpAddress'>(?<IpAddress>[^<]+)"
| rex field=_raw "Name='LogonType'>(?<LogonType>[^<]+)"
| rex field=_raw "Name='SubStatus'>(?<SubStatus>[^<]+)"
| stats count as failed_attempts, values(SubStatus) as SubStatus_codes, earliest(_time) as first_attempt, latest(_time) as last_attempt by IpAddress, TargetUserName
| where failed_attempts > 10 AND (TargetUserName="administrator" OR TargetUserName="Administrator")
| sort - failed_attempts
```

## Validation

NetExec generated SMB password guesses from KALI-OPS01 against WIN-CL01.

## Attack Simulation

```bash
nxc smb 10.0.30.100 -u administrator -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding
```

## Detection Result

The search found 2,651 failures from `10.0.50.60` over about 16.5 hours, all with `0xc000006a` (`STATUS_WRONG_PASSWORD`).

![DET-006 attack simulation](../../screenshots/rule06-alert.png)

![DET-006 result](../../screenshots/rule06-alert-results.png)

## False Positives

Stale credentials, administrative scripts, vulnerability scanning, or an approved password audit may generate repeated SMB failures.

## Investigation Steps

Confirm the source system and authorization, review the target's local-account policy, inspect adjacent successes, and check for NTLM relay exposure or follow-on activity.

## Tuning Recommendations

Disable or restrict remote use of the built-in Administrator account, deploy LAPS, baseline approved scanners, and resolve the CIM source-address mapping before considering `tstats`.

## Known Limitations

The query is host-specific and raw-search based. Attempts to override CIM `Authentication.src` were unsuccessful, although a custom `attacker_ip` extraction worked. SMB signing was observed disabled during testing, but this detection does not test for relay activity.

## Evidence

- [Simulation screenshot](../../screenshots/rule06-alert.png)
- [Detection result](../../screenshots/rule06-alert-results.png)
- [CIM debug screenshot](../../screenshots/rule06-cim-debug.png)

## Status

**Validated** — validated in the lab; not represented as production-ready.
