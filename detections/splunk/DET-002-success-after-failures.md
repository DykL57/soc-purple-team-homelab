# DET-002 — Successful Authentication After Failures

## Overview

Detects an account with five or more failures followed by at least one success in the same ten-minute window.

## Threat Behavior

A successful login after repeated failures can indicate password guessing that eventually found valid credentials.

## Data Sources

- Windows Security Events 4624 and 4625
- Splunk CIM Authentication data model

## MITRE ATT&CK

- T1078 — Valid Accounts

## Detection Logic

Count failed and successful authentication actions per account in ten-minute buckets; return buckets with at least five failures and one success.

## SPL

```spl
| tstats count(eval(Authentication.action="failure")) as fail_count,
         count(eval(Authentication.action="success")) as success_count,
         earliest(_time) as first_seen, latest(_time) as last_seen
    from datamodel=Authentication
    by Authentication.user, _time span=10m
| where fail_count >= 5 AND success_count > 0
| rename Authentication.user as Account_Name
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, Account_Name, fail_count, success_count
```

## Validation

The `simtest` lab account generated five failures followed by one successful logon.

## Attack Simulation

PowerShell launched five processes with intentionally invalid credentials and then one with a securely entered valid password.

## Detection Result

The search correlated the five failures and one success into one result.

![DET-002 result](../../screenshots/rule02-alert-results.png)

## False Positives

Users correcting a forgotten password, password rotation delays, and noisy service accounts can create the same sequence.

## Investigation Steps

Review the account, host, source context, privilege level, and activity immediately after the success.

## Tuning Recommendations

Exclude verified noisy service accounts and adjust the failure threshold for shared-workstation environments.

## Known Limitations

`Source_Network_Address` is not exposed by the default CIM Authentication fields used here. A raw Event 4624/4625 search is required when source-IP context is essential.

## Evidence

- [Detection result](../../screenshots/rule02-alert-results.png)

## Status

**Validated** — validated in the lab; not represented as production-ready.
