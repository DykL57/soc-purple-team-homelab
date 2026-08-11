# DET-003 — PsExec Service Creation

## Overview

Detects the Windows service installation behavior used by PsExec for remote execution.

## Threat Behavior

An actor with valid credentials can copy a binary through an administrative SMB share and create a remote service to execute it.

## Data Sources

- Windows System Event 7045 from DC01

## MITRE ATT&CK

- T1021.002 — SMB/Windows Admin Shares
- T1569.002 — Service Execution

## Detection Logic

Extract service details from raw Event 7045 text and match the default `PSEXESVC` service or binary name.

## SPL

```spl
index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| rex field=_raw "Service Name:\s+(?<ServiceName>\S+)"
| rex field=_raw "Service File Name:\s+(?<ServiceFileName>.+?)\s+Service Type:"
| rex field=_raw "Service Account:\s+(?<ServiceAccount>\S+)"
| search ServiceName="PSEXESVC" OR ServiceFileName="*PSEXESVC*"
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceAccount, Sid
```

## Validation

PsExec was run from WIN-CL01 against DC01 using a disposable lab account with the required service-logon right.

## Attack Simulation

The test created a disposable domain account, temporarily granted the required rights, ran `PsExec.exe \\DC01 ... whoami`, and removed the account and membership afterward.

## Detection Result

The search captured the service installations and extracted `PSEXESVC`, its path, `LocalSystem`, and the installing account SID. The returned remote identity was `lab\simlateral`.

![DET-003 alert](../../screenshots/rule03-alert.png)

## False Positives

Software deployment, endpoint management, backup, and help-desk tools can legitimately install services remotely.

## Investigation Steps

Identify the installer through `Sid`, review the source host and administrative-share activity, inspect the service binary, and correlate with Sysmon process creation.

## Tuning Recommendations

Use a broader service-name-agnostic version for renamed binaries, allowlist verified deployment infrastructure, and correlate with Event 5145 and Sysmon Event 1.

## Known Limitations

The narrow query misses renamed PsExec services. Event 7045 fields are not extracted by the current Windows TA. A CIM Change migration was attempted but required missing field-level mappings, so the working raw search was retained.

## Evidence

- [Alert screenshot](../../screenshots/rule03-alert.png)
- [CIM investigation notes](../../docs/lab-engineering-notes.md#cim-and-tstats)

## Status

**Validated** — validated in the lab; not represented as production-ready.
