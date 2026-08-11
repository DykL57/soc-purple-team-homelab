# DET-005 — Vertical Port Scan

## Overview

Detects one source touching many destination ports on one destination host within one minute.

## Threat Behavior

Attackers enumerate listening services before selecting an exploitation or lateral-movement path.

## Data Sources

- pfSense `filterlog` events via syslog in `index=pfsense`

## MITRE ATT&CK

- T1046 — Network Service Discovery

## Detection Logic

Parse IPv4 source, destination, and port fields; count distinct destination ports per source/destination pair; alert at ten or more ports in one minute.

## SPL

```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<src_port>\d+),(?<dst_port>\d+)"
| bin _time span=1m
| stats dc(dst_port) as unique_ports_tried, count as attempts by src_ip, dst_ip, _time
| where unique_ports_tried >= 10
| stats sum(attempts) as total_attempts, max(unique_ports_tried) as max_ports_per_min by src_ip, dst_ip
```

## Validation

KALI-OPS01 scanned ports 1–1000 on the pfSense LAN interface after a controlled route was added between the attack and server zones.

## Attack Simulation

```bash
nmap -sS -p 1-1000 10.0.20.1
```

## Detection Result

The search identified 759 unique destination ports from `10.0.50.60` to `10.0.20.1` in one minute. nmap reported three open and 997 filtered ports.

![DET-005 alert](../../screenshots/rule05-alert.png)

## False Positives

Vulnerability scanners, asset discovery, monitoring systems, and high-volume NAT gateways can create similar patterns.

## Investigation Steps

Identify the source asset, verify whether scanning was authorized, review targets and timing, and correlate with firewall outcomes and later authentication or exploitation attempts.

## Tuning Recommendations

Baseline and raise the lab threshold, allowlist approved scanners, and create separate horizontal-scan coverage.

## Known Limitations

The threshold of ten is intentionally low. This detects vertical scans and does not independently determine malicious intent.

## Evidence

- [Alert screenshot](../../screenshots/rule05-alert.png)

## Status

**Validated** — validated in the lab; not represented as production-ready.
