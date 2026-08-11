# DET-004 — Risky Geolocation Traffic

## Overview

Flags outbound pfSense traffic geolocated to a configurable country watchlist and enriches unique destination IPs with VirusTotal reputation fields.

## Threat Behavior

Unexpected outbound traffic to infrastructure associated with a monitored region can support C2 triage, but geolocation alone is weak evidence.

## Data Sources

- pfSense `filterlog` events via syslog in `index=pfsense`
- Splunk `iplocation`
- VirusTotal scripted lookup configured on the Splunk server

## MITRE ATT&CK

**N/A / Context-dependent.** The available evidence identifies geolocation-based network context but does not demonstrate application-layer command-and-control behavior.

## Detection Logic

Parse outbound IPv4 firewall events, exclude loopback and lab RFC1918 destinations, geolocate public destinations, filter to the watchlist, and enrich each unique destination with VirusTotal.

## SPL

```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4" AND direction="out"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| where dst_ip!="127.0.0.1" AND NOT match(dst_ip, "^10\.") AND NOT match(dst_ip, "^192\.168\.")
| iplocation dst_ip
| search Country IN ("Iran", "Russia", "North Korea", "Syria", "China")
| dedup dst_ip
| lookup vt_ip_reputation dst_ip
| stats count, values(dst_ip) as dest_ips, values(vt_malicious) as vt_malicious, values(vt_country) as vt_country by src_ip, Country
```

## Validation

The search was evaluated against approximately 8,300 organic outbound events collected during normal lab operation.

## Attack Simulation

No synthetic attack was performed. Validation used normal outbound traffic.

## Detection Result

The search returned four connections geolocated to Iran and two to Russia. Manual VirusTotal review showed both destination IPs were legitimate infrastructure and the geo-IP results were stale or incorrect.

![DET-004 alert](../../screenshots/rule04-alert.png)

## False Positives

Stale geolocation data, CDN or cloud addressing, and globally distributed infrastructure can generate matches. Both observed lab matches were false positives.

## Investigation Steps

Validate ownership, ASN, reputation, destination port, process or host context, and historical prevalence before escalation.

## Tuning Recommendations

Add persistent reputation caching, a second reputation source, ASN context, and known-infrastructure allowlists. Escalate only when stronger evidence accompanies geolocation.

## Known Limitations

Geo-IP is a weak signal. The repository does not contain the scripted lookup source, only documentation of its server-side configuration and observed validation. VirusTotal free-tier limits also constrain scale.

## Evidence

- [Alert screenshot](../../screenshots/rule04-alert.png)

## Status

**Experimental** — the pipeline was exercised, but the observed matches were false positives.
