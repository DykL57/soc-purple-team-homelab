# SOC & Purple Team Home Lab

## Overview

This repository documents a segmented, enterprise-style home lab used to practice SOC operations, adversary simulation, SIEM engineering, and detection validation. It demonstrates how Windows and network telemetry is collected in Splunk Enterprise, turned into defensible detections, tested in a controlled environment, and investigated with known limitations preserved.

> This lab uses **Splunk Enterprise**, not Splunk Enterprise Security. Suricata is installed on pfSense, but Suricata alert ingestion into Splunk is not yet complete.

## Architecture

![SOC and Purple Team home lab architecture](screenshots/Network-Architecture-Diagram_2.png)

pfSense is the only routing path between isolated VMware host-only networks. Its WAN receives a private RFC1918 address from the upstream router; the upstream router, not pfSense's WAN address, provides Internet-facing NAT.

## What I Built

- Active Directory domain services and DNS on Windows Server 2022
- Two domain-joined Windows endpoints with Sysmon and Splunk Universal Forwarder
- pfSense routing, firewall policy, DHCP, and Suricata IDS/IPS across segmented zones
- Splunk Enterprise pipelines for Windows telemetry and pfSense syslog
- Seven documented Splunk detections with attack or traffic-based validation evidence
- CIM-based `tstats` searches for authentication use cases and documented raw-search fallbacks where field mappings are incomplete

## Key Project Highlights

- Validated seven detections spanning authentication, lateral movement, reconnaissance, network activity, and PowerShell execution.
- Identified 759 distinct destination ports touched in one minute during controlled vertical-scan validation.
- Captured 2,651 failed SMB logons against a local Administrator account and documented the Windows RID 500 lockout limitation.
- Investigated stale GeoLite2 results, confirmed the observed hits as false positives, and added VirusTotal enrichment to the existing search workflow.
- Preserved root-cause findings for CIM mapping, Windows log placement, DHCP configuration, timestamps, and WAN stability in [Lab Engineering Notes](docs/lab-engineering-notes.md).

## Technology Stack

| Component | Purpose |
|---|---|
| Windows Server 2022 | Active Directory Domain Services and DNS |
| Windows 10 endpoints | Domain-joined detection targets |
| Splunk Enterprise | Log aggregation, SPL searches, and alerting |
| Splunk Universal Forwarder + Sysmon | Endpoint telemetry collection |
| Splunk CIM Add-on | Authentication data-model normalization |
| pfSense CE 2.8.1 | Routing, firewalling, DHCP, and syslog |
| Suricata | IDS/IPS installed and integrated with pfSense; Splunk ingestion pending |
| Kali Linux | Controlled attack-simulation platform |
| VMware Workstation | Virtualization and network segmentation |

## Network / Security Zones

| Zone | Subnet | Systems | Purpose |
|---|---|---|---|
| Servers | `10.0.20.0/24` | DC01, SPLUNK01 | Identity, DNS, and SIEM services |
| Clients | `10.0.30.0/24` | WIN-CL01, WIN-CL02 | Domain-joined endpoints |
| Sensor / Attack | `10.0.50.0/24` | KALI-OPS01 | Controlled adversary simulation |
| Gateway | Multiple interfaces | PFSENSE01 | Deny-by-default inter-zone routing and WAN access |

## Telemetry & Logging Pipeline

```text
Windows Security/System logs + Sysmon
                │
       Splunk Universal Forwarder
                │
                ├──────────────► Splunk Enterprise
                │
pfSense firewall/system/DHCP ──► UDP 5514 syslog

Suricata on pfSense ──► Splunk ingestion not yet implemented
```

Windows telemetry is stored in dedicated Splunk indexes. pfSense forwards firewall, system, and DHCP events for network visibility. Suricata operates on pfSense, but its alerts are not yet part of the Splunk pipeline.

## Detection Engineering

| ID | Detection | Primary data source | MITRE ATT&CK | Status |
|---|---|---|---|---|
| [DET-001](detections/splunk/DET-001-brute-force-authentication.md) | Brute-force authentication | Windows Security 4625 / CIM Authentication | T1110 | Validated |
| [DET-002](detections/splunk/DET-002-success-after-failures.md) | Success after failures | Windows Security 4624/4625 / CIM Authentication | T1078 | Validated |
| [DET-003](detections/splunk/DET-003-psexec-service-creation.md) | PsExec service creation | Windows System 7045 | T1021.002, T1569.002 | Validated |
| [DET-004](detections/splunk/DET-004-risky-geolocation-traffic.md) | Risky geolocation traffic | pfSense `filterlog` | T1071 | Experimental |
| [DET-005](detections/splunk/DET-005-vertical-port-scan.md) | Vertical port scan | pfSense `filterlog` | T1046 | Validated |
| [DET-006](detections/splunk/DET-006-local-admin-smb-brute-force.md) | Local Administrator SMB brute force | Windows Security 4625 | T1110.001 | Validated |
| [DET-007](detections/splunk/DET-007-encoded-powershell.md) | Encoded PowerShell | Sysmon 1 | T1059.001 | Validated |

See the complete [Splunk Detection Catalog](detections/splunk/README.md).

## Featured Detection Case Studies

- [DET-003 — PsExec Service Creation](detections/splunk/DET-003-psexec-service-creation.md): distinguishes the service's `LocalSystem` account from the SID that installed it and documents why the CIM Change model was not used.
- [DET-005 — Vertical Port Scan](detections/splunk/DET-005-vertical-port-scan.md): validates a network pattern against a controlled 1,000-port scan through pfSense.
- [DET-006 — Local Administrator SMB Brute Force](detections/splunk/DET-006-local-admin-smb-brute-force.md): captures a sustained password-guessing test and records the unresolved CIM `src` mapping gap.

## Repository Structure / Navigation

```text
.
├── README.md
├── detections/
│   └── splunk/                  # Catalog and DET-001 through DET-007
├── docs/
│   ├── lab-engineering-notes.md
│   ├── splunk_index_precedence_EN.md
│   └── troubleshooting-pfsense-bridged-wan-dhcp-conflict.md
└── screenshots/                # Detection and architecture evidence
```

## Current Status / Known Limitations

- Seven detections are documented; none are claimed to be production-ready.
- DET-004 remains Experimental because geo-IP is a weak signal and both validation hits were confirmed as false positives.
- DET-003 remains a raw search because Windows Event 7045 lacks the required CIM Change field extractions in the current configuration.
- DET-006 remains a raw search because the CIM `Authentication.src` override is unresolved.
- Suricata is installed and integrated with pfSense, but Suricata alert ingestion into Splunk is incomplete.
- The pfSense WAN uses a private upstream address and a Wi-Fi bridge; the private address is not publicly routable, and the Wi-Fi uplink has shown stability issues.

## Roadmap

- [ ] Ingest Suricata alerts into Splunk and validate the pipeline
- [ ] Build Suricata-backed detection use cases
- [ ] Resolve DET-006 CIM source-address mapping and assess a `tstats` migration
- [ ] Add horizontal port-scan coverage
- [ ] Replace the Wi-Fi WAN bridge with a dedicated wired adapter
- [ ] Add persistent caching for VirusTotal enrichment
- [ ] Expand detections into persistence, command-and-control, and exfiltration scenarios

## About / Contact

I'm Daniel, a SOC analyst focused on Splunk Enterprise, detection engineering, threat hunting, and blue-team operations.

- [LinkedIn](https://www.linkedin.com/in/danielluchter/)
- [GitHub](https://github.com/DykL57/)
