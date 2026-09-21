# ELASTIC-SRV01 and WIN-EDR01 Deployment and Telemetry

## Purpose

ELASTIC-SRV01 adds Elastic Stack, Elastic Security, and Fleet management to the home SOC lab. WIN-EDR01 is a dedicated Windows EDR validation endpoint running Elastic Agent with the Elastic Defend integration. The platform complements Splunk Enterprise; it does not replace Splunk and no Splunk-to-Elastic integration is implemented or claimed.

## Validated Systems

| System | Network | IP | Validated role |
|---|---|---|---|
| ELASTIC-SRV01 | VMnet3 / Infrastructure | `10.0.20.50` | Elastic Stack, Elastic Security analysis, Kibana, and Fleet Server |
| WIN-EDR01 | VMnet6 / Red Team / Targets / Simulation | `10.0.50.111` | Controlled Windows EDR test endpoint with Elastic Agent and Elastic Defend |

The supplied build evidence identifies ELASTIC-SRV01 as Ubuntu Server 26.04 LTS. The validated Elastic views show Elastic/Fleet 9.5.4 and Elastic Defend integration 9.5.0. These versions describe the evidence snapshot and should be rechecked after upgrades.

## Architecture and Telemetry Flow

```text
WIN-EDR01 (`10.0.50.111`, VMnet6)
    └─ Elastic Agent + Elastic Defend
           ├─ process and PowerShell telemetry
           ├─ network telemetry
           └─ file telemetry
                    │
                    └─ TCP/8220 ─► ELASTIC-SRV01 (`10.0.20.50`, VMnet3)
                                         ├─ Fleet Server / agent management
                                         └─ Elastic Security / Kibana analysis and alerting
```

The implemented relationship is direct Elastic endpoint telemetry from WIN-EDR01 to ELASTIC-SRV01. Existing Splunk ingestion paths remain unchanged and separate.

## Health Validation

- Fleet Server was healthy on ELASTIC-SRV01.
- The WIN-EDR01 agent policy included Elastic Defend and the System integration.
- WIN-EDR01 had a healthy current Elastic Agent record.
- The Elastic Defend endpoint for WIN-EDR01 was healthy.

The Fleet screenshot also contains historical/offline WIN-EDR01 records. They are preserved as historical UI context and are not described as the current agent state.

## Telemetry Validation

The deployment validation confirmed the following event categories in Elastic:

- General process activity from WIN-EDR01.
- Ordinary PowerShell execution telemetry.
- Encoded PowerShell command-line telemetry.
- Network events for WIN-EDR01 (`10.0.50.111`) communicating with ELASTIC-SRV01 (`10.0.20.50`) on TCP/8220.
- Controlled file creation by `powershell.exe`.

These observations validate endpoint collection and search visibility. They do not independently establish malicious intent or successful detection.

## Elastic Security Detection Validation

The controlled suspicious PowerShell scenario generated the Elastic Security alert `Suspicious Windows Powershell Arguments` on WIN-EDR01. The evidence shows Medium severity, risk score 47, `powershell.exe`, and investigation details linked to the source endpoint event.

The detection result is documented in [DET-021 — Suspicious Encoded PowerShell Execution](../detections/elastic/DET-021-suspicious-encoded-powershell-execution.md).

Alerting was validated separately from endpoint health and telemetry collection. No supplied evidence proves that Elastic prevented or blocked the PowerShell execution.

## Evidence Index

| Evidence | What it supports |
|---|---|
| [Fleet Server health](../screenshots/ELASTIC-SRV01-10-fleet-server-healthy-kibana.png) | ELASTIC-SRV01 Fleet Server health |
| [Agent policy integrations](../screenshots/WIN-EDR01-07-agent-policy-integrations.png) | Elastic Defend and System integration assignment |
| [Elastic Agent health](../screenshots/WIN-EDR01-09-fleet-agent-healthy.png) | Current WIN-EDR01 agent health, alongside historical/offline records |
| [Elastic Defend endpoint health](../screenshots/WIN-EDR01-10-elastic-defend-endpoint-healthy.png) | Endpoint protection integration health |
| [Process telemetry](../screenshots/WIN-EDR01-11-elastic-defend-process-telemetry.png) | Endpoint process collection |
| [PowerShell telemetry](../screenshots/WIN-EDR01-12-elastic-defend-powershell-telemetry-validation.png) | Controlled PowerShell process visibility |
| [Encoded PowerShell telemetry](../screenshots/WIN-EDR01-15-elastic-defend-encoded-powershell-telemetry.png) | Encoded-command visibility |
| [Network telemetry](../screenshots/WIN-EDR01-13-elastic-defend-network-telemetry-validation.png) | WIN-EDR01 to ELASTIC-SRV01 TCP/8220 events |
| [File telemetry](../screenshots/WIN-EDR01-14-elastic-defend-file-telemetry-validation.png) | Controlled file-creation visibility |
| [Suspicious PowerShell alert](../screenshots/WIN-EDR01-11-suspicious-powershell-alert.png) | Elastic Security alert generation |
| [Alert investigation details](../screenshots/WIN-EDR01-12-powershell-alert-details.png) | Analyst investigation context |

## Operational and Security Notes

- Enrollment tokens, API keys, authentication material, cookies, and private keys must never be committed.
- Do not publish full exported configurations until sensitive values are removed and the result is reviewed.
- Restrict platform and Fleet access to authorized management paths.
- Confirm agent and endpoint health before drawing conclusions from missing telemetry.
- Retain controlled-test context so authorized simulations are not mistaken for real compromise.
- Revalidate versions, integration health, and detection behavior after upgrades.
- The deployment is a home-lab implementation and is not represented as production-ready.

## Known Limitations

- The evidence validates process, PowerShell, network, and file telemetry from one controlled endpoint.
- The supplied evidence does not prove prevention or blocking.
- The full Elastic Security rule export and exact query were not supplied.
- A single successful controlled validation does not establish enterprise-wide coverage, resilience, or performance.
- Elastic and Splunk remain independent platforms in the current lab.

## Required Future Visual Architecture Update

The current Diagram_10 PNG variants remain historical 17-system views and are intentionally unchanged in this work. A future visual revision should:

1. Add ELASTIC-SRV01 (`10.0.20.50`) to VMnet3.
2. Add WIN-EDR01 (`10.0.50.111`) to VMnet6.
3. Add a direct `Elastic Agent / Elastic Defend telemetry` path from WIN-EDR01 to ELASTIC-SRV01.
4. Show Elastic Security as an additional detection and analysis platform alongside Splunk Enterprise.
5. Update the visual system total from 17 to 19.
6. Preserve all existing network zones, ZEEK01 passive-sensor semantics, and complete VMnet9 isolation.
7. Avoid adding a Splunk-to-Elastic connection because none is implemented.
