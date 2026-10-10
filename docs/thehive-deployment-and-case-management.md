# THEHIVE01 Deployment and Case Management

## Purpose and status

THEHIVE01 is the lab's active TheHive system for incident response, case management, and SOC investigation management.

| Property | Verified value |
|---|---|
| Hostname | `THEHIVE01` |
| Operating system | Ubuntu Server |
| Network | VMnet3 / `10.0.20.0/24` |
| IP address | `10.0.20.124` |
| Role | Incident response / case management / SOC investigation management |
| Status | Active |

## Validated deployment state

- TheHive service is operational.
- Cassandra is operational.
- Elasticsearch is operational.
- TheHive web access was validated successfully.
- High-level integration from TheHive to CORTEX01 was validated successfully.

## Scope and security notes

The available validation does not establish additional responders, automation, external integrations, or production readiness. This document intentionally excludes credentials, passwords, API keys, tokens, secrets, private keys, sensitive configuration, and private URLs.
