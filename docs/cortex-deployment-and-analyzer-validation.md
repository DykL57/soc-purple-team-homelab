# CORTEX01 Deployment and Analyzer Validation

## Purpose and status

CORTEX01 is the lab's active Cortex system for security analysis, analyzer execution, and enrichment.

| Property | Verified value |
|---|---|
| Hostname | `CORTEX01` |
| Operating system | Ubuntu Server |
| Network | VMnet3 / `10.0.20.0/24` |
| IP address | `10.0.20.125` |
| Role | Cortex analysis / analyzer execution / security enrichment |
| Status | Active |

## Validated deployment state

- Cortex is operational.
- Cortex web access is operational.
- The analyzer catalog is available.
- `TestAnalyzer_1_0` was executed successfully.
- The analyzer execution result was `Success`.
- High-level integration from THEHIVE01 to Cortex was validated successfully.

## Scope and security notes

Successful `TestAnalyzer_1_0` validation does not imply that every available analyzer is configured or production-ready. No additional analyzers, responders, automation, or external integrations are claimed. This document intentionally excludes API keys, analyzer credentials, passwords, tokens, secrets, and private keys.
