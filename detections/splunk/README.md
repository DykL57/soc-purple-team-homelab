# Splunk Detection Catalog

The catalog links each detection to its logic, validation evidence, limitations, and analyst guidance. Statuses describe the evidence in this lab, not production deployment readiness.

| ID | Detection | Data Source | MITRE ATT&CK | Status | Documentation |
|---|---|---|---|---|---|
| DET-001 | Brute-force authentication | Windows Security 4625 / CIM Authentication | T1110 | Validated | [DET-001](DET-001-brute-force-authentication.md) |
| DET-002 | Success after failures | Windows Security 4624/4625 / CIM Authentication | T1078 | Validated | [DET-002](DET-002-success-after-failures.md) |
| DET-003 | PsExec service creation | Windows System 7045 | T1021.002, T1569.002 | Validated | [DET-003](DET-003-psexec-service-creation.md) |
| DET-004 | Risky geolocation traffic | pfSense `filterlog` | N/A / Context-dependent | Experimental | [DET-004](DET-004-risky-geolocation-traffic.md) |
| DET-005 | Vertical port scan | pfSense `filterlog` | T1046 | Validated | [DET-005](DET-005-vertical-port-scan.md) |
| DET-006 | Local Administrator SMB brute force | Windows Security 4625 | T1110.001 | Validated | [DET-006](DET-006-local-admin-smb-brute-force.md) |
| DET-007 | Encoded PowerShell | Sysmon 1 | T1059.001 | Validated | [DET-007](DET-007-encoded-powershell.md) |
| DET-008 | Windows Whoami User Discovery | Sysmon 1 | T1033 | Validated | [DET-008](DET-008-whoami-user-discovery.md) |
| DET-009 | Sliver C2 Communication | Sysmon 3 | T1071 | Validated | [DET-009](DET-009-sliver-c2-communication.md) |
| DET-010 | Suspicious Network Service Scanning | pfSense `pfsense:firewall` | T1046 | Validated | [DET-010](DET-010-suspicious-network-service-scanning.md) |
| DET-011 | Suspicious Write to Sensitive SMB Share | Windows Security 5145 | N/A / Context-dependent | Validated | [DET-011](DET-011-suspicious-write-to-sensitive-smb-share.md) |
| DET-012 | PowerShell Download Activity | Sysmon 1 | T1059.001 | Validated | [DET-012](DET-012-powershell-download-activity.md) |

[Return to the project overview](../../README.md)
