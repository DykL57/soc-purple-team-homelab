# PHISH-GOPHISH Deployment and Telemetry

## Overview

PHISH-GOPHISH is the dedicated GoPhish host used for authorized internal phishing simulations in the SOC and Purple Team home lab. This document covers the deployed service, administration, logging, Splunk forwarding, and persistence. The end-to-end mail and campaign workflow is documented separately.

| Field | Validated value |
|---|---|
| Display name / hostname | PHISH-GOPHISH / `phish-gophish` |
| Operating system | Ubuntu 26.04.1 LTS, x86-64 |
| Virtualization | VMware |
| Network | VMnet6 / Red Team — `10.0.50.0/24` |
| IP / gateway | `10.0.50.70/24` / `10.0.50.1` |
| GoPhish | 0.12.1 |
| Splunk Universal Forwarder | 10.4.3 |

## Architecture / Network Placement

PHISH-GOPHISH resides on VMnet6. Its phishing listener is available internally on HTTP TCP/80. The administrative interface is not exposed directly to VMnet6.

```text
PHISH-GOPHISH 10.0.50.70/24
  -> VMnet6 / Red Team segment
  -> gateway 10.0.50.1
  -> phishing listener HTTP TCP/80
  -> local-only admin listener HTTPS 127.0.0.1:3333
```

## Service Configuration

| Setting | Validated value |
|---|---|
| Install path | `/opt/gophish` |
| Service | `gophish.service` |
| Service account | `gophish:gophish` |
| Working directory | `/opt/gophish` |
| Executable | `/opt/gophish/gophish` |
| Restart policy / delay | `on-failure` / 5 seconds |
| Runtime / boot state | Active / Enabled |

```ini
[Service]
User=gophish
Group=gophish
WorkingDirectory=/opt/gophish
ExecStart=/opt/gophish/gophish
Restart=on-failure
RestartSec=5
```

Only the operational settings needed to explain the deployment are shown. The complete GoPhish configuration is intentionally not published.

## Administration Model

The GoPhish administrative interface is bound to `https://127.0.0.1:3333`. Remote administration is performed through an SSH tunnel, so the interface is not directly reachable from VMnet6. The phishing listener is separate and listens on HTTP TCP/80 for controlled internal exercises.

## Logging

GoPhish writes application telemetry at `info` level to `/var/log/gophish/gophish.log`.

## Log Rotation

The validated logrotate policy is:

```text
daily
rotate 14
compress
delaycompress
missingok
notifempty
copytruncate
```

`copytruncate` is used because GoPhish keeps the active log file open. In this lab, it permits rotation without depending on application restart or log-reopen behavior.

A forced rotation was validated: GoPhish remained active, the active log was truncated correctly, GoPhish continued writing, the Splunk Universal Forwarder retained read access, and new telemetry continued after rotation.

## Splunk Universal Forwarder

Splunk Universal Forwarder 10.4.3 monitors the application log and forwards it to Splunk Enterprise on Rocky Linux 64-bit.

```ini
[monitor:///var/log/gophish/gophish.log]
disabled = false
index = gophish
sourcetype = gophish:log
```

The effective forwarding destination was validated as `10.0.20.100:9997`.

## Splunk Telemetry Pipeline

```text
PHISH-GOPHISH
  -> /var/log/gophish/gophish.log
  -> Splunk Universal Forwarder
  -> TCP/9997
  -> Splunk Enterprise 10.0.20.100
  -> index=gophish
  -> sourcetype=gophish:log
  -> search-time field extraction
  -> detection / alert
```

This pipeline uses Splunk Enterprise, not Splunk Enterprise Security.

## Search-Time Field Extraction

The following search-time extractions apply to `sourcetype=gophish:log`.

`props.conf`:

```ini
[gophish:log]
REPORT-gophish-http = gophish_http_fields
REPORT-gophish-rid = gophish_rid
REPORT-gophish-user-agent = gophish_user_agent
```

`transforms.conf`:

```ini
[gophish_http_fields]
REGEX = msg="(\d{1,3}(?:.\d{1,3}){3}).*?(GET|POST)\s+(/?[^\s]+)\s+HTTP/([0-9.]+)\D+(\d{3})\s+(\d+)
FORMAT = src_ip::$1 http_method::$2 uri::$3 http_version::$4 http_status::$5 bytes::$6
SOURCE_KEY = _raw

[gophish_rid]
REGEX = [?&]rid=([^&\s]+)
FORMAT = rid::$1
SOURCE_KEY = _raw

[gophish_user_agent]
REGEX = .*\"(.*?)\""$
FORMAT = user_agent::$1
SOURCE_KEY = _raw
```

Splunk `btool` validation confirmed that this configuration was loaded. Functional searches against browser-generated GoPhish telemetry and synthetic Purple Team test user-agents confirmed extraction of `src_ip`, `http_method`, `uri`, `http_version`, `http_status`, `bytes`, `rid`, and `user_agent`.

The field name `rid` is required for detection logic. Real tracking values are excluded and redacted in the screenshots.

## Validation

- GoPhish and Splunk Universal Forwarder were active and enabled.
- The intended listener bindings were available.
- Rotation did not interrupt service, log writes, access, or forwarding.
- Telemetry reached `index=gophish` with `sourcetype=gophish:log`.
- Search-time extraction worked.
- The scheduled detection alert appeared in Triggered Alerts.

![Final GoPhish SPL validation](../screenshots/DET-015-01-final-spl-validation.png)

![Triggered alert validation](../screenshots/DET-015-03-triggered-alert-validation.png)

## Reboot Persistence

After reboot, GoPhish and Splunk Universal Forwarder returned active and enabled; `127.0.0.1:3333` and TCP/80 returned; new startup entries appeared; and a test from KALI-OPS01 (`10.0.50.60`) reached Splunk with functional field extraction.

![Post-reboot telemetry and extraction validation](../screenshots/DET-015-04-post-reboot-detection-validation.png)

The RID and URI values in the public evidence are intentionally redacted.

## Security Considerations

- The system is restricted to authorized, lab-owned simulation activity.
- The administrative interface is bound to localhost and accessed through an SSH tunnel.
- Credentials, passwords, authentication/session artifacts, secrets, tokens, cookies, private keys, database contents, and configuration backups are excluded.
- GoPhish private-key material, database files, configuration backups, and unsanitized full configuration must never be published.
- Real RID values are excluded; only the field name and safe wildcard expression are documented.
- Internal HTTP is a lab design choice, not a production recommendation.

## Known Limitations

- This internal lab service is not represented as production-ready or Internet-facing.
- A tracked GET containing an RID does not by itself prove successful phishing, credential submission, compromise, malicious intent, or one unique human.
- Synthetic validation requests can match DET-015.
- Campaign and recipient metadata correlation is outside the current logic.
- Suricata alert ingestion into Splunk is now validated separately and is not part of this GoPhish telemetry pipeline.

## Related Documentation

- [MAIL-SRV01 and GoPhish Internal Phishing Simulation](mail-srv01-gophish-phishing-simulation.md)
- [DET-013 — Browser Connection to Known Phishing Infrastructure](../detections/splunk/DET-013-browser-connection-to-known-phishing-infrastructure.md)
- [DET-015 — GoPhish Tracked Phishing Link Click](../detections/splunk/DET-015-gophish-tracked-phishing-link-click.md)
- [Splunk Detection Catalog](../detections/splunk/README.md)

## Final State

**Validated / Lab-specific** — PHISH-GOPHISH runs as an enabled systemd service, uses a localhost-only administrative interface, writes rotating logs, and forwards `gophish:log` telemetry to Splunk Enterprise. Rotation continuity, reboot persistence, extraction, the DET-015 search, and alert firing were validated. No production readiness, credential collection, successful phishing, or compromise is claimed.
