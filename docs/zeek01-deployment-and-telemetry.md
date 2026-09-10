# ZEEK01 Deployment and Telemetry

## Purpose and Role

ZEEK01 is the lab's passive network detection and response sensor. It observes selected traffic on the VMnet6 Red Team / Targets segment and forwards Zeek JSON telemetry to Splunk Enterprise for hunting, enrichment, and detection engineering.

ZEEK01 is not a gateway, router, firewall, inline IDS, or full-packet-visibility sensor. Traffic does not route through it.

## Validated Platform

| Component | Validated value |
|---|---|
| Hostname | `ZEEK01` |
| Operating system | Ubuntu 26.04 LTS |
| Zeek | 8.0.10 LTS |
| ZeekControl | 2.6.0-31 |
| Splunk Universal Forwarder | 10.4.3 |
| Splunk destination | Splunk Enterprise on Rocky Linux 64-bit, `10.0.20.100:9997` |
| Splunk index | `zeek` |

## Dual-Interface Architecture

| Interface | Network | Addressing | Purpose |
|---|---|---|---|
| `ens33` | VMnet3 | `10.0.20.118/24`, gateway `10.0.20.1` | Management and Splunk forwarding |
| `ens34` | VMnet6 | No IP address and no gateway | Passive sensor interface |

The separation keeps administration and telemetry transport on VMnet3 while `ens34` observes VMnet6 without becoming an addressable host on the monitored segment. ZEEK01 remains one VM with two interfaces.

## Passive Sensor Design

Zeek monitors traffic visible to `ens34`. The interface has no Layer 3 configuration and is not used as a route. This design reduces the sensor's active footprint and prevents it from acting as an unintended gateway between networks.

The current VMware observation point provides partial passive visibility. Outbound traffic from RED_NET hosts is visible, but Internet return traffic is not consistently visible on `ens34`. Enabling promiscuous mode did not resolve the limitation.

## Splunk Telemetry Flow

```text
VMnet6 traffic visible to ZEEK01 ens34
                    │
                    ▼
             Zeek JSON logs
                    │
                    ▼
Splunk Universal Forwarder 10.4.3 on ZEEK01
                    │
           ens33 / VMnet3 / TCP 9997
                    │
                    ▼
Splunk Enterprise — 10.0.20.100
             index=zeek
```

## Zeek Sourcetypes

The validated `index=zeek` pipeline includes:

- `zeek:conn:json`
- `zeek:dns:json`
- `zeek:http:json`
- `zeek:ssl:json`
- `zeek:files:json`
- `zeek:notice:json`

Connection and DNS events provide the primary inputs for DET-018. The additional sourcetypes preserve protocol, file, TLS, and notice context for investigation when corresponding events are generated and visible.

## Custom Notice Validation

The notice pipeline was functionally validated with a controlled custom Zeek Notice event. The event was written as Zeek JSON, collected by the Universal Forwarder, ingested into `index=zeek`, and searchable with `sourcetype=zeek:notice:json`. This validates the notice transport and parsing path; it does not imply that every Zeek notice policy or alerting use case has been implemented.

## DET-018 Relationship

[DET-018 — Beaconing / C2 Communication](../detections/splunk/DET-018-beaconing-c2-communication.md) uses `zeek:conn:json` timing data and `zeek:dns:json` context from RED_NET. It measures periodicity and continuity and then enriches candidate destinations with the local `vt_ip_reputation` lookup.

VirusTotal data is cached contextual enrichment only. Zero malicious and zero suspicious results do not prove that a destination is benign. Cache age, missing results, DNS context, ownership, and the observed communication pattern all remain analyst considerations.

Because ZEEK01 does not consistently observe Internet return traffic, DET-018 intentionally does not depend on:

- `conn_state`
- response-byte counts
- a complete TCP handshake

The detection identifies behavior that can be consistent with beaconing. It does not by itself prove a specific command-and-control protocol, malware execution, compromise, or successful C2.

## Visibility Limitation

ZEEK01 has partial passive visibility on VMnet6. It observes outbound RED_NET traffic, but Internet return traffic is not consistently visible. This limitation must be preserved when interpreting connection state, byte counts, service identification, and session completeness.

The separate physical Home/IoT network at `10.100.102.0/24` normally uses the upstream Cellcom/Sagemcom router as its gateway. It does not normally traverse pfSense, and complete Zeek or Suricata visibility into autonomous Home/IoT Internet traffic has not been demonstrated.

## Operational and Security Notes

- Keep `ens34` without an IP address or gateway.
- Keep management and Splunk forwarding on `ens33` / VMnet3.
- Treat the sensor as passive and out of band; do not represent it as an enforcement control.
- Monitor Zeek and Splunk Universal Forwarder service health and log freshness.
- Monitor VirusTotal cache age and refresh behavior without committing API credentials or live lookup secrets.
- Preserve the VMnet9 malware-analysis network's complete separation; ZEEK01 has no role in routing or forwarding VMnet9 traffic.
- Treat missing return traffic as a visibility limitation, not evidence that no response occurred.

## Status

**Operational / Lab-specific.** Zeek JSON ingestion, Splunk Universal Forwarder transport, the documented sourcetypes, controlled custom Notice telemetry, and DET-018's connection/DNS workflow have been validated. Passive VMnet6 visibility remains partial and requires a validated mirroring or TAP design for improvement.
