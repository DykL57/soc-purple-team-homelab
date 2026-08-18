# Cowrie Honeypot Deployment

## Overview

HONEYPOT01 runs Cowrie as a deception service for controlled SSH/Telnet interaction, credential capture, and attacker command/session telemetry. The system is isolated in the DECEPTION security zone and forwards newline-delimited Cowrie JSON records to Splunk Enterprise.

This document describes the final working deployment. Temporary troubleshooting monitors are documented separately in [Troubleshooting Cowrie Splunk Ingestion](troubleshooting-cowrie-splunk-ingestion.md).

## Architecture

```text
KALI-OPS01
10.0.50.60
    |
    | SSH TCP/2222
    v
HONEYPOT01 / Cowrie
10.0.60.10
    |
    | /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
    v
Splunk Universal Forwarder
    |
    | TCP/9997
    v
Splunk Enterprise
10.0.20.100
index=honeypot
sourcetype=cowrie:json
```

## System and Network Role

| Setting | Final value |
|---|---|
| System | HONEYPOT01 |
| Hostname | `honeypot01` |
| Operating system | Ubuntu Server 24.04 |
| Address | `10.0.60.10/24` |
| Gateway | `10.0.60.1` |
| VMware network | VMnet7 |
| Security zone | DECEPTION |
| pfSense interface | DECEPTION |
| Honeypot | Cowrie |
| Cowrie listener | TCP/2222 |
| Cowrie directory | `/home/cowrie/my-honeypot` |
| JSON log | `/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json` |

## Installation Overview

Cowrie is installed under `/home/cowrie/my-honeypot` and writes JSON session telemetry to `var/log/cowrie/cowrie.json` within that directory. The operational service accepted controlled SSH connections from KALI-OPS01 and recorded connection, client, authentication, command, and session-close activity.

The Splunk Universal Forwarder is installed on HONEYPOT01 and runs as `splunkfwd`. Its local input configuration is stored at:

```text
/opt/splunkforwarder/etc/system/local/inputs.conf
```

## Cowrie Service Role

Cowrie provides an SSH/Telnet deception surface designed to record attacker interaction without exposing a production service. The validated test used:

```bash
ssh -p 2222 root@10.0.60.10
```

Cowrie recorded telemetry including session connection, client version and key exchange, login attempts and success, command input and failure, and session closure.

## Firewall Flows

Only the documented flows required for the validated path are represented here:

| Source | Destination | Service | Purpose |
|---|---|---|---|
| REDTEAM | HONEYPOT01 (`10.0.60.10`) | TCP/2222 | Cowrie SSH interaction; validated from KALI-OPS01 (`10.0.50.60`) |
| HONEYPOT01 (`10.0.60.10`) | Splunk Enterprise (`10.0.20.100`) | TCP/9997 | Universal Forwarder event transport |

pfSense logs confirmed PASS for the forwarding traffic. Connectivity to the Splunk receiver was also validated with:

```bash
nc -vz 10.0.20.100 9997
```

The Universal Forwarder showed an active forward to `10.0.20.100:9997`, and Splunk was confirmed listening on `0.0.0.0:9997`.

## Final Splunk Universal Forwarder Input

The final production monitor in `/opt/splunkforwarder/etc/system/local/inputs.conf` is:

```ini
[monitor:///home/cowrie/my-honeypot/var/log/cowrie/cowrie.json]
disabled = false
index = honeypot
sourcetype = cowrie:json
crcSalt = <SOURCE>
```

Temporary monitors used during diagnosis were disabled or removed after testing:

- `/var/log/cowrie-test/cowrie.json` with `sourcetype=cowrie:test`
- `/home/cowrie/my-honeypot/var/log/cowrie/cowrie-splunk-test.json` with `sourcetype=cowrie:home-test`

These temporary paths are not part of the final production configuration.

## Final Splunk Parsing Configuration

The final parsing stanza is stored on the Splunk Enterprise server in `/opt/splunk/etc/system/local/props.conf`:

```ini
[cowrie:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 0
KV_MODE = json
```

This configuration treats every newline-delimited JSON record as a separate event and enables JSON field extraction.

## Validation

The final validation search was:

```spl
index=honeypot host=honeypot01 earliest=-5m
| eval raw_length=len(_raw)
| table _time sourcetype eventid raw_length src_ip username password input message
| sort - _time
```

The search returned 23 individual Cowrie events. Observed event types included:

- `cowrie.session.connect`
- `cowrie.client.version`
- `cowrie.client.kex`
- `cowrie.login.success`
- `cowrie.client.size`
- `cowrie.client.var`
- `cowrie.session.params`
- `cowrie.command.input`
- `cowrie.command.failed`
- `cowrie.log.closed`
- `cowrie.session.closed`

Extracted fields included `src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`, `password`, `input`, `message`, `eventid`, `session`, and `sensor`.

Additional queries are available in [Cowrie Example Splunk Searches](../splunk/cowrie-example-searches.md).

## Time Configuration

HONEYPOT01 is configured for `Asia/Jerusalem`, with NTP active and the system clock synchronized. Cowrie records may still contain UTC/Z timestamps; this is expected.

## Security Considerations

- Keep HONEYPOT01 in the dedicated DECEPTION zone and restrict traffic to the documented test and forwarding flows.
- Treat captured usernames, passwords, commands, and session data as sensitive security telemetry.
- Grant the `splunkfwd` account only the traversal and read access required for the Cowrie log path. Broad permissions such as `chmod 777` are not required.
- Keep temporary diagnostic monitors disabled or removed after troubleshooting to prevent duplicate or incorrectly classified ingestion.

## Lessons Learned

1. Confirm the honeypot service and its log output independently before troubleshooting the forwarding layer.
2. Validate each layer in sequence: file access, input loading, forwarder connectivity, firewall policy, receiver state, index availability, and parsing.
3. Successful transport does not guarantee correct event boundaries. Newline-delimited JSON requires explicit parsing when Splunk groups the file into one event.
4. A controlled A/B test using a different filesystem path can isolate path-access problems from network and indexer problems.

## Final State

- Cowrie and SSH deception are operational.
- Kali-to-Cowrie testing is successful.
- Cowrie JSON logging and Universal Forwarder transport are operational.
- pfSense permits the documented flows.
- `index=honeypot` and `sourcetype=cowrie:json` are operational.
- Cowrie JSON lines are indexed as individual events with extracted fields.
