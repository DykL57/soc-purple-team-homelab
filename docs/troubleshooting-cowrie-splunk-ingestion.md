# Troubleshooting Cowrie Splunk Ingestion

## Case Summary

Cowrie accepted SSH sessions and wrote valid JSON, but the expected data did not initially appear correctly in `index=honeypot`. The investigation found multiple contributing issues rather than one isolated failure: filesystem traversal/read access, temporary monitor and sourcetype configurations, and incorrect event breaking for newline-delimited JSON.

## Expected Data Path

```text
Cowrie
  -> /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
  -> Splunk Universal Forwarder on LINUX-HONEYPOT01
  -> TCP/9997 through pfSense
  -> Splunk Enterprise 10.0.20.100
  -> index=honeypot, sourcetype=cowrie:json
```

## Symptom

The Cowrie service worked: SSH sessions from KALI-OPS01 reached the listener on TCP/2222, and Cowrie recorded connection, client, login, command, and session telemetry. Despite this, Cowrie data did not initially appear correctly in `index=honeypot`.

Later in the investigation, Splunk indexed the entire Cowrie JSON file as one event of approximately 33,824 bytes. The raw event contained many separate Cowrie records and appeared under temporary or incorrect sourcetypes including `json-too_small` and `cowrie:test`.

## Hypotheses

The investigation evaluated several possible failure points:

1. Cowrie was not writing valid JSON.
2. The `splunkfwd` service account could not traverse or read the path under `/home/cowrie`.
3. The Universal Forwarder input was not loaded.
4. The forwarder could not connect through pfSense to TCP/9997.
5. Splunk was not listening on TCP/9997.
6. The `honeypot` index did not exist or was not accepting events.
7. The source file or sourcetype configuration caused incorrect ingestion or event boundaries.

## Tests Performed

### 1. Confirm Cowrie service and JSON output

A controlled connection was made from KALI-OPS01:

```bash
ssh -p 2222 root@10.0.60.10
```

Cowrie recorded `session.connect`, client version and key exchange, login activity, command input/failure, and session-close telemetry. This proved that the deception service and JSON-producing workflow were operational.

### 2. Confirm Universal Forwarder file access

The Cowrie data lived under `/home/cowrie`, which had restrictive permissions. Rather than applying broad permissions such as `chmod 777`, ACLs granted `splunkfwd` only the traversal/read access required along the path.

Final validation used:

```bash
sudo -u splunkfwd head -n 1 /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
```

The command returned JSON successfully, proving that the service account could traverse the directory tree and read the production log.

### 3. Confirm the input configuration was loaded

`btool` showed that `/opt/splunkforwarder/etc/system/local/inputs.conf` was loaded. This ruled out an ignored or misplaced input file, but did not prove that Splunk could read and parse the source correctly.

### 4. Confirm transport through pfSense

Connectivity from LINUX-HONEYPOT01 to the Splunk receiver was tested with:

```bash
nc -vz 10.0.20.100 9997
```

The connection succeeded. pfSense logs showed PASS, the Universal Forwarder reported an active forward to `10.0.20.100:9997`, and the Splunk receiver was listening on `0.0.0.0:9997`. These checks moved the investigation away from routing, firewall, and receiver availability.

### 5. Confirm Splunk and indexer visibility

The `honeypot` index existed, and `_internal` events from `host=honeypot01` reached Splunk. This demonstrated that LINUX-HONEYPOT01 was known to Splunk and that the forwarding path was generally functional.

### 6. Run an A/B filesystem-path test

The production `cowrie.json` file was copied to:

```text
/var/log/cowrie-test/cowrie.json
```

Splunk indexed the test file with `sourcetype=cowrie:test`. This test isolated the original problem away from network transport and indexer connectivity and focused attention on the production path and monitor state.

### 7. Inspect raw event boundaries

Splunk initially produced one event of approximately 33,824 bytes containing many Cowrie JSON records. This proved that data transport was working but event breaking was not. The problem was therefore no longer “data is missing”; it was “newline-delimited records are being merged into one event.”

## Temporary Troubleshooting Configurations

Two diagnostic monitors were used during isolation:

| Path | Temporary sourcetype | Purpose |
|---|---|---|
| `/var/log/cowrie-test/cowrie.json` | `cowrie:test` | Compare ingestion from a conventional log path |
| `/home/cowrie/my-honeypot/var/log/cowrie/cowrie-splunk-test.json` | `cowrie:home-test` | Test a separate file under the Cowrie home path |

These monitors were later disabled or removed. They are not part of the final production configuration.

## False Leads and Partial Findings

- **Network or firewall failure:** plausible initially, but disproved by successful `nc`, pfSense PASS logs, an active forwarder connection, and a listening receiver.
- **Missing index:** disproved because `index=honeypot` existed.
- **Universal Forwarder entirely broken:** disproved by `_internal` events from LINUX-HONEYPOT01 and the successful A/B file test.
- **Cowrie service failure:** disproved by successful SSH interaction and valid session telemetry in `cowrie.json`.
- **Permissions as the only root cause:** ACLs were required, but correct access alone did not fix the single-large-event parsing problem.

## Root Cause

The final diagnosis identified multiple contributing issues:

1. The `splunkfwd` account required explicit traversal/read access to the Cowrie log path under `/home/cowrie`.
2. Temporary monitor and sourcetype configurations introduced additional ingestion paths during diagnosis and had to be removed from the final state.
3. Splunk grouped the newline-delimited Cowrie JSON file into one large event instead of breaking on each record.
4. The `cowrie:json` sourcetype required explicit event-breaking and JSON field-extraction settings.

## Final Fix

### Production forwarder monitor

File: `/opt/splunkforwarder/etc/system/local/inputs.conf`

```ini
[monitor:///home/cowrie/my-honeypot/var/log/cowrie/cowrie.json]
disabled = false
index = honeypot
sourcetype = cowrie:json
crcSalt = <SOURCE>
```

### Production parsing configuration

File: `/opt/splunk/etc/system/local/props.conf`

```ini
[cowrie:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 0
KV_MODE = json
```

The monitor selected only the production Cowrie log. The parsing stanza separated each newline-delimited JSON object and enabled JSON field extraction.

## Final Validation

```spl
index=honeypot host=honeypot01 earliest=-5m
| eval raw_length=len(_raw)
| table _time sourcetype eventid raw_length src_ip username password input message
| sort - _time
```

The search returned 23 individual Cowrie events. Event types included connection, client, authentication, command, log-close, and session-close records. Fields including `src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`, `password`, `input`, `message`, `eventid`, `session`, and `sensor` were extracted successfully.

LINUX-HONEYPOT01 was also corrected to `Asia/Jerusalem`, with NTP active and the clock synchronized. UTC/Z timestamps in Cowrie records remain expected.

## Lessons Learned

1. Troubleshoot ingestion as a chain of independent layers rather than one opaque service.
2. Use service-account impersonation to prove access with the same identity that reads the file.
3. An active forwarder and open receiver prove transport, not correct parsing.
4. A/B testing with a conventional log path is useful for separating path permissions from network/indexer problems.
5. Inspect `_raw` and event size when data arrives under an unexpected sourcetype or appears as one oversized event.
6. Remove diagnostic monitors after resolution so the final source, sourcetype, and event counts are unambiguous.

## Related Documentation

- [Cowrie Honeypot Deployment](cowrie-honeypot-deployment.md)
- [Cowrie Example Splunk Searches](../splunk/cowrie-example-searches.md)
