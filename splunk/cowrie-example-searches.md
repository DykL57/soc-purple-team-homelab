# Cowrie Example Splunk Searches

These searches use the validated Cowrie data in `index=honeypot`. Add a time range appropriate to the investigation.

## Event Type Summary

```spl
index=honeypot host=honeypot01
| stats count by eventid
| sort - count
```

Use this search to review the distribution of Cowrie event types from HONEYPOT01.

## Session Timeline

```spl
index=honeypot host=honeypot01
| table _time src_ip src_port dst_ip dst_port eventid username password input message
| sort - _time
```

Use this search to reconstruct authentication, command, and session activity in chronological order.

## Successful Logins

```spl
index=honeypot eventid="cowrie.login.success"
| table _time src_ip username password session
```

Use this search to identify credentials accepted by the deception service and the associated session.

## Commands Entered

```spl
index=honeypot eventid="cowrie.command.input"
| table _time src_ip username input session
| sort _time
```

Use this search to review commands entered during Cowrie sessions.

## Source IP and Event Activity

```spl
index=honeypot
| stats count by src_ip eventid
```

Use this search to compare event activity across source addresses.

## Commands by Source and Session

```spl
index=honeypot
| stats values(input) as commands count by src_ip session
```

Use this search to group observed commands by source address and Cowrie session.

## Validation Search

```spl
index=honeypot host=honeypot01 earliest=-5m
| eval raw_length=len(_raw)
| table _time sourcetype eventid raw_length src_ip username password input message
| sort - _time
```

This is the search used for final ingestion validation. It returned 23 individual events after the `cowrie:json` event-breaking configuration was applied.

## Related Documentation

- [Cowrie Honeypot Deployment](../docs/cowrie-honeypot-deployment.md)
- [Troubleshooting Cowrie Splunk Ingestion](../docs/troubleshooting-cowrie-splunk-ingestion.md)
