## Splunk Config Precedence Troubleshooting — Universal Forwarder Index Misrouting

**TL;DR:** Reorganized Windows event log indexing across 3 forwarders (2 workstations + 1 DC) into a role-based index scheme (`windows` / `win_dc` / `sysmon`). Verification searches showed events still landing in the wrong indexes despite correct app-level config — traced to a legacy `inputs.conf` in `etc/system/local/` silently overriding the new app on every host, due to Splunk's config file precedence rules.

**[Repository overview →](../README.md)**

### What happened
- New `lab_windows` app created to route `WinEventLog` and Sysmon inputs into role-based indexes (`windows` for endpoints, `win_dc` for the Domain Controller, `sysmon` for Sysmon telemetry) instead of everything defaulting to `main`.
- Post-deployment verification (`index=* host="WIN-CL01"`) showed events still split across `main`, `wineventlog`, and `sysmon` — the new index never appeared.

### Root cause
A leftover `inputs.conf` in `etc/system/local/` — which always wins Splunk's config precedence regardless of app name — was still defining the same stanzas with the old index values. The new app's config was 100% correct; it was simply never being read for the keys the legacy file also defined.

### Diagnosis
Used `splunk btool inputs list <stanza> --debug` on each forwarder to identify, per key, which file was actually winning — rather than guessing from file contents. This surfaced a second gap on the Domain Controller: it had no `lab_windows` app at all, so every input was still coming straight from `etc/system/local/`.

### Fix
1. Defined the correct stanzas in `etc/apps/lab_windows/local/inputs.conf` on all three hosts.
2. Commented out (not deleted, for audit trail) the conflicting stanzas in `etc/system/local/inputs.conf`.
3. Restarted each forwarder and re-verified with `btool` that `lab_windows` was the sole source.
4. Confirmed end-to-end with a live search (`stats count by host, index, sourcetype`).

### Design decision
The Domain Controller was deliberately isolated into its own index (`win_dc`) rather than reusing `windows`, to support tighter access control and independent retention for higher-sensitivity authentication data (Kerberos, DCSync-relevant Event ID 4662, etc.) — access control, retention, and volume were the driving criteria, not "one index per host."

### Key takeaway
`etc/system/local/` is a global override in Splunk that beats every app, regardless of alphabetical order — a very easy trap in app-based deployments. `btool --debug` is the definitive way to resolve "why isn't my config taking effect."
