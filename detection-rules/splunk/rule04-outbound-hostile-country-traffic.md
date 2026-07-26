# Rule 04 — Outbound Traffic to High-Risk Countries

**MITRE ATT&CK:** T1071 – Application Layer Protocol (general C2/exfil channel indicator); TA0011 – Command and Control (tactic-level)
**Category (SIEM taxonomy):** Network — Anomalous Outbound Traffic
**Severity:** Low–Medium (geo-IP alone is a weak signal — see Limitations; now paired with live IP reputation)
**Data Source:** pfSense firewall logs (`filterlog`) via syslog → Splunk (`index=pfsense`)
**Platform:** Network / Perimeter

## Detection Logic

Flags outbound connections from the lab network to public IP addresses geolocated in a configurable list of high-risk countries (e.g., countries associated with known APT activity against Israeli critical infrastructure — Iran, Russia, North Korea, Syria, China). Uses Splunk's built-in `iplocation` command (bundled MaxMind GeoLite2 database, no add-on required) against parsed pfSense `filterlog` events, then enriches each flagged IP with live reputation data from VirusTotal via a custom scripted lookup.

## SPL Query

```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4" AND direction="out"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| where dst_ip!="127.0.0.1" AND NOT match(dst_ip, "^10\.") AND NOT match(dst_ip, "^192\.168\.")
| iplocation dst_ip
| search Country IN ("Iran", "Russia", "North Korea", "Syria", "China")
| dedup dst_ip
| lookup vt_ip_reputation dst_ip
| stats count, values(dst_ip) as dest_ips, values(vt_malicious) as vt_malicious, values(vt_country) as vt_country, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, Country
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, Country, count, dest_ips, vt_malicious, vt_country
```

**Field extraction note:** pfSense's `filterlog` sourcetype arrives as unstructured, positional CSV inside the syslog message, with no default Splunk TA field extraction. Rather than parsing by fixed column position (which breaks across TCP/UDP/ICMP, since each logs a different number of fields), this query extracts the fixed-position header fields (rule, interface, action, direction, ipver) with one `rex`, then matches the `src_ip,dst_ip` pattern directly as two adjacent dotted-quad values with a second `rex` — robust regardless of protocol. `dedup _raw` was added defensively after discovering pfSense duplicates some syslog event types at the source (see Notable Troubleshooting) — investigation confirmed `filterlog` itself was not actually affected, but the safeguard is kept in place.

## Live IP Reputation Enrichment (VirusTotal)

To address the geo-IP false-positive problem documented below, a custom Python scripted lookup (`vt_ip_lookup.py`) was built to query the VirusTotal API for every geo-flagged IP and return live reputation data (`vt_malicious`, `vt_suspicious`, `vt_reputation`, `vt_country`) directly inside the search results — no more manually copying IPs into the VirusTotal website one at a time.

**How it works:**
1. Script lives at `$SPLUNK_HOME/etc/apps/search/bin/vt_ip_lookup.py`, registered in Splunk as an External lookup (`Settings → Lookups → Lookup definitions`, type `External`, supported fields `dst_ip, vt_malicious, vt_suspicious, vt_reputation, vt_country`).
2. The API key is stored in a **separate, local-only file** (`vt_api_key.txt`, `chmod 600`) next to the script — never hardcoded in the script itself and never committed to source control, so the script is safe to publish while the credential stays server-side only.
3. Splunk pipes matching rows to the script via stdin as CSV; the script queries `https://www.virustotal.com/api/v3/ip_addresses/{ip}` per unique IP, with an in-memory cache and a 16-second sleep between requests to stay under VirusTotal's free-tier rate limit (4 requests/minute, 500/day).
4. `| dedup dst_ip` is applied **before** the lookup call in the SPL — critical given the rate limit, so each unique IP is queried once per search run rather than once per matching event.

**Validation:** ran the script standalone against `31.58.102.164` (the IP earlier confirmed manually as a false positive) and got back `vt_malicious=0, vt_suspicious=0, vt_country=US` — matching the manual VirusTotal check exactly. The automated pipeline agrees with the earlier manual finding, confirming the integration works correctly end-to-end.

**Setup note:** getting this working required first resolving an unrelated but blocking WAN connectivity outage on the lab itself — see Notable Troubleshooting in the main README for the full story (the Splunk server, and in fact the entire LAN, had lost outbound internet access due to a Wi-Fi-as-WAN stability issue, which had to be fixed before the script could reach VirusTotal's API at all).

## Simulation / Validation

No synthetic simulation was needed — this rule was validated against real, organic outbound DNS resolution traffic generated by pfSense itself (root DNS server queries, Windows Update, telemetry endpoints, etc.) over several hours of normal lab operation, exported and reviewed as a CSV of ~8,300 geolocated events spanning dozens of countries (United States, Canada, Germany, Israel, Japan, Sweden, and others).

## Result

Query correctly aggregated outbound connections by source IP and country. Over the validation window, it surfaced:
- **4 connections to `31.58.102.164`, geolocated as Iran**
- **2 connections to `185.209.85.151`, geolocated as Russia**

## Known Limitation — Both Flagged IPs Confirmed as False Positives (Now Auto-Detected)

Both geolocated hits from this validation run were manually cross-checked against VirusTotal and confirmed to be **legitimate infrastructure, not actually associated with Iran or Russia**. This is not a statement about Iran or Russia as monitored countries — they remain valid, legitimate entries in the watch list given known APT activity against Israeli critical infrastructure. It's a statement about **Splunk's bundled MaxMind GeoLite2 database misattributing the country of record for these two specific IP addresses**.

**Root cause:** the free GeoLite2 database bundled with Splunk is a point-in-time snapshot that is not automatically kept current. IP block ownership and geolocation change frequently — through RIR reassignment, cloud/CDN provider churn, and IP leasing — and a stale local database will misattribute a block's country of record. This is a materially weaker signal than live WHOIS-backed or multi-source threat-intel platforms (VirusTotal, AbuseIPDB), which is exactly why they disagreed here.

**This limitation is now mitigated, not just documented** — the VirusTotal scripted lookup above automatically surfaces `vt_malicious=0` for both flagged IPs directly in the search results, meaning an analyst reviewing this alert no longer needs to manually check external threat-intel sites before recognizing these as likely false positives. Geo-IP alone remains a weak signal, but it's no longer the *only* signal in this rule's output.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert type | Scheduled |
| Schedule | Every 15 minutes |
| Time range | Last 20 minutes (overlap for boundary safety) |
| Trigger condition | Number of Results > 0 |
| Trigger | Once |
| Throttling | Suppress by `src_ip`, `Country`, 1 hour |
| Recommended action | With `vt_malicious=0`, route to a low-priority review queue; with `vt_malicious>0`, escalate immediately |

## False Positive Notes
- **Geo-IP database staleness** (see above) — the primary source of false positives for the geo-location component of this rule; now caught automatically via the VirusTotal enrichment rather than requiring manual verification
- DNS root servers, CDN edge nodes, and cloud provider IP ranges (Microsoft, Google, Akamai, etc.) are globally distributed and can geolocate to unexpected countries even when accurate — legitimate infrastructure traffic, not malicious
- Internal/private ranges (`10.x`, `192.168.x`, loopback) are explicitly excluded from this query; confirm this exclusion list stays in sync with the lab's actual internal addressing if the network topology changes
- VirusTotal's free-tier rate limit (4 req/min, 500/day) means this enrichment doesn't scale to high-volume production use without either a paid tier or a persistent cache — see script notes

## What I'd Tune in Production
- Replace the script's in-memory cache with a persistent lookup table (KV Store or CSV) so previously-checked IPs are never re-queried across separate search runs, not just within a single run
- Add AbuseIPDB as a second reputation source and combine/cross-validate scores rather than relying on VirusTotal alone
- Consider a paid VirusTotal tier or batched API usage if this rule's match volume grows beyond what the free tier's rate limit can sustain
- Build a maintained allowlist of known-legitimate infrastructure (root DNS servers, major cloud/CDN ASNs) to suppress expected noise before it ever reaches the analyst queue
- Consider correlating hits from this rule with destination port/protocol — outbound HTTPS to a high-risk-geolocated IP is far less notable than outbound traffic on an unusual port, which would better indicate actual C2 activity
- Track ASN in addition to country, since ASN ownership data tends to be more stable and reliable than country-level geolocation
