# Rule 05 — Port Scan Detection (High Port-Touch Volume from Single Source)

**MITRE ATT&CK:** T1046 – Network Service Discovery
**Category (SIEM taxonomy):** Network — Reconnaissance
**Severity:** Medium
**Data Source:** pfSense firewall logs (`filterlog`) via syslog → Splunk (`index=pfsense`)
**Platform:** Network / Perimeter

## Detection Logic

Flags a single source IP touching an unusually high number of distinct destination ports on the same destination host within a 1-minute window — the classic signature of a port scan (e.g., `nmap`, masscan, or any reconnaissance tool enumerating open services). Deliberately does **not** filter on `action="block"` — the rule detects the *pattern* of many-ports-from-one-source regardless of whether pfSense's firewall rules pass or block the traffic, since a permissive firewall rule (or a scan against an already-open service range) would otherwise hide a real scan from a block-only detection.

## SPL Query

```spl
index=pfsense "filterlog"
| dedup _raw
| rex field=_raw "filterlog\s+\d+\s+-\s+-\s+(?<rule>[^,]*),(?<sub>[^,]*),(?<anchor>[^,]*),(?<tracker>[^,]*),(?<iface>[^,]*),(?<reason>[^,]*),(?<action>[^,]*),(?<direction>[^,]*),(?<ipver>[^,]*),"
| where ipver="4"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?<src_port>\d+),(?<dst_port>\d+)"
| bin _time span=1m
| stats dc(dst_port) as unique_ports_tried, count as attempts by src_ip, dst_ip, _time
| where unique_ports_tried >= 10
| stats sum(attempts) as total_attempts, max(unique_ports_tried) as max_ports_per_min, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, dst_ip
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, src_ip, dst_ip, max_ports_per_min, total_attempts
```

**Field extraction note:** reuses the same `filterlog` positional-CSV parsing approach as Rule 4 (`rex` for header fields, `rex` for the IP/port pattern), plus `dedup _raw` as a defensive measure against the pfSense syslog duplication issue documented in the main troubleshooting log.

**Threshold note:** `unique_ports_tried >= 10` in a 1-minute window is intentionally low for lab-scale validation. In production, this should be tuned against a baseline of legitimate scanning activity (see False Positive Notes).

## Simulation Used to Trigger It

Required extending the lab network topology to allow this test: `KALI-OPS01` (Zone 5, `10.0.50.0/24`) had no route to Zone 2 (`10.0.20.0/24`) prior to this rule, by design (pfSense deny-by-default). Added:
- A 4th virtual NIC on `PFSENSE01`, bridged to Kali's VMnet
- A new pfSense interface (`OPT2`), static IP `10.0.50.1/24`
- A firewall rule on `OPT2` (`Pass`, protocol `any`, source `Any`, destination `10.0.20.0/24`) — deliberately permissive, so the scan's traffic passes through rather than getting blocked, testing the "pattern regardless of block/pass" design goal above
- A default route added on Kali: `sudo ip route add default via 10.0.50.1`

**Scan command (from Kali):**
```bash
nmap -sS -p 1-1000 10.0.20.1
```

## Result

nmap reported 3 open ports (53/domain, 80/http, 443/https — pfSense's own DNS resolver and WebGUI) and 997 filtered ports against `10.0.20.1` (pfSense LAN interface). The detection query correctly identified the scan: **759 unique destination ports touched by `10.0.50.60` against `10.0.20.1` within a single one-minute window**, far exceeding the 10-port threshold.

![Rule 5 Alert](../../screenshots/rule05-alert.png)

## Alert Configuration

| Setting | Value |
|---|---|
| Alert type | Scheduled |
| Schedule | Every 5 minutes |
| Time range | Last 10 minutes (overlap for boundary safety) |
| Trigger condition | Number of Results > 0 |
| Trigger | Once |
| Throttling | Suppress by `src_ip`, `dst_ip`, 30 minutes |

## False Positive Notes
- **Legitimate vulnerability scanners** (Nessus, OpenVAS, Qualys) intentionally touch many ports on many hosts and will trigger this rule identically to a malicious scan — maintain an allowlist of known scanner source IPs/hosts if these run regularly in the environment
- **Network monitoring tools** (some SNMP pollers, asset discovery tools like the `nmap -sn` sweep used to build this lab's own device inventory) can also cross the threshold — cross-reference `src_ip` against the device inventory lookup before escalating
- **Load balancers / NAT gateways** aggregating many clients behind one IP could appear to "scan" simply through high legitimate connection diversity — less relevant in this lab's flat network, but a real production consideration

## What I'd Tune in Production
- Raise the threshold significantly (the lab's `>= 10` is deliberately sensitive for validation; production environments typically use 15-50+ depending on baseline traffic)
- Add a lookup-based allowlist for known scanner infrastructure (security team's own vulnerability scanner, SOC tooling)
- Correlate with `dst_port` diversity *and* whether the ports actually returned open/closed/filtered responses — a scan against a host with almost everything filtered (like this validation run) is a stronger anomaly signal than a scan against a host with many open services
- Consider a lower per-source threshold across *multiple* destination hosts (horizontal scan) as a separate, related detection — this rule currently only catches vertical scans (many ports, one host)
