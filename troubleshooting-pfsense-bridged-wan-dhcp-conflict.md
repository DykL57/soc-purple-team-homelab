# Troubleshooting Log — pfSense Bridged WAN Migration & VMnet3 DHCP Conflict

**Date:** 2026-07-26
**Component:** PFSENSE01 (VMware Workstation), host machine networking
**Category:** Distributed deployment / virtual networking / DHCP

## Goal

Give pfSense's WAN interface a real IP address from the Cellcom ISP router (instead of VMware's internal NAT), so pfSense could see and log real inbound/outbound traffic and forward it to Splunk via syslog.

## Starting state

- `PFSENSE01` Network Adapter 1 was set to `Custom (VMnet8)` — VMware's internal NAT network.
- pfSense's WAN reached the internet through the host's own connection via VMware NAT, not a real ISP-assigned address.
- The host machine already had a virtual adapter on VMnet8 automatically (VMware creates one by default for NAT), which is why GUI/Splunk access via `192.168.142.x` had worked without any extra configuration up to this point.

## Step 1 — Switch WAN to Bridged

**Change:** `PFSENSE01` Network Adapter 1 → `Bridged`, bridged to a newly-enabled onboard Wi-Fi adapter (since the host's single wired Ethernet port was already in use and VMware requires an unused physical adapter to create a new Bridged network).

**Result:** WAN interface received a real DHCP lease from the Cellcom router (`10.100.102.14/24`) — confirmed via `Status → Interfaces → WAN` in pfSense.

## Step 2 — Lost access to the pfSense Web GUI

**Symptom:** Immediately after the WAN change, the pfSense GUI became unreachable from the host browser.

**Root cause:** Two compounding factors:
1. The host's route to pfSense's old management path (via VMnet8) no longer applied the same way after removing that adapter's role from PFSENSE01.
2. More fundamentally, pfSense **blocks WebGUI access on the WAN interface by default** for security reasons — GUI access was never supposed to route over WAN in the first place. The correct path is via the **LAN** interface.

**Fix:** Accessed pfSense via the VM console (not the browser) using `11) Restart GUI` to rule out a service crash, then connected the host to pfSense's LAN network (`VMnet3`, `10.0.20.0/24`) via `VMware Virtual Network Editor → VMnet3 → ☑ Connect a host virtual adapter to this network`. This gave the host a route to `https://10.0.20.1` (pfSense LAN GUI).

## Step 3 — pfSense syslog → Splunk: nothing arriving

**Symptom:** After configuring pfSense Remote Logging (`Status → System Logs → Settings`) to forward Firewall/System/DHCP events to the Splunk server (`192.168.142.139:5514`), and configuring a matching UDP input in Splunk, `index=pfsense` showed zero events. `tcpdump` on the Splunk server confirmed no packets were arriving at all — this was a routing problem, not a syslog config or firewall problem.

**Root cause:** The Splunk server (Rocky Linux) sat on `VMnet8` (`192.168.142.x`) — the same NAT network that used to carry pfSense's WAN before Step 1. Once WAN moved to Bridged, **pfSense no longer had any interface at all on `192.168.142.0/24`**. Checking `Diagnostics → Routes` on pfSense confirmed only three networks were known: WAN (`10.100.102.0/24`), LAN (`10.0.20.0/24`), and OPT1 (`10.0.30.0/24`) — no route to `192.168.142.0/24` existed, so pfSense had no way to send syslog there regardless of any config.

**Fix:** Moved the Splunk server's VM network adapter from `VMnet8` to `VMnet3` (pfSense's LAN, `10.0.20.0/24`) — placing it in the same zone as the rest of the lab's Zone 1/MGMT infrastructure, consistent with the documented architecture. Updated pfSense's Remote Logging target and the Universal Forwarders on DC01/WIN-CL01 (`outputs.conf`) to point at the Splunk server's new LAN address.

## Step 4 — Host couldn't reach the Splunk server on its new address either

**Symptom:** After moving Splunk to `VMnet3`, `ping` to the Splunk server's expected new address failed from the host, and the Splunk GUI was unreachable.

**Root cause investigation:**
- `ipconfig /all` on the host showed a `VMware Network Adapter VMnet3` interface existed and was physically present, but had **no IPv4 address** — only a link-local IPv6 address.
- Checked `VMware Virtual Network Editor → VMnet3` and found VMware's **own built-in DHCP server** was enabled on that network (`DHCP: Enabled` in the network list) — running *in parallel* with pfSense's own DHCP server on the same LAN interface (em1). Two DHCP servers competing on one L2 segment is a known cause of intermittent or total DHCP failure.
- Disabled VMware's local DHCP service for VMnet3 (`Virtual Network Editor → VMnet3 → uncheck "Use local DHCP service to distribute IP address to VMs"`), so pfSense would be the sole DHCP authority on that segment, as intended by the original lab design.
- After disabling VMware's DHCP and re-running `ipconfig /release` / `/renew`, the host adapter still received no lease — it fell back to an **APIPA** address (`169.254.x.x`), confirming pfSense's own DHCP server also wasn't responding to the request (reason not fully diagnosed — deferred as a non-blocking follow-up item).

**Fix (pragmatic, to unblock progress):** Assigned a static IP manually to the host's `VMware Network Adapter VMnet3`:
```
IP address:      10.0.20.55
Subnet mask:      255.255.255.0
Default gateway:  10.0.20.1
Preferred DNS:    10.0.20.1
```
This bypasses DHCP entirely and gave the host immediate connectivity to both the pfSense LAN GUI (`10.0.20.1`) and the relocated Splunk server (`10.0.20.100`).

## Outcome

- pfSense WAN now has a real, routable IP from the ISP.
- pfSense GUI reachable via LAN from the host (static IP).
- Splunk server relocated to the correct lab zone (`VMnet3`, LAN), reachable from both pfSense and the host.
- pfSense syslog (Firewall/System/DHCP events) successfully reaching Splunk on UDP 5514, confirmed via `tcpdump` and `index=pfsense` search results.

## Key lesson

A single topology change (moving one network adapter from NAT to Bridged) triggered a cascading chain of failures across components that don't look related at first glance: GUI access, syslog delivery, and DHCP — because all three ultimately depend on the same underlying Layer 2/3 topology. The systematic debugging path that worked: check the routing table (`Diagnostics → Routes`) before assuming an application-layer misconfiguration, use `tcpdump` to separate "packets aren't arriving" from "packets arrive but aren't processed," and check `ipconfig /all` for APIPA addresses as a fast signal that DHCP — not the target service — is the actual point of failure.

## Open follow-up (non-blocking)

Diagnose why pfSense's own DHCP server (`Services → DHCP Server → LAN`) did not respond to the host's renewed DHCP request even after VMware's competing DHCP service was disabled. Not urgent — the static IP workaround is stable — but worth understanding for completeness.
