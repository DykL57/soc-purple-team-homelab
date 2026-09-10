# Home SOC / Purple Team Lab — ASCII Architecture

This document is a text-only companion to the enterprise architecture diagram. The lab contains exactly 17 systems: pfSense and 16 hosts/VMs.

```text
                              [ Internet ]
                                   |
                      [ Physical Upstream Router ]
                                   |
                   [ VMware Bridged WAN / VMnet0 ]
                                   |
                              [ pfSense ]
                 Firewall / Router / DHCP / Suricata
                                   |
             +---------------------+---------------------+
             |                     |                     |
             |                     |                     +--> VMnet7  10.0.60.0/24
             |                     |                          Honeypot / Deception
             |                     |                          `-- LINUX-HONEYPOT01  10.0.60.10
             |                     |                              Cowrie SSH/Telnet / Splunk UF
             |                     |
             |                     +--> VMnet6  10.0.50.0/24
             |                          Red Team / Targets / Simulation
             |                          |-- KALI-OPS01       10.0.50.60
             |                          |-- WIN-REDTEAM01    10.0.50.50
             |                          |-- FILE-SRV01       10.0.50.105
             |                          |-- WEB-APP01        10.0.50.102
             |                          |-- C2-SLIVER01      10.0.50.61
             |                          `-- PHISH-GOPHISH    10.0.50.70
             |
             +--> VMnet3  10.0.20.0/24
             |    Infrastructure / Servers / SIEM
             |    |-- DC01                10.0.20.10
             |    |-- linux-srv01         10.0.20.41
             |    |-- MAIL-SRV01          10.0.20.30
             |    |-- Splunk Enterprise   10.0.20.100  (Rocky Linux 64-bit)
             |    `-- ZEEK01              10.0.20.118  (Management)
             |         |-- ens33 -> VMnet3 -> 10.0.20.118 Management
             |         `-- ens34 -> VMnet6 -> Passive Sensor / No IP
             |
             `--> VMnet4  10.0.30.0/24
                  Windows Clients
                  |-- WIN-CL01  10.0.30.100
                  `-- WIN-CL02  10.0.30.101


       VMnet9 — 10.0.90.0/24 — ISOLATED MALWARE ANALYSIS
       ==================================================
       NO GATEWAY / NO PFSENSE / NO INTERNET / NO SPLUNK

       [ SANDBOX01 ] <--> [ Fake DNS / Network Services ] <--> [ REMNUX01 ]
        10.0.90.10                                               10.0.90.20
        Windows analysis                                        REMnux / dnsmasq / INetSim
```

## Mail and phishing flow

```text
PHISH-GOPHISH -> SMTP -> MAIL-SRV01
MAIL-SRV01 -> IMAP/IMAPS -> WIN-CL01 / Thunderbird
```

PHISH-GOPHISH is an internal simulation platform. These relationships do not imply credential capture, Internet-facing phishing, Active Directory mail integration, or production mail infrastructure.

## Simplified telemetry flow

```text
Windows / Linux --+
Zeek -------------|
pfSense ----------+--> TELEMETRY / LOGS & EVENTS --> Splunk Enterprise
Suricata ---------|    (IN PROGRESS)
Cowrie -----------+
```

ZEEK01 is one dual-interface system. Its `ens33` interface provides management connectivity on VMnet3 at `10.0.20.118`; its `ens34` interface passively monitors VMnet6 and has no IP address. Splunk Enterprise and Rocky Linux 64-bit are likewise one system.

VMnet9 is intentionally separate from the routed architecture and has no connection to pfSense, Splunk Enterprise, the Internet, or any routed VMnet.
