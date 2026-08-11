# Lab Engineering Notes

This document preserves implementation details and troubleshooting findings moved from the main README. It is intentionally candid about failed approaches, workarounds, and incomplete work.

## Network Monitoring

pfSense forwards firewall, system, and DHCP events to Splunk over UDP 5514. Firewall data is searched in `index=pfsense`; repository evidence also refers to `filterlog` events and the `pfsense:firewall` sourcetype. A device-inventory lookup created from an `nmap -sn` sweep can enrich raw IP addresses with device names and types.

Suricata is installed and integrated with pfSense. Suricata alert ingestion into Splunk is not complete and no Suricata-backed detection is represented as validated.

## CIM and `tstats`

DET-001 and DET-002 use the CIM Authentication data model. The `Splunk_SA_CIM` add-on was installed, relevant index macros were constrained to `index=wineventlog`, and results were checked against lab authentication events.

DET-003 was deliberately retained as a raw Event 7045 search. Applying a `change` tag made events eligible for the CIM Change model but did not populate required fields such as `object` and `object_category`. Correct support would require additional `props.conf` or `transforms.conf` extraction work.

DET-006 was also retained as a raw search. An `EXTRACT` populated `IpAddress`, but `Authentication.src` continued to resolve to the workstation name. `FIELDALIAS-src_ip`, `EVAL-src`, and `btool` investigation did not resolve the collision, while an equivalent custom `attacker_ip` field worked.

## Troubleshooting Findings

### pfSense boot failure

The VM failed with `No /boot/loader` when using ZFS under BIOS-mode VMware. Reinstalling with UFS resolved the boot issue.

### Incorrect Windows timestamps

Splunk appeared empty for recent time ranges because DC01 used Pacific Time and its clock was incorrect. Correcting both the time zone and system clock restored accurate event-time searches.

### Intentional inter-zone isolation

VMware host-only networks could not communicate until pfSense interfaces and explicit firewall policies were added. Zone 5 initially had no route to Zone 2 by design; a scoped path was added to perform DET-005 validation.

### PsExec logon rights

PsExec failed with substatus `0xC000015B` and Logon Type 5. The missing right was **Log on as a service**, not **Access this computer from the network**.

### Event 7045 placement and extraction

Service installation Event 7045 is stored in the Windows System log, not Security. The default Windows TA did not extract the needed service fields, so DET-003 uses `rex` against `_raw`.

### CIM index constraints

Editing a data model constraint did not resolve the missing explicit-index warning because the model referenced a macro. The correct change was to update the corresponding CIM search macro under Advanced Search.

### Bridged WAN and DHCP

Moving pfSense WAN from VMware NAT to bridged mode removed an expected route and exposed a DHCP pool configured for `192.168.1.x` on a `10.0.20.0/24` interface. The pool was corrected to `10.0.20.101–200`, and SPLUNK01 received a static mapping at `10.0.20.100`. See [the full DHCP investigation](troubleshooting-pfsense-bridged-wan-dhcp-conflict.md).

### Splunk configuration precedence

Forwarder inputs continued writing to the wrong index because `etc/system/local/inputs.conf` overrode an app-level configuration. `btool inputs list <stanza> --debug` identified the winning file. See [Splunk index precedence](splunk_index_precedence_EN.md).

### Duplicated `dpinger` events

Some `dpinger` syslog messages arrived duplicated. The duplication remains unexplained, but the message `sendto error: 64` was not harmless noise: it indicated `EHOSTDOWN` and helped identify WAN gateway reachability loss.

### Wi-Fi WAN instability

The VirusTotal lookup initially failed because the entire lab had lost outbound connectivity. pfSense reported the WAN interface as up while its gateway showed 100% packet loss. Reconnecting Wi-Fi and disabling power-saving restored connectivity; a dedicated wired WAN adapter remains the durable planned fix.

## Lab Hygiene

Attack simulations use VM snapshots and disposable accounts. Test accounts and temporary elevated memberships are removed after validation. The VirusTotal API key is stored only on the Splunk server in a local file with restricted permissions and is not committed to this repository.
