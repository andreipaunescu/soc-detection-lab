# SOC Homelab

A small, isolated Security Operations lab for practising telemetry collection, detection engineering and triage. A Windows 11 victim and a Kali Linux attacker run on a Windows PC, and all Windows telemetry is forwarded to a Splunk Enterprise instance on a separate Linux laptop. The lab runs on its own network link, with no route to the home network.

## Architecture

<img width="822" height="342" alt="soc-homelab drawio" src="https://github.com/user-attachments/assets/32c59600-2d57-424f-b353-5c123327db06" />


- **Lab network:** 10.10.10.0/24 on a direct Ethernet cable, with no DHCP and no default gateway. Addresses are grouped by role in blocks of ten: attacker at .5, Windows workstations at .30, the SIEM at .40.
- **Firewall:** on the SIEM, ufw allows forwarding and web access only from the lab subnet. Remote access to the web UI goes over Tailscale, on the tailnet interface only.

## Design decisions

**Hyper-V with an External switch.** The VMs need to reach the SIEM on the lab link but must not reach the home network. Hyper-V's Default Switch uses NAT to the host's internet connection, which gives the VMs a route to the home LAN, so it's unsuitable for attack traffic. An External switch bound to the lab adapter puts the VMs directly on the lab link.

**Splunk on a separate machine.** Keeping the SIEM off the attacker's network means a compromised victim can't tamper with the logs it's sending.

**Sysmon with a published community config.** The Sysmon configuration is SwiftOnSecurity's `sysmon-config`. Some event types are disabled to limit noise, which has a cost: image load (Event 7) and process access (Event 10) are off, so detections that depend on them, such as LSASS access, aren't possible yet. That trade-off is intentional and will be revisited in later detections.

**Two audit layers.** Sysmon provides process, network and registry telemetry, and Windows auditing provides logon events (4624 and 4625), command-line logging (4688) and PowerShell script block logging (4104). Logon failure auditing is enabled, so brute-force attempts are recorded.

**Raw field names for 4625.** The Splunk Add-on for Microsoft Windows (11.0.2) maps some normalised field names, but not all of them for failed logons in this version. Searches use the raw Windows names (`TargetUserName`, `IpAddress`, `SubStatus`), so results don't depend on the add-on's mapping.

## What's collected

| Source | Index | Notes |
|---|---|---|
| Sysmon Operational | `sysmon` | Process creation, network connections, registry Run keys |
| Security | `wineventlog` | Logons (4624, 4625), privilege use (4672), scheduled tasks (4698, planned), command lines (4688) |
| PowerShell Operational | `wineventlog` | Script block logging (4104) |
| System | `wineventlog` | Service state changes (7023) |

## Scenarios and detections

| Scenario | Technique | Status |
|---|---|---|
| S1 | Initial access via RDP brute force (T1110) | Published |
| S2 | Scheduled task persistence (T1053.005) | Published |
| S3 to S8 | To be defined | Planned |

Each scenario will have its own folder under `scenarios/`, with the commands run, the expected events and the Splunk searches that detect them. Detections live under `detections/`, one Markdown file per rule.

## Repository layout

```
soc-homelab/
├── README.md
├── scenarios/      attack steps and expected telemetry
└── detections/     detection rules and their validation
```
