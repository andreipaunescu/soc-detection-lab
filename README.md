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
| S2 | Scheduled task persistence (T1053.005) | Planned |
| S3 to S8 | To be defined | Planned |

Each scenario will have its own folder under `scenarios/`, with the commands run, the expected events and the Splunk searches that detect them. Detections live under `detections/`, one Markdown file per rule.

## Lessons learned

These are the problems that took the most time to solve, and what they taught me.

**Failed logons were missing until the right audit was on.** Windows doesn't log failed logons unless failure auditing is enabled, and enabling success auditing alone isn't enough. Checking the policy with `auditpol /get` before running an attack saved time later.

**Bad passwords show up with a different logon type.** My first detection searched for `LogonType 10` (interactive RDP) for failed logons and found nothing. With Network Level Authentication, a wrong password is rejected before the RDP session starts, so the event is logged as `LogonType 3`. Checking the raw event XML, rather than trusting a field name from a search, was what revealed it.

**Field names differ between raw events and the add-on's mapping.** `Account_Name` and `Failure_Reason` were empty for failed logons, while the raw `TargetUserName` and `SubStatus` fields had the data. For detections, I'll use whichever field names are reliably populated.

**Network profiles and interface addresses don't persist on their own.** A Windows network with no gateway defaults back to the Public profile after a reboot, which blocks RDP. On the Linux side, an address set only in the GUI disappeared after a reboot. Both are fixed by making the setting explicit (a Private profile with a startup task, and a static NetworkManager profile).

**Timestamps need one clock.** Hydra logged in the Kali machine's local time (UTC-5), while Splunk displayed Bucharest time (UTC+2). Setting Kali to UTC and recording all notes in UTC makes correlating events across the lab straightforward.

**Module paths need one root.** Moving tools into a single `C:\lab` folder, and setting the Atomic Red Team path once in the PowerShell profile, removed the need to pass paths manually in every session.

## Repository layout

```
soc-homelab/
├── README.md
├── lab/            setup and runbook (test wordlists and loot stay on Kali)
├── scenarios/      attack steps and expected telemetry
└── detections/     detection rules and their validation
```
