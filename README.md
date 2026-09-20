# SOC/SIEM Detection Lab

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.14.7-1a73e8)
![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-informational)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-red)

A home SOC/SIEM detection lab built with Wazuh, Sysmon, and isolated Windows and Kali VMs, simulating 4 MITRE ATT&CK techniques with full detection write ups, including a built in rule gap found and closed with custom detections.

## Architecture

The lab runs on 3 machines connected on a single isolated internal network with no route to the internet or the host's home network:

| Machine | Role | IP Address |
|---|---|---|
| Windows 10/11 VM | Target host | 192.168.56.10 |
| Kali Linux VM | Attacker host | 192.168.56.20 (shifted to 192.168.56.102 mid session via DHCP) |
| Wazuh manager | SIEM (Docker, host machine) | 192.168.56.1 |

The Windows VM runs Sysmon for endpoint telemetry and the Wazuh agent to forward logs. The Kali VM runs the attack tooling (Hydra, netexec, PowerShell payload hosting). Wazuh's manager, indexer, and dashboard run as a single node Docker deployment on the host, reachable from both VMs.

## Techniques Simulated

| MITRE ID | Technique | Detection Method | Write up |
|---|---|---|---|
| T1110.001 | Brute Force, Password Guessing | Built in rule (Windows Event 4625) | [writeups/T1110-brute-force-login.md](writeups/T1110-brute-force-login.md) |
| T1059.001 | Command and Scripting Interpreter, PowerShell | Custom rule 100002 | [writeups/T1059.001-suspicious-powershell.md](writeups/T1059.001-suspicious-powershell.md) |
| T1098 / T1136.001 | Account Manipulation / Create Local Account | Built in rules 60109, 60170, 60154 | [writeups/T1098-new-local-admin-account.md](writeups/T1098-new-local-admin-account.md) |
| T1003.001 | OS Credential Dumping, LSASS Memory | Raw telemetry plus custom rules 100004 and 100010 (built in rule 92900 has a detection gap, see below) | [writeups/T1003.001-credential-dumping.md](writeups/T1003.001-credential-dumping.md) |
| T1053.005 | Scheduled Task/Job | Attempted, descoped from the final write up set | [writeups/T1053.005-scheduled-task-persistence-DESCOPED.md](writeups/T1053.005-scheduled-task-persistence-DESCOPED.md) |

## Key Finding: A Real Gap in Wazuh's Built in Ruleset

Wazuh's built in rule 92900 is designed to catch LSASS credential dumping via Sysmon Event 10, but it never fired against ProcDump in this lab. The rule's `GrantedAccess` allowlist only matches `0x1010` or `0x40`, values that predate current Windows and Sysmon access mask conventions. The raw Sysmon telemetry confirms that `procdump64.exe -ma` actually requests `GrantedAccess: 0x1FFFFF` on this host, a value entirely outside the rule's allowlist.

Two custom rules were written to close this gap: rule 100004, a precise, high confidence rule scoped to `sourceImage=procdump`, and rule 100010, a broader rule that catches any process accessing `lsass.exe`. Both were validated against live attack traffic. The full investigation, including two independent custom rule dependency bugs that had to be fixed before either rule would fire, is documented in [writeups/T1003.001-credential-dumping.md](writeups/T1003.001-credential-dumping.md).

## How to Reproduce

See [docs/build-guide.md](docs/build-guide.md) for the full as built environment setup, including the two configuration issues that were found and fixed along the way (Sysmon's ProcessAccess logging shipping disabled by default, and the Kali VM's DHCP assigned IP shifting mid test).

## Repo Structure

```
soc-siem-detection-lab/
├── README.md                  This file
├── docs/
│   └── build-guide.md         Full environment build and configuration guide
├── configs/
│   ├── sysmonconfig-export.xml   Sysmon configuration used on the Windows VM
│   └── local_rules.xml           Custom Wazuh detection rules
├── writeups/                  One investigation write up per technique
│   ├── T1110-brute-force-login.md
│   ├── T1059.001-suspicious-powershell.md
│   ├── T1098-new-local-admin-account.md
│   ├── T1003.001-credential-dumping.md
│   └── T1053.005-scheduled-task-persistence-DESCOPED.md
└── screenshots/                Supporting screenshots, one folder per technique
```

## Tools Used

- VirtualBox
- Windows 10/11
- Kali Linux
- Wazuh 4.14.7 (Docker)
- Sysmon
- ProcDump
- Hydra
- netexec

## Author

Parit Vorasaran
