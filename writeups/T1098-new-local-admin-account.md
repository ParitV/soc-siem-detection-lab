# T1098 / T1136.001 - New Local Admin Account (Privilege Escalation via Account Manipulation)

**Host:** DESKTOP-18T77L4
**Actor:** `paritvr` (SID `...-1001`) creating and escalating `attacker` (SID `...-1002`)
**Date/time:** 05:12:27 to 05:12:38 UTC

## Summary

A new local account was created and immediately escalated to the local Administrators group, a classic two-step create-then-escalate persistence pattern. Wazuh's built-in Windows ruleset detected every step of the sequence without any custom rule, and its severity tiering correctly distinguished routine account lifecycle activity from the privilege-escalation step.

## Alert Summary

| Time (UTC) | Event | Rule | Level |
|---|---|---|---|
| 05:12:27.529 | Event 4720, account `attacker` created | 60109, "User account enabled or created" | 8 (Medium) |
| 05:12:27.549 (+20ms) | Event 4732, added to "Users" group | 60170, "Users Group Changed" | 5 (Low) |
| 05:12:38.552 (+11s) | Event 4732, added to "Administrators" group | 60154, "Administrators Group Changed" | 12 (High), `rule.mail: true` |

## Evidence

- **SID chain:** `subjectUserSid` (`...-1001`, `paritvr`) performed every action. `targetSid` on the 4720 event and `memberSid` on both 4732 events all point to the same `...-1002` (`attacker`), proving one continuous sequence rather than three unrelated events.
- **The 20-millisecond gap** between account creation and the "Users" group addition is automatic Windows behavior on every new account, not a deliberate attacker action.
- **The 11-second gap** before the "Administrators" addition is the deliberate second command, a clear two-step create-then-escalate pattern rather than a single action. The exact millisecond timestamps are direct evidence of that sequence.
- **Severity tiering is itself a finding:** Wazuh treats "account created" as worth watching (level 8), treats addition to the ordinary "Users" group as routine noise (level 5, since every account ends up there), but escalates sharply to level 12 the moment "Administrators" specifically is touched. This is the ruleset correctly distinguishing normal account lifecycle from privilege escalation.
- **`rule.mail: true`** on rule 60154 shows Wazuh's maintainers specifically flagged this exact event to trigger an email notification by default, an indicator of how seriously the ruleset authors treat Administrators-group changes.

## MITRE ATT&CK Mapping

- **Tactic:** Persistence / Privilege Escalation
- **Technique:** T1098 (Account Manipulation); also mappable to T1136.001 (Create Account: Local Account)

## Impact

A new local administrator account gives an attacker a persistent, high-privilege foothold that survives a password reset on the originally compromised account, and can be used for further lateral movement, defense tampering, or direct data access.

## Response

- **Detect:** rule 60154 already triggers an email notification by default on any Administrators-group change, a strong signal that Wazuh's maintainers deliberately weighted this event heavily. Treat that email as a page-worthy alert, not routine noise.
- **Contain:** disable the new account immediately, and force a credential reset for the account that created it.
- **Harden:** alert on any change to the local Administrators group regardless of source, and restrict who can run `net localgroup administrators ... /add` via Group Policy or AppLocker.
- **Investigate:** pull the full logon history for the `attacker` account to determine whether it was used for anything before being caught.
