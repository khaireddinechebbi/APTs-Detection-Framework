# Atomic Red Team Tests for APT29 & Lazarus Group - T1053.005 Scheduled Task/Job: Scheduled Task

This repository documents **Atomic Red Team tests for T1053.005 (Scheduled Task/Job: Scheduled Task)** that closely emulate the tradecraft of both **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with relevant tests for detecting scheduled task abuse activities
* Map the tests to known APT29 and Lazarus Group behaviors and campaigns
* Highlight specific techniques used by these threat groups for persistence and lateral movement

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Highly skilled in persistence mechanisms and lateral movement
  * Uses **scheduled task abuse** for maintaining access and executing tools

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **financial theft campaigns** and destructive attacks
  * Uses **scheduled tasks** for periodic execution of payloads and persistence
  * Leverages multiple task creation methods for defense evasion

Both groups leverage T1053.005 (Scheduled Task) because it allows them to:
* Establish persistence through automatic execution at system startup or user logon
* Execute tools and payloads on remote systems for lateral movement
* Blend malicious activity with legitimate Windows task scheduling
* Evade detection by using built-in system utilities

---

## Atomic Test Analysis

### Atomic Test #1 - Scheduled Task Startup Script
**Technique:** Logon/Startup Task Persistence  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```cmd
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```
**Explanation:** Both groups use scheduled tasks for persistence. APT29 created tasks to maintain persistence when hosts booted, while Lazarus Group used scheduled tasks for periodic execution of remote scripts and dropped payloads.

**APT29 Correlation:** Used startup tasks for persistent access during SolarWinds campaign.
**Lazarus Correlation:** Employed periodic task execution in Operation Dream Job.

### Atomic Test #3 - Scheduled task Remote
**Technique:** Remote Task Creation for Lateral Movement  
**Adversary Usage:** APT29  
**Command:**
```cmd
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
```
**Explanation:** APT29 used this technique extensively during the SolarWinds campaign to create tasks on remote hosts as part of their lateral movement strategy, using stolen credentials to propagate through networks.

**APT29 Correlation:** Primary technique for lateral movement in victim environments.

### Atomic Test #7 - Scheduled Task Executing Base64 Encoded Commands From Registry
**Technique:** Stealthy Task Execution with Encoded Commands  
**Adversary Usage:** Lazarus Group  
**Command:**
```cmd
schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st #{time}
```
**Explanation:** Lazarus Group uses encoded commands and registry storage for stealthy task execution. This technique resembles their approach of periodic execution while avoiding clear-text command logging.

**Lazarus Correlation:** Similar to techniques used for maintaining persistent access.

### Atomic Test #9 - PowerShell Modify A Scheduled Task
**Technique:** Task Manipulation for Tool Execution  
**Adversary Usage:** APT29  
**Command:**
```powershell
Set-ScheduledTask "AtomicTaskModifed" -Action $NewAction
```
**Explanation:** APT29 demonstrated sophisticated tradecraft by manipulating existing legitimate tasks - updating them to execute their tools and then restoring original configurations to avoid detection.

**APT29 Correlation:** Used in SolarWinds campaign for executing tools while maintaining stealth.

---

## Correlation with APT29 & Lazarus Tradecraft

### APT29 Focus:
* **Remote Task Creation (#3)**: Lateral movement through remote task deployment
* **Task Manipulation (#9)**: Sophisticated modification of existing tasks
* **Startup Persistence (#1)**: Long-term access maintenance through boot tasks
* **Stealth Operations**: careful task management to avoid detection

### Lazarus Group Focus:
* **Periodic Execution (#7)**: Scheduled payload execution at regular intervals
* **Script Execution**: Running remote scripts through scheduled tasks
* **Persistence Maintenance (#1)**: Maintaining access through logon tasks
* **Multiple Methods**: Using various task creation techniques

### Common Tactical Objectives:
1. **Persistence**: Maintain long-term access to compromised systems
2. **Lateral Movement**: Execute code on remote systems within networks
3. **Defense Evasion**: Blend with legitimate Windows task scheduling
4. **Execution**: Run tools and payloads through trusted mechanisms

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world tradecraft** from both sophisticated threat groups
* Detection should focus on:
  * `schtasks /create` commands, especially with remote system targeting
  * Scheduled task modifications and action changes
  * Tasks executing encoded commands or registry-stored payloads
  * Unusual task names or execution patterns

* Critical detection opportunities:
  * **Process creation**: schtasks.exe creating or modifying tasks
  * **Registry modifications**: Changes to task-related registry keys
  * **Scheduled task events**: Windows event logs for task creation/modification
  * **Network activity**: Remote task creation attempts

### Mitigation Strategies:
* Implement application control to restrict schtasks.exe if not required
* Monitor scheduled task creation and modification events
* Use privileged access management to limit remote task creation capabilities
* Regularly audit scheduled tasks for unusual configurations
* Implement network segmentation to limit lateral movement opportunities

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used remote task creation for lateral movement and task manipulation for tool execution
2. **APT29 Various Operations**: Employed startup tasks for persistent access maintenance
3. **Lazarus Operation Dream Job**: Used scheduled tasks for periodic execution of remote scripts
4. **Lazarus Financial Attacks**: Employed task persistence for long-term access to financial networks

## Academic References

1. MITRE ATT&CK Technique T1053.005 - Scheduled Task/Job: Scheduled Task
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (Lazarus Group)
4. CrowdStrike: "APT29 Tradecraft and Techniques" (2023)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)

## Detection Recommendations

* **SIEM Rules**: Alert on schtasks.exe with remote create/modify commands
* **EDR Monitoring**: Track scheduled task creation and modification activities
* **Windows Event Logging**: Monitor TaskScheduler operational logs for suspicious events
* **Registry Monitoring**: Detect changes to task-related registry locations
* **Behavioral Analysis**: Identify unusual task scheduling patterns.