# Atomic Red Team Tests for APT29 - T1021.006 Remote Services: Windows Remote Management

This repository documents **Atomic Red Team tests for T1021.006 (Windows Remote Management)** that emulate the **lateral movement and remote execution** tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard).

The goal is to:
* Provide defenders with relevant tests for detecting malicious WinRM activity.
* Map the tests to known APT29 behaviors and campaigns.
* Highlight specific techniques used by this threat group for lateral movement and command execution.

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a highly sophisticated Russian state-sponsored threat group.
  * A key actor in the **SolarWinds supply chain compromise** of 2020.
  * Known for stealth, patience, and the use of legitimate administrative tools for lateral movement (Living off the Land).
  * Heavily utilizes **PowerShell Remoting (WinRM)** and other native Windows features for executing commands on remote systems.

* **The SolarWinds Campaign** demonstrated APT29's mastery of WinRM:
  * Used compromised credentials to move laterally within victim networks.
  * Leveraged WinRM/PowerShell Remoting for hands-on-keyboard activity and execution of follow-on payloads.
  * Blended in with normal administrative traffic, making detection difficult.

APT29 leverages T1021.006 (WinRM) because it allows them to:
* Use stolen credentials to authenticate to remote systems legitimately.
* Execute commands remotely without dropping additional tools on disk (fileless execution).
* Abuse a protocol that is often enabled and required for administration in corporate environments.
* Evade detection by appearing as normal administrative activity.

---

## Selected Atomic Tests for T1021.006

| Test # | Technique | Description | APT29 Relevance |
|--------|-----------|-------------|-----------------|
| **1** | Enable WinRM | Enables PowerShell Remoting on a host to prepare it for remote access. | **Preparatory Step** |
| **2** | Remote Code Execution with `Invoke-Command` | Uses PowerShell Remoting to execute a command on a remote host (or localhost for simulation). | **Primary Execution** |
| **3** | WinRM Access with Evil-WinRM | Uses a common offensive tool to interact with a remote host via WinRM. | **Tool Usage** |

---

## Detailed Test Analysis

### Atomic Test #1 - Enable Windows Remote Management
**Technique:** Service Configuration Modification
**Adversary Usage:** APT29 (Preparatory Step)
**Command:**
```powershell
Enable-PSRemoting -Force
```
**Explanation:** Before using WinRM, it must be enabled on a target host. APT29 may run this command on a newly compromised host to facilitate further lateral movement from it. The `-Force` flag suppresses user prompts, making it suitable for silent execution.

**APT29 Correlation:** A necessary preparatory step to configure a system for remote management, often performed after initial access.

### Atomic Test #2 - Remote Code Execution with PS Credentials Using Invoke-Command
**Technique:** Remote Command Execution
**Adversary Usage:** APT29 (Primary TTP)
**Command:**
```powershell
Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock {whoami}
```
**Explanation:** This is the core technique. `Invoke-Command` is the primary PowerShell cmdlet for executing code on one or more remote systems via WinRM. APT29 uses this with valid credentials to run commands, deploy payloads, and conduct reconnaissance across the network.

**APT29 Correlation:** A direct emulation of how APT29 conducts lateral movement and execution during operations like SolarWinds. They use built-in tools to avoid detection.

### Atomic Test #3 - WinRM Access with Evil-WinRM
**Technique:** Remote Service Session
**Adversary Usage:** APT29 (Tool Usage)
**Command:**
```bash
evil-winrm -i #{destination_address} -u #{user_name} -p #{password}
```
**Explanation:** While APT29 heavily uses built-in tools, they also employ specialized offensive utilities. Evil-WinRM is a common tool that provides an interactive shell over WinRM, offering more features than the standard WinRM client. Its presence indicates more advanced adversary activity.

**APT29 Correlation:** APT29 is known to use a mix of built-in and custom tools. The use of a tool like Evil-WinRM would be consistent with their adaptable tradecraft for specific tasks.

---

## Correlation with APT29 Tradecraft

### SolarWinds Campaign Characteristics:
* **Abuse of Valid Accounts:** Used stolen credentials (e.g., SAML signing certificate) to gain unauthorized access.
* **Lateral Movement:** Moved from the compromised SolarWinds Orion server to other critical assets in the victim's environment.
* **Living off the Land:** Heavily relied on PowerShell and WinRM (`Invoke-Command`) for remote execution, minimizing the need for custom malware.
* **Stealth:** WinRM traffic (HTTP/S on ports 5985/5986) often blends with legitimate administrative traffic.

### Technical Implementation:
* **Authentication:** Uses Kerberos or NTLM authentication over WinRM, which appears identical to legitimate admin logins.
* **Execution:** Commands are executed remotely and output is returned to the attacker's session, often with no file touch.
* **Scope:** Can be used to execute commands on a single host or many hosts simultaneously.

### Tactical Objectives:
1. **Lateral Movement:** Move from the initial foothold to other systems of interest.
2. **Execution:** Run commands, scripts, and payloads on remote systems.
3. **Discovery:** Conduct reconnaissance across the network from a centralized tool.
4. **Persistence:** Establish new footholds on critical systems.

---

## Defender Notes

* These tests are critical for detecting post-compromise activity and lateral movement, a hallmark of APT29's operations.
* Detection should focus on:
  * **Network Traffic:** WinRM connections (port 5985/5986) originating from non-admin workstations or unexpected sources.
  * **Command Line:** Use of `Enable-PSRemoting` and `Invoke-Command`, especially with `-Credential` or targeting multiple computers.
  * **Logon Events:** Successful network logons (Event ID 4624) with Logon Type 3 (Network) followed by PowerShell process creation.
  * **PowerShell Logging:** Module logging showing the use of the `Microsoft.PowerShell.Core` module for `Invoke-Command`.

### Mitigation Strategies:
* **Network Segmentation:** Restrict WinRM traffic to specific administrative subnets and jump servers.
* **Privileged Access Management (PAM):** Strictly control and monitor accounts that have administrative privileges necessary for WinRM access.
* **Application Allowlisting:** Use tools like AppLocker or WDAC to restrict PowerShell execution to specific users and systems.
* **Enhanced Logging:** Enable PowerShell Module Logging, Script Block Logging, and ensure Windows Event Logs are collected and analyzed.

## Campaign References

1. **SolarWinds Campaign (2020):** Mass-scale use of compromised credentials and WinRM for lateral movement across victim environments.
2. **Multiple APT29 Operations:** Consistent use of PowerShell and WinRM for remote execution and lateral movement.

## Academic References

1. MITRE ATT&CK Technique T1021.006 - Remote Services: Windows Remote Management
2. US CISA Alert AA20-352A: Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations
3. Microsoft: "What is Windows Remote Management?"
4. Various cybersecurity intelligence reports on APT29 tradecraft.

## Detection Recommendations

* **SIEM Rules:**
    * Alert on `Enable-PSRemoting` being executed on endpoints.
    * Alert on `Invoke-Command` targeting multiple hosts or critical servers.
    * Correlate network logon events (4624, Logon Type 3) from unusual IPs with subsequent PowerShell execution.
* **EDR Detection:**
    * Detect the `evil-winrm` tool based on command-line arguments or process lineage.
    * Look for `winrs.exe` or `wsmprovhost.exe` (the WinRM client and host processes) with suspicious parent processes.
* **Network Detection:**
    * Monitor for WinRM connections outside of designated administrative hours or from non-corporate IP ranges.

This test suite provides defenders with the necessary visibility to detect and respond to the WinRM-based lateral movement techniques favored by APT29, a critical component of their operational playbook for navigating and exploiting victim networks.