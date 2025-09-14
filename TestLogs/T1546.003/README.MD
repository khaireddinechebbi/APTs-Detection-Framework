# Atomic Red Team Tests for APT29 - T1546.003 Event Triggered Execution: WMI Event Subscription

This repository documents selected **Atomic Red Team tests for T1546.003 (Event Triggered Execution: WMI Event Subscription)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard).

The goal is to:
* Provide defenders with relevant tests for detecting WMI event subscription persistence activities
* Map the tests to known APT29 behaviors and campaigns
* Highlight specific techniques used by this threat group for advanced persistence

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Highly skilled in advanced persistence mechanisms and stealth techniques
  * Uses **WMI event subscriptions** for maintaining long-term access to compromised systems

* **Operation Ghost** (2013-2019) demonstrated APT29's sophisticated use of WMI event subscriptions:
  * Targeted ministries of foreign affairs and diplomatic entities
  * Used WMI for advanced persistence alongside steganography techniques
  * Maintained access for 6 years through sophisticated evasion methods

APT29 leverages T1546.003 (WMI Event Subscription) because it allows them to:
* Establish persistence that is difficult to detect and remove
* Execute code with SYSTEM privileges through WmiPrvSe.exe
* Blend with legitimate Windows management activities
* Maintain access across reboots and system changes

---

## Selected Atomic Tests for T1546.003

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **1** | Persistence via CommandLineEventConsumer | Uses WMI event filter to trigger command execution | **APT29** |
| **2** | Persistence via ActiveScriptEventConsumer | Uses WMI to execute VBScript code on event trigger | **APT29** |
| **3** | MOFComp.exe Load MOF File | Compiles and loads MOF files for WMI subscription | **APT29** |

---

## Detailed Test Analysis

### Atomic Test #1 - Persistence via CommandLineEventConsumer
**Technique:** WMI Command Execution Trigger  
**Adversary Usage:** APT29  
**Command:**
```powershell
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```
**Explanation:** APT29 uses WMI event filters with CommandLineEventConsumer to execute arbitrary commands when specific system events occur. This technique provides reliable persistence that executes with SYSTEM privileges and is difficult to detect through traditional means.

**APT29 Correlation:** Used in Operation Ghost and other campaigns for maintaining persistent access to high-value targets.

### Atomic Test #2 - Persistence via ActiveScriptEventConsumer
**Technique:** WMI Script Execution Trigger  
**Adversary Usage:** APT29  
**Command:**
```powershell
$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments $FilterArgs
$Consumer=Set-WmiInstance -Namespace "root\subscription" -Class ActiveScriptEventConsumer -Arguments $ConsumerArgs
$FilterToConsumerBinding = Set-WmiInstance -Namespace 'root/subscription' -Class '__FilterToConsumerBinding' -Arguments $FilterToConsumerArgs
```
**Explanation:** APT29 employs ActiveScriptEventConsumer to execute VBScript or JScript code through WMI events. This allows for more sophisticated execution chains while maintaining the stealth benefits of WMI-based persistence.

**APT29 Correlation:** Part of their advanced persistence toolkit used in long-term operations.

### Atomic Test #3 - Windows MOFComp.exe Load MOF File
**Technique:** MOF File Compilation and Loading  
**Adversary Usage:** APT29  
**Command:**
```powershell
mofcomp.exe "T1546.003.mof"
```
**Explanation:** APT29 uses the Managed Object Format (MOF) compiler to create permanent WMI event subscriptions. MOF files provide a declarative way to define WMI classes and event subscriptions that persist across reboots.

**APT29 Correlation:** Used for sophisticated persistence mechanisms that survive system changes and security tooling.

---

## Correlation with APT29 Tradecraft

### Operation Ghost Characteristics:
* **Long-term Persistence**: 6-year campaign duration using advanced techniques
* **Stealth Operations**: WMI subscriptions blend with legitimate management activities
* **System Privileges**: Execution through WmiPrvSe.exe with SYSTEM privileges
* **Evasion Focus**: Difficult to detect through traditional security monitoring

### Technical Implementation:
* **Event-based Triggers**: Execution based on system events (uptime, logon, etc.)
* **Multiple Consumer Types**: Command line, script, and other execution methods
* **Permanent Subscriptions**: MOF-based subscriptions that survive reboots
* **Legitimate Appearance**: Use of standard Windows management infrastructure

### Tactical Objectives:
1. **Persistence**: Maintain long-term access to compromised systems
2. **Privilege Escalation**: Execute code with SYSTEM privileges
3. **Defense Evasion**: Avoid detection by using legitimate Windows components
4. **Execution**: Run malicious code through trusted system processes

---

## Defender Notes

* These tests are high-value because they **closely emulate APT29's advanced persistence tradecraft**
* Detection should focus on:
  * Creation of WMI event filters, consumers, and bindings
  * Unusual WMI activity in the root/subscription namespace
  * MOF file compilation and loading activities
  * WmiPrvSe.exe executing unexpected child processes

* Critical detection opportunities:
  **WMI monitoring**: Event filter and consumer creation events
  **Process behavior**: WmiPrvSe.exe spawning unusual processes
  **File operations**: MOF file creation and compilation
  **Command line**: mofcomp.exe usage with suspicious files

### Mitigation Strategies:
* Implement WMI auditing and monitoring capabilities
* Use application control to restrict unnecessary WMI operations
* Monitor for unusual activity in root/subscription namespace
* Regularly review WMI event subscriptions for anomalies
* Implement privileged access management for WMI operations

## Campaign References

1. **Operation Ghost** (2013-2019): Extensive use of WMI event subscriptions for persistence
2. **SolarWinds Compromise**: Used WMI for various execution and persistence activities
3. **Various APT29 Operations**: Consistent use of advanced persistence mechanisms

## Academic References

1. MITRE ATT&CK Technique T1546.003 - Event Triggered Execution: WMI Event Subscription
2. Faou, M., Tartare, M., Dupuy, T. (2019) - "OPERATION GHOST" analysis
3. Microsoft: "Monitoring WMI Activity" documentation
4. Various cybersecurity intelligence reports on APT29 tradecraft

## Detection Recommendations

* **WMI Auditing**: Enable and monitor WMI activity logs
* **Behavioral Analysis**: Detect unusual WmiPrvSe.exe process behavior
* **Command Line Monitoring**: Alert on mofcomp.exe usage
* **Namespace Monitoring**: Watch for root/subscription modifications
* **Threat Intelligence**: Correlate with known APT29 WMI patterns

This test provides defenders with critical capabilities to detect and respond to WMI event subscription techniques used by APT29, which are fundamental to their persistent access strategies in targeted environments. The techniques demonstrated here reflect the advanced tradecraft that makes APT29 one of the most sophisticated threat actors operating today.