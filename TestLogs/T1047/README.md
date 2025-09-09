# Atomic Red Team Tests for APT29 & Lazarus Group - T1047 Windows Management Instrumentation

This repository documents **Atomic Red Team tests for T1047 (Windows Management Instrumentation)** that closely emulate the tradecraft of both **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with relevant tests for detecting WMI abuse activities
* Map the tests to known APT29 and Lazarus Group behaviors and campaigns
* Highlight specific techniques used by these threat groups for execution and lateral movement

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Highly skilled in living-off-the-land techniques and lateral movement
  * Uses **WMI abuse** for remote execution and lateral movement

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **financial theft campaigns** and destructive attacks
  * Uses **WMI** alongside other living-off-the-land techniques for execution and propagation
  * Leverages multiple execution methods to evade detection

Both groups leverage T1047 (Windows Management Instrumentation) because it allows them to:
* Execute malicious code through a trusted Windows management infrastructure
* Perform lateral movement using built-in system utilities
* Bypass application control solutions that don't monitor WMI activities
* Blend with legitimate administrative operations

---

## Atomic Test Analysis

### Atomic Test #5 - WMI Execute Local Process
**Technique:** Local Process Execution via WMI  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```cmd
wmic process call create notepad.exe
```
**Explanation:** Both APT29 and Lazarus Group use WMI for local process execution as part of their living-off-the-land methodology. This technique allows them to execute processes while blending with legitimate administrative activity and avoiding detection by security tools focused on traditional process creation.

**APT29 Correlation:** APT29 has used WMI for various system manipulation tasks during their espionage operations.
**Lazarus Correlation:** Lazarus Group employs WMI as one of multiple execution vectors in their attacks.

### Atomic Test #6 - WMI Execute Remote Process
**Technique:** Remote Process Execution via WMI  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```cmd
wmic /user:DOMAIN\Administrator /password:P@ssw0rd1 /node:"192.168.1.100" process call create cmd.exe
```
**Explanation:** Both groups use WMI for lateral movement within compromised networks. APT29 has famously used this technique for spreading through victim environments, while Lazarus Group employs it for rapid network propagation in financial and destructive attacks.

**APT29 Correlation:** Extensively used in SolarWinds campaign for lateral movement.
**Lazarus Correlation:** Employed in financial institution attacks and Operation Dream Job.

### Atomic Test #9 - WMI Execute rundll32
**Technique:** DLL Execution via WMI and Rundll32  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```cmd
wmic /node:127.0.0.1 process call create "rundll32.exe \"PathToAtomicsFolder\..\ExternalPayloads\calc.dll\" StartW"
```
**Explanation:** Both groups use technique chaining to evade detection. APT29 combines WMI with rundll32 for sophisticated execution chains, while Lazarus Group frequently uses rundll32 in various attack phases and combines it with WMI for additional obfuscation.

**APT29 Correlation:** Used in advanced execution chains for payload delivery.
**Lazarus Correlation:** Common in financial malware and ransomware operations.

---

## Correlation with APT29 & Lazarus Tradecraft

### APT29 Focus:
* **Stealthy Lateral Movement (#6)**: APT29 uses WMI for careful, targeted lateral movement
* **Living-off-the-Land (#5, #9)**: Heavy reliance on built-in Windows utilities
* **Long-term Operations**: WMI used for persistent access maintenance

### Lazarus Group Focus:
* **Rapid Propagation (#6)**: Lazarus uses WMI for aggressive network spreading
* **Multiple Techniques (#9)**: Combines WMI with other execution methods
* **Financial Objectives**: WMI used in bank network penetration

### Common Tactical Objectives:
1. **Execution**: Run malicious code through trusted Windows components
2. **Lateral Movement**: Move through networks using stolen credentials
3. **Defense Evasion**: Avoid detection by using legitimate administrative tools
4. **Persistence**: Maintain access through various execution mechanisms

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world tradecraft** from both threat groups
* Detection should focus on:
  * `wmic process call create` commands, especially with remote nodes
  * WMI network traffic over ports 135 (DCOM) or 5985/5986 (WinRM)
  * Authentication events followed by WMI execution
  * Unusual process chains involving wmic.exe and rundll32.exe

* Critical detection opportunities:
  * **Process creation**: wmic.exe creating child processes
  * **Network connections**: WMI traffic to multiple systems
  * **Command line**: Complex WMI commands with credentials and remote nodes
  * **Authentication**: Remote logins followed by WMI activity

### Mitigation Strategies:
* Implement application control to restrict wmic.exe if not required
* Monitor WMI activity through enhanced logging and auditing
* Use network segmentation to limit WMI traffic between segments
* Regularly review and remove unnecessary administrative privileges
* Implement credential management to detect stolen credential usage

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used WMI for lateral movement through victim networks
2. **APT29 COVID-19 Vaccine Targeting** (2020): Employed WMI for spreading through research environments
3. **Lazarus Operation Dream Job**: Used WMI alongside other execution techniques
4. **Lazarus Financial Attacks**: Employed WMI for bank network penetration

## Academic References

1. MITRE ATT&CK Technique T1047 - Windows Management Instrumentation
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (Lazarus Group)
4. CrowdStrike: "APT29 Targets COVID-19 Vaccine Development" (2020)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)

## Detection Recommendations

* **SIEM Rules**: Alert on wmic.exe with process creation commands
* **EDR Monitoring**: Track WMI process creation and remote execution
* **Network Monitoring**: Detect WMI traffic patterns and unusual connections
* **Authentication Monitoring**: Watch for credential use with WMI operations
* **Behavioral Analysis**: Identify unusual wmic.exe activity patterns

This test provides defenders with critical capabilities to detect and respond to WMI abuse techniques used by both APT29 and Lazarus Group, which are fundamental to their operational success in targeted environments.