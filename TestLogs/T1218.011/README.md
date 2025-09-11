# Atomic Red Team Tests for APT29 and Lazarus Group - T1218.011 Signed Binary Proxy Execution: Rundll32

This repository documents selected **Atomic Red Team tests for T1218.011 (Signed Binary Proxy Execution: Rundll32)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with a curated set of relevant tests for detecting rundll32 abuse activities
* Map each test to known adversary behaviors and campaigns
* Highlight overlap and differences between the groups' execution techniques

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Frequently uses **living-off-the-land techniques** with legitimate system utilities
  * Employs **rundll32.exe** to execute malicious payloads and bypass application controls

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **financial theft campaigns** and destructive attacks including **Operation Dream Job**
  * Uses **rundll32.exe** to execute malicious payloads on compromised hosts
  * Leverages multiple execution methods to evade security controls

Both groups leverage T1218.011 (Rundll32) because it allows them to:
* Execute malicious code through a trusted Microsoft-signed binary
* Bypass application control solutions using legitimate Windows components
* Load and execute various file types beyond traditional DLLs
* Avoid detection by blending with normal system operations

---

## Selected Atomic Tests for T1218.011

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **10** | Execution of non-dll using rundll32.exe | Executes non-DLL files through rundll32 | **APT29 & Lazarus** |
| **11** | Rundll32 with Ordinal Value | Uses ordinal values for execution obscurity | **APT29** |
| **12** | Rundll32 with Control_RunDLL | Executes through Control Panel item method | **APT29** |
| **14** | Running DLL with .init extension and function | Uses file extension obfuscation for execution | **Lazarus** |

---

## Detailed Test Analysis

### Atomic Test #10 - Execution of non-dll using rundll32.exe
**Technique:** Non-DLL File Execution via Rundll32  
**Adversary Usage:** APT29 & Lazarus Group  
**Command:**
```powershell
rundll32.exe C:\Users\$env:username\Downloads\calc.png, StartW
```
**Explanation:** Both groups use rundll32 to execute non-DLL files, exploiting its flexibility in loading various file types. Lazarus Group specifically used this technique during Operation Dream Job to execute a .db file, while APT29 employed similar methods during the SolarWinds campaign.

**APT29 Correlation:** Used during SolarWinds campaign for executing various payload types through trusted utilities.
**Lazarus Correlation:** Directly used in Operation Dream Job: `rundll32.exe "C:\ProgramData\ThumbNail\thumbnail.db", CtrlPanel...`

### Atomic Test #11 - Rundll32 with Ordinal Value
**Technique:** Ordinal Value Execution for Obscurity  
**Adversary Usage:** APT29  
**Command:**
```cmd
rundll32.exe "PathToAtomicsFolder\T1218.010\bin\AllTheThingsx64.dll",#2
```
**Explanation:** APT29 uses advanced obfuscation techniques like ordinal value execution to hide malicious activity. This approach makes analysis more difficult by avoiding clear function name references, which aligns with their sophisticated tradecraft.

### Atomic Test #12 - Rundll32 with Control_RunDLL
**Technique:** Control Panel Item Execution  
**Adversary Usage:** APT29  
**Command:**
```cmd
rundll32.exe shell32.dll,Control_RunDLL "PathToAtomicsFolder\T1047\bin\calc.dll"
```
**Explanation:** APT29 employs multiple execution methods, including abuse of Control Panel item execution through rundll32. This technique provides alternative execution vectors that may evade monitoring focused on traditional DLL loading.

### Atomic Test #14 - Running DLL with .init extension and function
**Technique:** File Extension Obfuscation  
**Adversary Usage:** Lazarus Group  
**Command:**
```cmd
rundll32.exe PathToAtomicsFolder\T1218.011\bin\_WT.init,krnl
```
**Explanation:** Lazarus Group uses file extension obfuscation to evade detection. This test demonstrates executing a DLL with an .init extension, similar to how Lazarus used a .db file extension to disguise malicious payloads during Operation Dream Job.

---

## Correlation with APT29 & Lazarus

* **APT29 Focus:**
  * Advanced obfuscation techniques (#11 - ordinal values)
  * Multiple execution methods (#12 - Control_RunDLL)
  * Sophisticated tradecraft for defense evasion
  → Used for stealthy payload execution during espionage operations

* **Lazarus Group Focus:**
  * File extension obfuscation (#14 - .init files)
  * Non-traditional file execution (#10 - .db files)
  * Direct payload execution through trusted binaries
  → Used for rapid payload deployment in financial and destructive attacks

* **Overlap:**
  * Both groups abuse **rundll32.exe** for execution
  * Both leverage **trusted Windows utilities** to evade detection
  * Both use **file type manipulation** to bypass security controls
  * Both employ **multiple execution methods** in attack chains

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world adversary tradecraft**
* Detection should focus on:
  * rundll32.exe executing non-DLL files (#10 - especially unusual extensions)
  * rundll32.exe with ordinal values instead of function names (#11)
  * Unusual file extensions being loaded by rundll32 (#14 - .init, .db, etc.)
  * Control_RunDLL and other non-standard execution methods (#12)
  * rundll32.exe executing from unusual directories or with unusual parent processes

* Correlation across events is essential:
  * Process creation + file operations with unusual extensions
  * Command line analysis for obfuscation techniques
  * Parent-child process relationships involving rundll32
  * Multiple execution methods chained together

* Implement application control to restrict rundll32.exe if not needed for business purposes
* Monitor for rundll32.exe execution patterns that deviate from normal administrative use

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used rundll32 for various payload execution methods during the compromise
2. **Lazarus Operation Dream Job**: Used rundll32 to execute thumbnail.db file with specific parameters
3. **APT29 Various Operations**: Employed advanced rundll32 techniques for defense evasion in espionage campaigns
4. **Lazarus Financial Attacks**: Used rundll32 for payload execution in banking network penetration

## Academic References

1. MITRE ATT&CK Technique T1218.011 - Signed Binary Proxy Execution: Rundll32
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (Lazarus Group TTPs)
4. CrowdStrike: "APT29 Tradecraft and Techniques" (2023)
5. Kaspersky: "Lazarus Group Operation Dream Job Analysis" (2022)