# Atomic Red Team Tests for APT29 - T1003.002 OS Credential Dumping: Security Account Manager

This repository documents **Atomic Red Team tests for T1003.002 (OS Credential Dumping: SAM)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard).

The goal is to:
* Provide defenders with relevant tests for detecting SAM credential dumping activities
* Map the tests to known APT29 behaviors and campaigns
* Highlight specific techniques used by this threat group for credential access

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Highly skilled in credential access and lateral movement techniques
  * Uses **SAM database dumping** to extract local account credentials for privilege escalation and lateral movement

APT29 leverages T1003.002 (SAM Credential Dumping) because it allows them to:
* Extract local account password hashes from compromised systems
* Obtain credentials for lateral movement within networks
* Gain persistence by capturing local administrator accounts
* Perform pass-the-hash attacks using obtained credential materials

---

## Selected Atomic Tests for T1003.002

| Test # | Technique | Description | Used By |
|--------|-----------|-------------|---------|
| **1** | Registry dump of SAM, creds, and secrets | Uses reg save to extract SAM, SYSTEM, and SECURITY hives | **APT29** |
| **8** | Dumping of SAM, creds, and secrets (Reg Export) | Uses reg export as alternative to reg save | **APT29** |
| **3** | esentutl.exe SAM copy | Uses esentutl.exe to copy SAM database | **APT29** |

---

## Detailed Test Analysis

### Atomic Test #1 - Registry dump of SAM, creds, and secrets
**Technique:** Registry-Based Credential Dumping  
**Adversary Usage:** APT29  
**Command:**
```cmd
reg save HKLM\sam %temp%\sam
reg save HKLM\system %temp%\system
reg save HKLM\security %temp%\security
```
**Explanation:** This is a **primary technique** used by APT29 during their operations. The combination of extracting SAM, SYSTEM, and SECURITY hives allows them to obtain local account hashes, cached credentials, and LSA secrets. APT29 has been observed using this exact methodology in multiple campaigns.

### Atomic Test #8 - Dumping of SAM, creds, and secrets (Reg Export)
**Technique:** Alternative Registry Export  
**Adversary Usage:** APT29  
**Command:**
```cmd
reg export HKLM\sam %temp%\sam
reg export HKLM\system %temp%\system
reg export HKLM\security %temp%\security
```
**Explanation:** APT29 uses multiple methods for registry extraction. The `reg export` command provides an alternative to `reg save` that may evade some detection mechanisms while achieving the same objective.

### Atomic Test #3 - esentutl.exe SAM copy
**Technique:** Alternative SAM Extraction  
**Adversary Usage:** APT29  
**Command:**
```cmd
esentutl.exe /y /vss %SystemRoot%/system32/config/SAM /d %temp%/SAM
```
**Explanation:** APT29 employs multiple living-off-the-land techniques. Using esentutl.exe provides an alternative method for copying the SAM database that may bypass monitoring focused on reg.exe operations.

---

## Correlation with APT29 Tradecraft

### APT29 Focus:
* **Registry Operations (#1, #8)**: APT29 uses legitimate tools like reg.exe to extract SAM, SYSTEM, and SECURITY hives
* **Multiple Techniques (#3)**: Employment of alternative utilities like esentutl.exe for the same objective
* **Living-off-the-Land**: All techniques use built-in Windows utilities to avoid detection

### Tactical Objectives:
1. **Credential Access**: Extract local account password hashes from SAM database
2. **Lateral Movement**: Use obtained hashes for pass-the-hash attacks
3. **Persistence**: Maintain access through local account compromise
4. **Privilege Escalation**: Gain higher-level access through credential theft

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world APT29 tradecraft**
* Detection should focus on:
  * `reg save` or `reg export` operations targeting SAM, SYSTEM, and SECURITY hives
  * Files being written to temporary directories with names like "sam", "system", "security"
  * esentutl.exe copying files from system32/config directory
  * PowerShell scripts performing registry-based credential extraction
  * Unusual parent-child process relationships involving these activities

* Critical detection opportunities:
  * **Process creation**: reg.exe with save/export parameter targeting sensitive registry hives
  * **File creation**: Registry hive files written to temp directories
  * **Registry access**: Processes reading from sensitive security locations
  * **Privilege requirements**: These operations typically require SYSTEM privileges

### Mitigation Strategies:
* Implement application control to restrict unnecessary registry operations
* Monitor for registry access to sensitive security hives
* Use privileged access management to limit SYSTEM account activities
* Implement credential guard to protect against pass-the-hash attacks
* Regularly monitor for unusual file creation in temp directories

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used SAM and LSA secrets dumping to extract credentials for lateral movement
2. **APT29 COVID-19 Vaccine Targeting** (2020): Employed credential dumping techniques to gain access to research networks
3. **Various APT29 Operations**: Consistently demonstrated advanced credential access capabilities including SAM database extraction

## Academic References

1. MITRE ATT&CK Technique T1003.002 - OS Credential Dumping: Security Account Manager
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Russian SVR Activities" (APT29 TTPs)
4. CrowdStrike: "APT29 Targets COVID-19 Vaccine Development" (2020)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)

## Detection Recommendations

* **SIEM Rules**: Alert on reg.exe saving/exporting HKLM\sam, HKLM\system, HKLM\security
* **EDR Monitoring**: Track unusual file creation patterns in temp directories
* **Registry Monitoring**: Detect access to sensitive SAM database locations
* **Behavioral Analysis**: Identify unusual SYSTEM account activities involving registry operations
* **File Integrity Monitoring**: Watch for registry hive files in non-standard locations.