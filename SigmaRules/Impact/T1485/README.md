# Atomic Red Team Tests for Advanced Threat Actors - T1485 Data Destruction

This repository documents **Atomic Red Team tests for T1485 (Data Destruction)** that emulate the **impact** tradecraft of a wide range of threat actors, from commodity ransomware to sophisticated Advanced Persistent Threats (APTs).

The goal is to:
* Provide defenders with relevant tests for detecting data destruction activities
* Map the tests to common adversary behaviors and underlying technical execution patterns
* Highlight critical detection opportunities to stop destructive attacks before significant damage occurs

---

## Background

* **T1485 (Data Destruction)** is a high-impact technique used by adversaries to render data irrecoverable, disrupt operations, and cause maximum damage to target organizations
* This technique is distinct from Disk Wipe (T1561) as it focuses on file/directory destruction rather than entire disk sectors
* Commonly employed by ransomware groups, hacktivists, and state-sponsored APTs during final attack stages

Threat actors leverage data destruction because it is:
* **Highly Destructive:** Causes immediate business disruption and recovery costs
* **Difficult to Recover:** Properly executed destruction prevents forensic recovery
* **Psychological Impact:** Sends a strong message to victims and stakeholders

---

## Selected Atomic Tests for T1485

| Test # | Technique | Description | Adversary Relevance |
|--------|-----------|-------------|---------------------|
| **1** | Windows - Overwrite file with SysInternals SDelete | Uses legitimate SysInternals tool to securely delete files | **Destruction Mechanism** |
| **3** | Overwrite deleted data on C drive | Uses cipher.exe to wipe free space, preventing file recovery | **Anti-Forensics** |
| **5** | ESXi - Delete VM Snapshots | Targets virtualization infrastructure for maximum disruption | **Cloud/Infrastructure Focus** |

---

## Detailed Test Analysis

### Atomic Test #1 - Windows - Overwrite file with SysInternals SDelete
**Technique:** Secure File Deletion
**Adversary Usage:** Targeted File Destruction
**Command:**
```powershell
& "PathToAtomicsFolder\..\ExternalPayloads\Sdelete\sdelete.exe" -accepteula "target_file.txt"
```
**Explanation:** This test uses Microsoft's official SysInternals SDelete utility to securely overwrite and delete files. The tool overwrites file data multiple times before deleting it, making forensic recovery extremely difficult. This represents adversaries using legitimate system tools for destructive purposes (Living off the Land).

**Adversary Correlation:** Advanced threat actors often use trusted system utilities to avoid detection while achieving their destructive goals.

### Atomic Test #3 - Overwrite deleted data on C drive
**Technique:** Anti-Forensics Data Wiping
**Adversary Usage:** Comprehensive Data Destruction
**Command:**
```cmd
cipher.exe /w:C:
```
**Explanation:** This test uses the built-in Windows cipher utility to overwrite all deleted data on the C: drive. This prevents recovery of any previously deleted files through forensic techniques. The RansomEXX ransomware group employed this method to maximize impact and hinder recovery efforts.

**Why this is a key detection opportunity:** The use of `cipher /w` on entire drives is highly unusual for normal administrative activity and represents a clear indicator of destructive intent.

### Atomic Test #5 - ESXi - Delete VM Snapshots
**Technique:** Virtualization Infrastructure Targeting
**Adversary Usage:** Critical Infrastructure Disruption
**Command:**
```cmd
plink.exe -batch "esxi_host" -ssh -l root -pw "password" "for i in `vim-cmd vmsvc/getallvms | awk 'NR>1 {print $1}'`; do vim-cmd vmsvc/snapshot.removeall $i & done"
```
**Explanation:** This test targets VMware ESXi infrastructure by deleting all virtual machine snapshots across the environment. This is particularly destructive as snapshots are often used for backup and recovery purposes. Removing them significantly impacts disaster recovery capabilities.

**Adversary Correlation:** State-sponsored APTs and sophisticated ransomware groups increasingly target virtualization infrastructure to maximize operational impact.

---

## Correlation with Adversary Tradecraft

### Common Characteristics:
* **Timing:** Often executed as final action in attack chain
* **Scope:** Can range from targeted file deletion to organization-wide destruction
* **Tooling:** Mix of built-in OS tools and specialized destructive utilities
* **Objectives:** Extortion, sabotage, political messaging, or covering tracks

### Technical Execution Chain:
1.  **Reconnaissance:** Identify critical data and systems
2.  **Access Establishment:** Gain appropriate privileges
3.  **Destruction Execution:** Deploy destruction mechanisms
4.  **Verification:** Confirm successful destruction
5.  **Coverage:** Remove evidence of destructive activities

### Tactical Objectives:
1.  **Impact (TA0040):** Primary objective is to cause organizational damage
2.  **Defense Evasion (TA0005):** Often includes anti-forensics measures

---

## Defender Notes

* **Prevention is critical.** The best defense is to limit privileges and monitor for unusual administrative activities
* Detection should focus on **destructive patterns** and **unusual tool usage**

**Critical Detection Opportunities:**
*   **Tool Usage:** Monitoring for unusual use of system utilities like:
    *   `cipher.exe /w` on production systems
    *   `sdelete.exe` in enterprise environments
    *   ESXi snapshot management commands
*   **Pattern Recognition:** Bulk deletion operations, especially of backup files, snapshots, or critical system files
*   **Access Patterns:** Unusual administrative access to critical systems or data repositories

### Mitigation Strategies:
* **Backup Protection:** Ensure backups are isolated and protected from destructive actions
* **Privilege Management:** Implement least privilege principles for all accounts
* **Monitoring:** Deploy robust monitoring for destructive command patterns
* **Incident Response:** Have tested recovery procedures for destructive incidents

## Campaign References

1.  **RansomEXX:** Used cipher.exe /w for anti-forensics data destruction
2.  **Shamoon:** Notorious for widespread data destruction in energy sector
3.  **Olympic Destroyer:** Employed destructive capabilities during Winter Olympics
4.  **APT Groups:** Various state-sponsored actors use data destruction for sabotage

## Academic References

1.  MITRE ATT&CK Technique T1485 - Data Destruction
2.  CISA: "Destructive Malware" Alert Series
3.  NIST: "Guidelines for Data Sanitization" (SP 800-88)
4.  Cybereason: "Analysis of RansomEXX Ransomware"

This test suite provides defenders with the necessary visibility to detect data destruction activities, allowing them to respond before adversaries can cause significant damage to organizational assets and operations.