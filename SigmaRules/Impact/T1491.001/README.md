# Atomic Red Team Tests for Advanced Threat Actors - T1491.001 Defacement: Internal Defacement

This repository documents **Atomic Red Team tests for T1491.001 (Internal Defacement)** that emulate the **impact** tradecraft of ransomware groups and sophisticated threat actors seeking to intimidate victims and disrupt operations through visual system modifications.

The goal is to:
* Provide defenders with relevant tests for detecting system defacement activities
* Map the tests to common adversary behaviors and psychological operations
* Highlight critical detection opportunities to identify system compromise through visible changes

---

## Background

* **T1491.001 (Internal Defacement)** is an impact technique where adversaries modify system interfaces to display threatening messages, often as part of ransomware or hacktivist campaigns
* This technique serves both psychological and operational purposes: intimidating victims, demonstrating compromise, and pressuring compliance with demands
* Commonly employed by ransomware groups to increase pressure for payment and by hacktivists to spread messages

Threat actors leverage internal defacement because it:
* **Creates Immediate Impact**: Visually demonstrates system compromise to users
* **Increases Psychological Pressure**: Makes the threat tangible and urgent for victims
* **Disrupts Operations**: Can prevent normal system use through obstructive messages
* **Amplifies Message**: Reaches all system users simultaneously

---

## Selected Atomic Tests for T1491.001

| Test # | Technique | Description | Adversary Relevance |
|--------|-----------|-------------|---------------------|
| **1** | Replace Desktop Wallpaper | Changes user desktop background to display threat messages | **User Intimidation** |
| **2** | Configure LegalNotice Registry Keys | Modifies system login messages to display ransom notes | **Boot-Time Intimidation** |
| **3** | ESXi - Change DCUI Welcome Message | Alters virtualization host welcome messages | **Infrastructure Targeting** |

---

## Detailed Test Analysis

### Atomic Test #1 - Replace Desktop Wallpaper
**Technique:** User Interface Modification
**Adversary Usage:** Immediate Visual Impact
**Command:**
```powershell
# Downloads and sets malicious wallpaper
$wc.DownloadFile($url, $imgLocation)
[Win32.Wallpaper]::SetWallpaper($imgLocation)
```
**Explanation:** This test downloads an image from a remote URL and sets it as the desktop wallpaper. Ransomware groups often use this to display payment instructions, threats, or contact information directly on the user's desktop. The image typically contains ransom notes, Bitcoin addresses, and threats about data exposure.

**Adversary Correlation:** Groups like Maze, Conti, and REvil have used desktop wallpaper changes to pressure victims into paying ransoms.

### Atomic Test #2 - Configure LegalNoticeCaption and LegalNoticeText Registry Keys
**Technique:** System Message Modification
**Adversary Usage:** Pre-Login Intimidation
**Command:**
```powershell
# Modifies legal notice registry keys
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption -Value "PYSA" -Force
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText -Value "Ransom message..." -Force
```
**Explanation:** This test modifies Windows registry keys that control the legal notice displayed before user login. This ensures every user sees the ransom message when attempting to access the system, creating maximum visibility and pressure. The message appears before credentials are entered, making normal system access impossible without seeing the threat.

**Adversary Correlation:** Used by PYSA, Grief, Maze, DopplePaymer, and other ransomware groups to display ransom notes at system startup.

### Atomic Test #3 - ESXi - Change Welcome Message on Direct Console User Interface (DCUI)
**Technique:** Infrastructure Message Modification
**Adversary Usage:** Hypervisor-Level Intimidation
**Command:**
```cmd
# Modifies ESXi host welcome message
esxcli system welcomemsg set -m 'RANSOMWARE-NOTIFICATION'
```
**Explanation:** This test targets VMware ESXi hypervisors by changing the Direct Console User Interface welcome message. This affects the physical console access to virtualization hosts, demonstrating compromise at the infrastructure level and impacting critical business systems.

**Adversary Correlation:** Ransomware groups increasingly target virtualization infrastructure, and modifying console messages demonstrates complete control over critical systems.

---

## Correlation with Adversary Tradecraft

### Common Characteristics:
* **Timing:** Typically occurs after data encryption during ransomware attacks
* **Scope:** Can affect individual workstations or entire infrastructure
* **Content:** Includes payment instructions, threats, contact information, and deadlines
* **Persistence:** Messages remain visible until manually removed

### Technical Execution Chain:
1.  **Initial Access:** Compromise through phishing, vulnerabilities, or exposed services
2.  **Privilege Escalation:** Gain administrative privileges required for system modifications
3.  **Defacement Execution:** Modify system interfaces to display threatening messages
4.  **Verification:** Confirm changes are visible to users
5.  **Communication:** Often coupled with extortion emails and dark web sites

### Tactical Objectives:
1.  **Impact (TA0040):** Primary objective is psychological pressure and operational disruption
2.  **Credential Access (TA0006):** May be combined with credential harvesting through fake login prompts

---

## Defender Notes

* **Visibility is crucial.** Monitor for system modifications that indicate defacement
* **Response should be immediate** to prevent psychological impact on users

**Critical Detection Opportunities:**
*   **Registry Changes:** Monitor modifications to:
    *   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption`
    *   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText`
*   **File System Changes:** Detection of new wallpaper images in system directories
*   **Process Monitoring:** Unusual processes modifying system UI elements
*   **ESXI Configuration Changes:** Modifications to hypervisor welcome messages

### Mitigation Strategies:
* **Registry Monitoring:** Implement change detection for critical system registry keys
* **Application Control:** Restrict ability to modify system UI elements
* **User Education:** Train users to recognize and report system defacement
* **Incident Response:** Have procedures for rapid restoration of original system messages
* **Backup Verification:** Ensure clean backups are available for system restoration

## Campaign References

1.  **PYSA Ransomware:** Known for using LegalNotice registry modifications
2.  **Maze Ransomware:** Used desktop wallpapers and system messages for extortion
3.  **Grief Ransomware:** Employed system defacement as pressure tactic
4.  **ESXi-Targeting Ransomware:** Groups like LockBit and RansomEXX target virtualization platforms

## Academic References

1.  MITRE ATT&CK Technique T1491.001 - Defacement: Internal Defacement
2.  CISA: "Ransomware Guide" prevention and response best practices
3.  NIST: "Computer Security Incident Handling Guide" (SP 800-61)
4.  Trend Micro: "Analysis of Ransomware Defense and Mitigation Strategies"

This test suite provides defenders with the necessary visibility to detect system defacement activities, allowing them to respond quickly to ransomware incidents and minimize psychological impact on users while maintaining business operations.