# Atomic Red Team Tests for Lazarus Group - T1021.004 Remote Services: SSH

This repository documents **Atomic Red Team tests for T1021.004 (SSH)** that emulate the **persistence establishment and lateral movement** tradecraft of the **Lazarus Group** (a.k.a. Hidden Cobra, APT38).

The goal is to:
* Provide defenders with relevant tests for detecting malicious SSH service manipulation, particularly on ESXi systems.
* Map the tests to known Lazarus Group behaviors and campaigns, especially their ransomware operations.
* Highlight specific techniques used by this threat group for maintaining access and evading detection.

---

## Background

* **Lazarus Group** (Hidden Cobra, APT38) is a prolific North Korean state-sponsored threat group.
  * Responsible for destructive cyber attacks, espionage, and financially motivated campaigns, including the **WannaCry ransomware** outbreak and the **Sony Pictures hack**.
  * Known for **brazen, destructive attacks** and high-value financial theft (e.g., bank heists, cryptocurrency exchange compromises).
  * Has increasingly targeted **virtualization infrastructure**, especially VMware ESXi, for ransomware deployment.

* **Recent ESXi-Targeting Ransomware Campaigns** (2023-2025) demonstrate Lazarus's focus on SSH:
  * Groups like **Black Basta** (associated with Lazarus) specifically target ESXi hypervisors to encrypt virtual machines for maximum impact.
  * A common first step is to **enable the SSH service** on the ESXi host if it is not already active. This provides a persistent, encrypted command-and-control channel outside of the vCenter management suite.
  * This allows attackers to execute commands directly on the hypervisor, often to deploy ransomware payloads.

The Lazarus Group leverages T1021.004 (SSH) on ESXi because it allows them to:
* Gain direct command-line access to the hypervisor, the most critical part of a virtualized environment.
* Establish a persistent backdoor that is not dependent on the vCenter management platform.
* Execute commands with high privileges to shut down VMs and deploy ransomware encryptors.
* Use an encrypted protocol that can blend with any legitimate administrative traffic.

---

## Selected Atomic Tests for T1021.004

| Test # | Technique | Description | Lazarus Group Relevance |
|--------|-----------|-------------|-------------------------|
| **1** | Enable SSH via PowerCLI | Uses the VMware management module for PowerShell to enable the ESXi SSH daemon (TSM-SSH). | **Initial Access & Persistence** |
| **2** | Enable SSH via VIM-CMD | Uses the native ESXi shell command (`vim-cmd`) to enable the SSH service remotely. | **Persistence & Execution** |

---

## Detailed Test Analysis

### Atomic Test #1 - ESXi - Enable SSH via PowerCLI
**Technique:** Abuse of Valid Accounts & System Services
**Adversary Usage:** Lazarus Group (Initial Access & Persistence)
**Command:**
```powershell
Get-VMHostService -VMHost #{vm_host} | Where-Object {$_.Key -eq "TSM-SSH" } | Start-VMHostService
```
**Explanation:** This test uses the legitimate VMware PowerCLI module, typically used by system administrators, to enable the SSH service. Lazarus Group would use compromised administrator credentials to run this command, effectively "legitimizing" their malicious activity by using the approved management tool. This provides them with a remote shell access point.

**Lazarus Correlation:** This reflects a sophisticated approach where the group uses valid accounts and authorized software to achieve their goals, making detection harder. It is a critical step in their ESXi ransomware playbook.

### Atomic Test #2 - ESXi - Enable SSH via VIM-CMD
**Technique:** Abuse of Valid Accounts & System Services
**Adversary Usage:** Lazarus Group (Persistence & Execution)
**Command:**
```bash
vim-cmd hostsvc/enable_ssh
```
**Explanation:** This test demonstrates the direct method. If the Lazarus Group gains access to an ESXi host's shell (e.g., through a vulnerability or misconfiguration), they can use the built-in `vim-cmd` utility to enable SSH directly. This creates a more persistent foothold, ensuring access remains even if their initial entry vector is closed.

**Lazarus Correlation:** This is a common technique observed in post-compromise activity on ESXi hosts. It signifies an attacker consolidating their access and preparing the system for further malicious actions, such as deploying ransomware payloads.

---

## Correlation with Lazarus Group Tradecraft

### ESXi Ransomware Campaign Characteristics:
* **Targeting Critical Infrastructure:** Focus on ESXi servers to maximize disruption and extortion leverage.
* **Dual Use of Tools:** Use of both official management tools (PowerCLI) and native system commands (`vim-cmd`).
* **Persistence First:** Enabling SSH is not the end goal; it is the enabling step for follow-on actions like deploying encryptors.
* **Destructive End Goal:** The ultimate objective is often data encryption and destruction, not just espionage.

### Technical Implementation:
* **Authentication:** Relies on **compromised credentials** for ESXi `root` or vCenter administrative accounts.
* **Execution:** Commands are executed to manipulate system services (TSM-SSH).
* **Persistence:** The change (enabling SSH) persists across reboots unless manually reverted.

### Tactical Objectives:
1.  **Persistence:** Establish a reliable, long-term access method to the hypervisor.
2.  **Defense Evasion:** Use legitimate protocols and tools to avoid triggering security alerts.
3.  **Lateral Movement:** Use the hypervisor as a foothold to potentially attack other hosts or management components.
4.  **Impact:** Prepare the environment for the ultimate destructive payload (e.g., ransomware).

---

## Defender Notes

* These tests are critical for defending virtualized environments, which are high-value targets for destructive attacks.
* Detection should focus on:
  * **Service Modification:** Auditing for changes to the TSM-SSH service state (e.g., from stopped to running).
  * **Command Line Auditing:** Monitoring for the execution of `vim-cmd hostsvc/enable_ssh` or `Start-VMHostService` for the SSH service.
  * **PowerCLI Usage:** Logging and alerting on PowerCLI execution, especially from non-administrative workstations or outside of change windows.
  * **Network Traffic:** SSH connections (port 22) to ESXi hosts, particularly if SSH was previously disabled or if the source IP is unusual.

### Mitigation Strategies:
* **Hardening:** Ensure SSH is disabled on ESXi hosts if it is not explicitly required for operations. This is a primary mitigation.
* **Network Segmentation:** Strictly firewall ESXi management interfaces (including SSH) to allow access only from designated jump servers or administrative subnets.
* **Privileged Access Management (PAM):** Protect ESXi `root` and vCenter admin credentials with extreme care; use multi-factor authentication (MFA) where possible.
* **Logging and Monitoring:** Ensure ESXi logs are forwarded to a SIEM and that alerts are configured for service state changes.

## Campaign References

1.  **Black Basta Ransomware (2023-2024):** Extensive campaigns targeting ESXi environments, often involving the enabling of SSH as a precursor to encryption.
2.  **Other Lazarus-Affiliated Operations:** Consistent targeting of virtualization infrastructure for both cyberespionage and financially motivated attacks.

## Academic References

1.  MITRE ATT&CK Technique T1021.004 - Remote Services: SSH
2.  MITRE ATT&CK Technique T1578.002 - Modify System Service: Service Execution
3.  CISA Alert (AA24-131A): #StopRansomware: Black Basta
4.  VMware Security Hardening Guides

## Detection Recommendations

*   **SIEM Rules:**
    *   Alert on any ESXi log event indicating the TSM-SSH service being started.
    *   Correlate authentication events from administrative accounts with subsequent service modification events.
*   **EDR/VMware Monitoring:**
    *   Detect the execution of `vim-cmd hostsvc/enable_ssh` on an ESXi host.
    *   Monitor for PowerCLI being used to start the TSM-SSH service.
*   **Network Detection:**
    *   Alert on new SSH sessions to ESXi hosts, especially if the host previously had no SSH traffic.

This test suite provides defenders with the necessary visibility to detect and respond to the SSH-based persistence techniques used by the Lazarus Group, a critical component of their operational playbook for compromising and destroying virtualized environments.