# Atomic Red Team Tests for Advanced Threat Actors - T1566.001 Phishing: Spearphishing Attachment

This repository documents **Atomic Red Team tests for T1566.001 (Spearphishing Attachment)** that emulate the **initial access** tradecraft of a wide range of threat actors, from commodity ransomware to sophisticated Advanced Persistent Threats (APTs).

The goal is to:
* Provide defenders with relevant tests for detecting the delivery and execution of malicious email attachments.
* Map the tests to common adversary behaviors and the underlying social engineering and technical execution patterns.
* Highlight the critical detection opportunities to stop an attack at the initial access stage.

---

## Background

* **T1566.001 (Spearphishing Attachment)** is the most common initial access vector in the world. It is the primary entry point for ransomware, data theft, espionage, and everything in between.
* This technique is a subset of **Phishing (T1566)** and is distinct from **Spearphishing Link (T1566.002)** because the payload is delivered directly as an email attachment.
* It relies on **User Execution (T1204)**—the victim must open the file and interact with it (e.g., enable macros, click "OK" on a prompt).

Threat actors leverage spearphishing attachments because it is:
* **Highly Effective:** It bypasses technical controls by targeting human psychology.
* **Low Cost:** Easy to automate and deploy at scale.
* **Versatile:** A wide variety of file types can be used to deliver malware (Office macros, PDFs, ISO files, archives).

---

## Selected Atomic Tests for T1566.001

| Test # | Technique | Description | Adversary Relevance |
|--------|-----------|-------------|---------------------|
| **1** | Download Macro-Enabled Attachment | Simulates a user downloading a malicious macro-enabled Excel document from the internet. | **Delivery Mechanism** |
| **2** | Malicious Macro Execution | Simulates a Word document executing a VBA macro that writes a file to disk and spawns a command shell to run a network command. | **Payload Execution** |

---

## Detailed Test Analysis

### Atomic Test #1 - Download Macro-Enabled Phishing Attachment
**Technique:** Delivery and Download
**Adversary Usage:** Universal First Stage
**Command:**
```powershell
Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm
```
**Explanation:** This test emulates the final step of the phishing email interaction: the user clicks a link and downloads the malicious attachment. The file is typically saved to the user's `Temp` or `Downloads` directory. This step itself is not malicious but is the necessary precursor to execution. Detection at this stage is difficult as it blends with normal web browsing, but it can be caught by email filters (blocking the initial email) or web proxies (blocking the download URL).

**Adversary Correlation:** This is the action performed by the victim that completes the "delivery" phase of the cyber kill chain.

### Atomic Test #2 - Word spawned a command shell and used an IP address in the command line
**Technique:** User Execution & Defense Evasion
**Adversary Usage:** Universal Payload Execution
**Command (VBA Macro):**
```vba
Shell$ "ping 8.8.8.8"
```
**Explanation:** This test emulates the core malicious action: the execution of the payload. A Microsoft Word document contains a VBA macro. When the user enables macros, the macro code executes. In this case, it uses the `Shell` command to spawn a hidden command prompt (`cmd.exe`) which then executes a command (`ping 8.8.8.8`). In a real attack, this would be a command to download a payload, execute a PowerShell script, or establish a reverse shell.

**Why this is a key detection opportunity:** The parent-child process relationship of `winword.exe` -> `cmd.exe` is highly unusual for normal user activity and is a massive red flag. This is a primary signature for detecting malicious document execution.

**Adversary Correlation:** This is the "exploitation" and "installation" phase. The macro is the exploit that leads to the installation of further malware.

---

## Correlation with Adversary Tradecraft

### Common Characteristics:
* **Social Engineering:** The email will have a compelling lure (e.g., an invoice, a shipping notice, a resume) tailored to the target.
* **File Types:** Common malicious attachments include:
    *   **Macro-Enabled Office Docs:** `.docm`, `.xlsm`, `.pptm`
    *   **PDFs:** Exploiting vulnerabilities in PDF readers.
    *   **Archives:** `.zip`, `.rar` containing scripts or executables.
    *   **ISO files:** A modern trend to bypass email filters, containing a LNK file that executes code.
* **Obfuscation:** Macros and scripts are often heavily obfuscated to avoid signature-based detection.

### Technical Execution Chain:
1.  **Delivery:** Phishing email delivered to inbox.
2.  **User Execution:** User opens the attachment.
3.  **Exploitation:** User enables content/macros (or a vulnerability is exploited).
4.  **Payload Execution:** Macro/script executes (e.g., `winword.exe` -> `cmd.exe` -> `powershell.exe`).
5.  **Persistence:** The downloaded payload establishes persistence on the system.

### Tactical Objectives:
1.  **Initial Access (TA0001):** The sole purpose of this technique is to gain the first foothold inside a target network.

---

## Defender Notes

* **Prevention is paramount.** The best defense is to **block macro-enabled documents from the internet** via Group Policy or Microsoft Office security settings.
* Detection should focus on the **post-delivery execution**, as this is where clear behavioral signatures appear.

**Critical Detection Opportunities:**
*   **Process Creation:** The most reliable detection is monitoring for **Microsoft Office applications (winword.exe, excel.exe) spawning child processes** like:
    *   `cmd.exe`
    *   `powershell.exe`
    *   `wscript.exe`
    *   `mshta.exe`
*   **Command Line Arguments:** Look for command lines with suspicious arguments from Office applications, especially those involving network-related commands (`ping`, `nslookup`, `web requests`) or encoded PowerShell scripts.
*   **File Writing:** Office applications writing executable content (`*.exe`, `*.dll`, `*.jse`, `*.vbs`) to the `Temp` directory.

### Mitigation Strategies:
* **Disable Macros:** Block macros from the internet entirely via Group Policy.
* **Email Filtering:** Use advanced email security gateways to scan and detonate attachments.
* **Application Allowlisting:** Use tools like AppLocker to prevent Office applications from spawning scripting engines.
* **User Training:** Train users to identify and report phishing attempts.

## Campaign References

1.  **All Ransomware Groups:** Use phishing attachments as a primary initial access method.
2.  **APT29 (Cozy Bear):** Has used sophisticated phishing lures targeting government and diplomatic entities.
3.  **FIN7:** Notorious for using malicious Word documents in large-scale campaigns.

## Academic References

1.  MITRE ATT&CK Technique T1566.001 - Phishing: Spearphishing Attachment
2.  Microsoft: "How to block macros from running in Office from the internet"
3.  CISA: "Security Tip (ST04-010) - Avoiding Social Engineering and Phishing Attacks"

This test suite provides defenders with the necessary visibility to detect the critical execution phase of spearphishing attachments, allowing them to stop attacks at the initial access stage before adversaries can establish a foothold.