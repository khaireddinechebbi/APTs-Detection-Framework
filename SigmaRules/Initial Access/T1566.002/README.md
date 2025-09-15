# Atomic Red Team Tests for Advanced Threat Actors - T1566.002 Phishing: Spearphishing Link

This repository documents **Atomic Red Team tests for T1566.002 (Spearphishing Link)** that emulate the **initial access** tradecraft of threat actors who use malicious URLs instead of attachments to bypass security controls.

The goal is to:
* Provide defenders with relevant tests for detecting user-driven execution via malicious links.
* Map the tests to common adversary behaviors, particularly the "Paste and Run" technique.
* Highlight the critical detection opportunities that differ from attachment-based phishing.

---

## Background

* **T1566.002 (Spearphishing Link)** is a highly prevalent initial access vector. It differs from its counterpart (**T1566.001 Spearphishing Attachment**) by delivering the malicious payload via a link to an external website rather than as a direct email attachment.
* This technique is often favored because it can more easily **evade email security gateways** that focus on scanning attachments. The email itself contains no malicious content, only a link.
* It relies heavily on **User Execution (T1204)** and social engineering—the victim must click the link and then perform an action on the resulting web page (e.g., download a file, enter credentials, copy and paste a command).

Threat actors leverage spearphishing links because:
* **Evades Detection:** The initial email is clean, making it harder for automated systems to block.
* **Flexible:** The payload hosted on the website can be changed quickly without needing to send new emails.
* **Credential Harvesting:** Perfect for phishing login pages to steal credentials for **Valid Accounts (T1078)**.
* **Multi-Stage Attacks:** Allows for reconnaissance (seeing who clicks the link) before delivering the final payload.

---

## Selected Atomic Test for T1566.002

| Test # | Technique | Description | Adversary Relevance |
|--------|-----------|-------------|---------------------|
| **1** | Paste and Run Technique | Simulates a campaign where a user is tricked into copying and executing a malicious command from a website. | **Evasion & User Execution** |

---

## Detailed Test Analysis

### Atomic Test #1 - Paste and Run Technique
**Technique:** User Execution via GUI Manipulation
**Adversary Usage:** Increasingly Common in Malvertising and Phishing Campaigns
**Method:**
1.  **The Lure:** A user visits a malicious website (e.g., from a phishing email link). The site displays fake error messages or CAPTCHas.
2.  **The Trick:** The user is instructed to "fix" the issue by copying a provided command and pasting it into the Run dialog (`Win + R`).
3.  **The Execution:** This test uses PowerShell to **programmatically simulate** this action. It automates pressing `WIN + R` to open the Run dialog and then "types" a Base64-encoded PowerShell command that executes `calc.exe` (a stand-in for a real malicious payload).

**Key Commands:**
```powershell
# Simulates pressing WIN+R
[K]::keybd_event($VK_LWIN, 0, $KEYDOWN, [UIntPtr]::Zero)
[K]::keybd_event($VK_R, 0, $KEYDOWN, [UIntPtr]::Zero)

# "Types" the malicious command into the Run dialog
[System.Windows.Forms.SendKeys]::SendWait("cmd /c powershell -ec <BASE64_ENCODED_PAYLOAD> {ENTER}")
```

**Why this is a key detection opportunity:** This technique is highly effective because it doesn't require the user to open an email attachment. The entire malicious process begins with a user action on a website. Detection must therefore focus on the **resulting command execution** rather than the initial email.

**Adversary Correlation:** This technique has been used in real campaigns, such as the **Fake CAPTCHA** campaign noted in the test, which delivered the Lumma Stealer malware to users of pirated movie sites.

---

## Correlation with Adversary Tradecraft

### Common Characteristics:
* **The Lure:** Emails with urgent requests ("Your package couldn't be delivered", "Your account has been locked", "You must update your security settings").
* **The Hook:** Links leading to convincing fake login portals (e.g., Microsoft 365, Google, corporate VPN) or websites that prompt the user to run a command or download a file.
* **The Payload:** Often leads to:
    *   **Credential Harvesting:** Fake login pages stealing usernames and passwords.
    *   **Malware Download:** Downloaders for info-stealers (e.g., Lumma, Vidar) or ransomware.
    *   **Direct Execution:** Using the "Paste and Run" method to execute commands immediately.

### Technical Execution Chain:
1.  **Delivery:** Clean email with a link is delivered.
2.  **User Execution:** User clicks the link, opening a web browser.
3.  **Social Engineering:** User is tricked on the website into downloading a file, entering credentials, or copying a command.
4.  **Payload Execution:** The malicious action is performed (e.g., `powershell.exe` runs an encoded command from the Run dialog).

### Tactical Objectives:
1.  **Initial Access (TA0001):** The primary goal.
2.  **Credential Access (TA0006):** If the link leads to a phishing page.

---

## Defender Notes

* **Defense is multi-layered.** No single control can stop this; it requires a combination of technical controls and user awareness.
* Detection must focus on the **actions that follow the link click**, not the email itself.

**Critical Detection Opportunities:**
*   **Process Creation from Browser:** A web browser process (`msedge.exe`, `chrome.exe`) spawning a script host (`powershell.exe`, `wscript.exe`, `cmd.exe`) is a massive red flag.
    *   `parent.name : ("msedge.exe", "chrome.exe", "firefox.exe") and process.name : ("powershell.exe", "cmd.exe")`
*   **Suspicious PowerShell Parameters:** The use of the `-EncodedCommand` (`-ec`) flag with a Base64 string is a common way to obfuscate commands.
    *   `process.args : ("-ec", "-EncodedCommand", "-e")`
*   **Run Dialog Usage for Code Execution:** While harder to detect, the execution of unusual commands from the Run Dialog can be monitored via command-line auditing.

### Mitigation Strategies:
* **Web Proxies & DNS Filtering:** Block access to known malicious domains and newly registered domains.
* **Network Monitoring:** Detect beaconing traffic to known malicious infrastructure.
* **Endpoint Detection and Response (EDR):** Deploy EDR to detect the malicious process chains originating from browser activity.
* **User Training:** Train users to be skeptical of unsolicited links and to never copy/paste and run commands from untrusted sources.
* **Application Restrictions:** Use application allowlisting tools like AppLocker to prevent unauthorized applications from running, even if triggered by the user.

## Campaign References

1.  **Fake CAPTCHA Campaign (2023):** Delivered Lumma Stealer via malicious websites prompting users to run commands.
2.  **Various Phishing Campaigns:** Constant use of links to credential harvesting pages mimicking Microsoft, Apple, and Amazon.

## Academic References

1.  MITRE ATT&CK Technique T1566.002 - Phishing: Spearphishing Link
2.  Proofpoint: "From Clipboard to Compromise"
3.  CISA: "Avoiding Social Engineering and Phishing Attacks"

This test suite provides defenders with the necessary context to understand and detect the execution chain associated with link-based phishing, a critical technique for modern threat actors seeking to evade traditional email security measures.