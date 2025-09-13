# APT29 vs. Lazarus Techniques Table

**Severity Legend:**
- 🔴 **Critical** (Immediate threat to core infrastructure, enables full domain compromise)
- 🟠 **High** (Significant impact on security posture, enables lateral movement/persistence)  
- 🟡 **Medium** (Moderate risk, requires attention but limited scope)
- 🔵 **Low** (Basic techniques, still important for initial access)

| Technique ID | Technique Name | Used By | Severity | MITRE Tactics | Quick Notes / Why Severity |
|-------------|----------------|---------|----------|---------------|----------------------------|
| **T1003.002** | OS Credential Dumping: SAM | APT29 | 🔴 | Credential Access | **Critical:** Extracts local password hashes enabling pass-the-hash attacks and lateral movement |
| **T1003.004** | OS Credential Dumping: LSA Secrets | APT29 | 🔴 | Credential Access | **Critical:** Reveals service account passwords, cached credentials, and authentication secrets |
| **T1047** | Windows Management Instrumentation | Both | 🟠 | Execution, Lateral Movement | **High:** Enables remote code execution and lateral movement using built-in Windows utilities |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Both | 🟠 | Persistence, Execution | **High:** Provides reliable persistence mechanism and remote code execution capabilities |
| **T1055.001** | Process Injection: DLL Injection | Lazarus | 🟠 | Defense Evasion, Privilege Escalation | **High:** Evades detection by executing code in legitimate process memory space |
| **T1059.001** | Command Interpreter: PowerShell | Both | 🟠 | Execution | **High:** Powerful scripting enables complex attacks while evading traditional detection |
| **T1105** | Ingress Tool Transfer | Both | 🟡 | Command and Control | **Medium:** Essential for tool delivery but requires prior access to be effective |
| **T1218.005** | Mshta | Both | 🟠 | Defense Evasion, Execution | **High:** Executes scripts through trusted binary, bypassing application control solutions |
| **T1218.010** | Regsvr32 | Lazarus | 🟠 | Defense Evasion, Execution | **High:** Loads and executes code through legitimate COM component registration |
| **T1218.011** | Rundll32 | Both | 🟠 | Defense Evasion, Execution | **High:** Executes payloads through trusted Windows binary, supports various file types |
| **T1573** | Encrypted Channel | APT29 | 🟠 | Command and Control | **High:** Evades network monitoring by concealing C2 traffic in encrypted communications |
| **T1001.002** | Data Obfuscation: Steganography | APT29 | 🟠 | Defense Evasion | **High:** Hides data in plain sight, extremely difficult to detect without specialized tools |
| **T1027.003** | Obfuscated Files: Steganography | APT29 | 🟠 | Defense Evasion | **High:** Conceals malicious code within legitimate files, bypassing content inspection |
| **T1546.003** | WMI Event Subscription | APT29 | 🔴 | Persistence, Privilege Escalation | **Critical:** Stealthy persistence mechanism that's difficult to detect and remove |
| **T1558.003** | Kerberoasting | APT29 | 🔴 | Credential Access | **Critical:** Extracts service account credentials enabling golden ticket attacks and domain dominance |
| **T1562.002** | Disable Windows Event Logging | APT29 | 🟠 | Defense Evasion | **High:** Blinds defenders by eliminating forensic evidence and detection capabilities |
| **T1021.006** | Remote Services: Windows Remote Management | APT29 | 🟠 | Lateral Movement | **High:** Enables remote system management and code execution using built-in protocols |
| **T1078.002** | Domain Accounts | APT29 | 🔴 | Persistence, Privilege Escalation | **Critical:** Compromised domain accounts provide extensive access and persistence capabilities |
| **T1482** | Domain Trust Discovery | APT29 | 🟠 | Discovery | **High:** Maps trust relationships enabling cross-domain attacks and privilege escalation |
| **T1190** | Exploit Public-Facing Application | APT29 | 🔴 | Initial Access | **Critical:** Provides initial foothold into protected networks through vulnerable services |
| **T1204.002** | User Execution: Malicious File | Both | 🟠 | Execution | **High:** Relies on user interaction but highly effective for initial execution |
| **T1566.001** | Phishing: Spearphishing Attachment | Both | 🟠 | Initial Access | **High:** Effective social engineering that bypasses technical controls through user manipulation |
| **T1070.004** | File Deletion | Both | 🟡 | Defense Evasion | **Medium:** Removes evidence but leaves traces in file system metadata and logs |
| **T1082** | System Information Discovery | Both | 🟡 | Discovery | **Medium:** Provides reconnaissance data but doesn't directly enable compromise |
| **T1016.001** | System Network Configuration Discovery | Both | 🟡 | Discovery | **Medium:** Network mapping helps attackers but requires follow-on techniques for impact |

## Recommended Techniques for Project Expansion

Based on your current work and the threat landscape, here are the **top 5 techniques** I recommend adding to your project:

### 1. 🔴 **T1546.003 - WMI Event Subscription** (APT29)
**Why:** This is a sophisticated persistence mechanism that APT29 heavily uses. It would complement your WMI (T1047) work perfectly.
**Use Case:** Advanced persistence that's hard to detect
**MITRE Tactics:** Persistence, Privilege Escalation

### 2. 🔴 **T1558.003 - Kerberoasting** (APT29) 
**Why:** Critical credential access technique that's fundamental to APT29's lateral movement
**Use Case:** Domain privilege escalation and credential theft
**MITRE Tactics:** Credential Access

### 3. 🟠 **T1001.002/T1027.003 - Steganography** (APT29)
**Why:** Advanced data obfuscation that would enhance your defense evasion coverage
**Use Case:** Data exfiltration and payload hiding
**MITRE Tactics:** Defense Evasion

### 4. 🟠 **T1562.002 - Disable Windows Event Logging** (APT29)
**Why:** Directly impacts detection capabilities - crucial for understanding attacker tradecraft
**Use Case:** Defense evasion and operational security
**MITRE Tactics:** Defense Evasion

## Project Enhancement Strategy

### Phase 1: Immediate Adds (1-2 weeks)
- **T1546.003 - WMI Event Subscription** - Builds on your existing WMI expertise
- **T1562.002 - Disable Event Logging** - Practical defense evasion technique

### Phase 2: Advanced Techniques (2-3 weeks)  
- **T1558.003 - Kerberoasting** - Critical credential access
- **T1001.002 - Steganography** - Advanced obfuscation

### Phase 3: Completion (1 week)
- **T1055.001 - Process Injection** - Finalize Lazarus coverage

## Why These Techniques?

1. **Strategic Coverage:** Covers both APT29 and Lazarus core techniques
2. **Progressive Difficulty:** Builds from your current knowledge
3. **High Impact:** Addresses critical attack vectors
4. **Detection Value:** Provides significant defensive insights
5. **Career Relevance:** These are in-demand skills for threat hunting.