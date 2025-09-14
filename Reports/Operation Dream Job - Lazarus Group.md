# Operation Dream Job - Lazarus Group Cyber Espionage Campaign

## Overview

**Operation Dream Job** was a sophisticated cyber espionage campaign conducted by the **Lazarus Group** (APT38) between September 2019 and August 2020. This operation primarily targeted defense, aerospace, government, and critical infrastructure sectors across the United States, Israel, Australia, Russia, and India. The campaign employed elaborate social engineering tactics, using fake job offers as bait to compromise high-value targets.

## Campaign Timeline

- **First Observed**: September 2019
- **Last Observed**: August 2020
- **Primary Actor**: Lazarus Group (North Korean state-sponsored)
- **Primary Targets**: Defense contractors, aerospace companies, government agencies

## Attack Methodology

### 1. Reconnaissance & Targeting
- Created fake LinkedIn profiles posing as HR recruiters
- Conducted extensive research on target organizations and key employees
- Identified specific roles and individuals to target with tailored job offers

### 2. Initial Access
- Sent spearphishing messages via LinkedIn with fake job opportunities
- Conducted actual job interviews to build credibility
- Delivered malicious documents disguised as job descriptions

### 3. Execution & Persistence
- Used malicious Office documents with embedded macros
- Implemented multiple persistence mechanisms
- Employed living-off-the-land techniques for stealth

### 4. Lateral Movement & Data Collection
- Explored network environments and discovered files
- Searched for sensitive documents related to security and finances
- Used custom tools for continued access and monitoring

### 5. Exfiltration
- Archived stolen data using RAR compression
- Exfiltrated data through multiple channels including cloud services
- Used encrypted communications to avoid detection

## Key Techniques Used

**Severity Legend:**
- 🔴 **Critical** (Immediate threat to core infrastructure, enables full domain compromise)
- 🟠 **High** (Significant impact on security posture, enables lateral movement/persistence)  
- 🟡 **Medium** (Moderate risk, requires attention but limited scope)
- 🔵 **Low** (Basic techniques, still important for initial access)

**Coverage Status:**
- ✅ **Covered** - Already implemented in your project
- ❌ **Not Covered** - Not yet implemented in your project

| Technique ID | Technique Name | Severity | Covered | Category | Description |
|-------------|----------------|----------|---------|----------|-------------|
| **T1047** | Windows Management Instrumentation | 🟠 **High** | ✅ **Covered** | Execution | Used WMIC to execute remote XSL scripts for payload delivery |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | 🟠 **High** | ✅ **Covered** | Persistence | Created tasks for periodic execution of remote scripts |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | 🟠 **High** | ✅ **Covered** | Execution | Used PowerShell to explore compromised environments |
| **T1105** | Ingress Tool Transfer | 🟡 **Medium** | ✅ **Covered** | C2 | Downloaded multistage malware and tools onto compromised hosts |
| **T1218.010** | System Binary Proxy Execution: Regsvr32 | 🟠 **High** | ✅ **Covered** | Defense Evasion | Used regsvr32 to execute malware components |
| **T1218.011** | System Binary Proxy Execution: Rundll32 | 🟠 **High** | ✅ **Covered** | Defense Evasion | Executed malware through rundll32 with specific parameters |
| **T1573.001** | Encrypted Channel: Symmetric Cryptography | 🟠 **High** | ✅ **Covered** | C2 | Used AES encryption for C2 communications |
| **T1087.002** | Account Discovery: Domain Account | 🟠 **High** | ❌ **Not Covered** | Discovery | Queried Active Directory for employee and admin accounts |
| **T1583.001** | Acquire Infrastructure: Domains | 🟡 **Medium** | ❌ **Not Covered** | Infrastructure | Registered domains identical to compromised companies for BEC |
| **T1583.004** | Acquire Infrastructure: Server | 🟠 **High** | ❌ **Not Covered** | Infrastructure | Acquired servers to host malicious tools and payloads |
| **T1583.006** | Acquire Infrastructure: Web Services | 🟠 **High** | ❌ **Not Covered** | Infrastructure | Used DropBox and OneDrive for file hosting |
| **T1071.001** | Application Layer Protocol: Web Protocols | 🟡 **Medium** | ❌ **Not Covered** | C2 | Used HTTP/HTTPS for C2 communications |
| **T1560.001** | Archive Collected Data: Archive via Utility | 🟡 **Medium** | ❌ **Not Covered** | Exfiltration | Archived victim data into RAR files for compression |
| **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | 🟠 **High** | ❌ **Not Covered** | Persistence | Placed LNK files in startup folder for persistence |
| **T1110** | Brute Force | 🟠 **High** | ❌ **Not Covered** | Credential Access | Performed brute force attacks against admin accounts |
| **T1059.003** | Windows Command Shell | 🟡 **Medium** | ❌ **Not Covered** | Execution | Used cmd for file operations and DLL execution |
| **T1059.005** | Visual Basic | 🟠 **High** | ❌ **Not Covered** | Execution | Used VBA macros in malicious documents |
| **T1584.001** | Compromise Infrastructure: Domains | 🟠 **High** | ❌ **Not Covered** | Infrastructure | Compromised domains in Italy for C2 infrastructure |
| **T1584.004** | Compromise Infrastructure: Server | 🟠 **High** | ❌ **Not Covered** | Infrastructure | Compromised servers to host malicious tools |
| **T1005** | Data from Local System | 🟠 **High** | ❌ **Not Covered** | Collection | Used Trojans and DLLs to exfiltrate data from hosts |
| **T1622** | Debugger Evasion | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Used IsDebuggerPresent to detect debuggers |
| **T1587.001** | Develop Capabilities: Malware | 🟠 **High** | ❌ **Not Covered** | Capability | Developed custom tools (Sumarta, DBLL Dropper, Torisma, DRATzarus) |
| **T1587.002** | Develop Capabilities: Code Signing Certificates | 🟠 **High** | ❌ **Not Covered** | Capability | Digitally signed malware and tools |
| **T1585.001** | Establish Accounts: Social Media Accounts | 🟠 **High** | ❌ **Not Covered** | Reconnaissance | Created fake LinkedIn accounts for targeting |
| **T1585.002** | Establish Accounts: Email Accounts | 🟠 **High** | ❌ **Not Covered** | Reconnaissance | Created fake email accounts for personas and BEC |
| **T1041** | Exfiltration Over C2 Channel | 🟠 **High** | ❌ **Not Covered** | Exfiltration | Exfiltrated data to actor-controlled C2 servers |
| **T1567.002** | Exfiltration to Cloud Storage | 🟠 **High** | ❌ **Not Covered** | Exfiltration | Used custom dbxcli to exfiltrate to Dropbox |
| **T1083** | File and Directory Discovery | 🟡 **Medium** | ❌ **Not Covered** | Discovery | Searched for security and financial documents |
| **T1589** | Gather Victim Identity Information | 🟡 **Medium** | ❌ **Not Covered** | Reconnaissance | Conducted extensive reconnaissance research |
| **T1591** | Gather Victim Org Information | 🟡 **Medium** | ❌ **Not Covered** | Reconnaissance | Gathered organization information for targeting |
| **T1591.004** | Identify Roles | 🟠 **High** | ❌ **Not Covered** | Reconnaissance | Targeted specific individuals with tailored job offers |
| **T1656** | Impersonation | 🟠 **High** | ❌ **Not Covered** | Initial Access | Impersonated HR personnel through LinkedIn |
| **T1070.004** | Indicator Removal: File Deletion | 🟡 **Medium** | ❌ **Not Covered** | Defense Evasion | Removed delivered files from compromised systems |
| **T1534** | Internal Spearphishing | 🟠 **High** | ❌ **Not Covered** | Initial Access | Conducted spearphishing from within compromised orgs |
| **T1036.008** | Masquerading: Masquerade File Type | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Disguised malicious files as JPEG files |
| **T1106** | Native API | 🟠 **High** | ❌ **Not Covered** | Execution | Used Windows API for User-Agent discovery |
| **T1027.002** | Obfuscated Files: Software Packing | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Packed .db files with Themida |
| **T1027.013** | Obfuscated Files: Encrypted/Encoded File | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Encrypted malware with XOR and Base64 |
| **T1588.002** | Obtain Capabilities: Tool | 🟡 **Medium** | ❌ **Not Covered** | Capability | Obtained tools (Wake-On-Lan, Responder, ChromePass) |
| **T1588.003** | Obtain Capabilities: Code Signing Certificates | 🟠 **High** | ❌ **Not Covered** | Capability | Used Sectigo RSA code signing certificates |
| **T1566.001** | Phishing: Spearphishing Attachment | 🟠 **High** | ❌ **Not Covered** | Initial Access | Emails with malicious attachments |
| **T1566.002** | Phishing: Spearphishing Link | 🟠 **High** | ❌ **Not Covered** | Initial Access | Malicious OneDrive links via email |
| **T1566.003** | Phishing: Spearphishing via Service | 🟠 **High** | ❌ **Not Covered** | Initial Access | LinkedIn messages about fictitious jobs |
| **T1593.001** | Search Open Websites: Social Media | 🟡 **Medium** | ❌ **Not Covered** | Reconnaissance | Used LinkedIn to identify targets |
| **T1505.004** | Server Software Component: IIS Components | 🟠 **High** | ❌ **Not Covered** | Persistence | Targeted IIS servers to install C2 components |
| **T1608.001** | Stage Capabilities: Upload Malware | 🟠 **High** | ❌ **Not Covered** | Capability | Used compromised servers to host malware |
| **T1608.002** | Stage Capabilities: Upload Tool | 🟠 **High** | ❌ **Not Covered** | Capability | Used multiple servers to host tools |
| **T1553.002** | Subvert Trust Controls: Code Signing | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Digitally signed malware to evade detection |
| **T1614.001** | System Location Discovery: System Language Discovery | 🟡 **Medium** | ❌ **Not Covered** | Discovery | Avoided Korean, Japanese, Chinese systems |
| **T1221** | Template Injection | 🟠 **High** | ❌ **Not Covered** | Execution | Used DOCX files to retrieve malicious templates |
| **T1204.001** | User Execution: Malicious Link | 🟠 **High** | ❌ **Not Covered** | Execution | Lured users to execute malicious links |
| **T1204.002** | User Execution: Malicious File | 🟠 **High** | ❌ **Not Covered** | Execution | Lured victims to execute malicious documents |
| **T1497.001** | Virtualization/Sandbox Evasion: System Checks | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Conducted system checks to detect sandboxes |
| **T1497.003** | Virtualization/Sandbox Evasion: Time Based Evasion | 🟠 **High** | ❌ **Not Covered** | Defense Evasion | Used timing checks to detect virtualization |
| **T1220** | XSL Script Processing | 🟠 **High** | ❌ **Not Covered** | Execution | Used remote XSL scripts to download payloads |

## Coverage Summary

**✅ Covered Techniques (8):** You have good coverage of core execution and defense evasion techniques used by Lazarus Group.

**❌ Not Covered Techniques (45):** Significant opportunity to expand your project with additional techniques, particularly in:
- Reconnaissance and social engineering tactics
- Advanced persistence mechanisms  
- Custom malware development and tooling
- Cloud-based exfiltration methods
- Infrastructure manipulation

## Recommended Next Additions

Based on Operation Dream Job's tradecraft, consider adding these high-impact techniques:

1. **T1566.003 - Spearphishing via Service** (🟠 High) - LinkedIn-based initial access
2. **T1585.001 - Social Media Accounts** (🟠 High) - Fake profile creation
3. **T1567.002 - Cloud Storage Exfiltration** (🟠 High) - Dropbox exfiltration
4. **T1027.013 - Encrypted Files** (🟠 High) - XOR and Base64 obfuscation
5. **T1547.001 - Registry Run Keys** (🟠 High) - Startup folder persistence
