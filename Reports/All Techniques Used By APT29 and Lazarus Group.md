# APT29 vs Lazarus Group Techniques Comparison

**Severity Legend:**
- 🔴 **Critical** (Immediate threat to core infrastructure, enables full domain compromise)
- 🟠 **High** (Significant impact on security posture, enables lateral movement/persistence)  
- 🟡 **Medium** (Moderate risk, requires attention but limited scope)
- 🔵 **Low** (Basic techniques, still important for initial access)

**Coverage Status:**
- ✅ **Covered** - Already implemented in your project
- ❌ **Not Covered** - Not yet implemented in your project

| Technique ID | Technique Name | Used By | Severity | Covered | Why Severity |
|-------------|----------------|---------|----------|---------|--------------|
| **T1003.002** | OS Credential Dumping: SAM | APT29 | 🔴 Critical | ✅ Covered | Extracts local password hashes enabling pass-the-hash attacks |
| **T1003.004** | OS Credential Dumping: LSA Secrets | APT29 | 🔴 Critical | ✅ Covered | Reveals service account passwords and authentication secrets |
| **T1003.006** | OS Credential Dumping: DCSync | APT29 | 🔴 Critical | ❌ Not Covered | Enables full Active Directory domain replication and compromise |
| **T1047** | Windows Management Instrumentation | Both | 🟠 High | ✅ Covered | Enables remote code execution using built-in Windows utilities |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Both | 🟠 High | ✅ Covered | Provides reliable persistence and remote execution capabilities |
| **T1055.001** | Process Injection: DLL Injection | Lazarus | 🟠 High | ✅ Covered | Evades detection by executing code in legitimate process memory |
| **T1059.001** | Command Interpreter: PowerShell | Both | 🟠 High | ✅ Covered | Powerful scripting enables complex attacks while evading detection |
| **T1105** | Ingress Tool Transfer | Both | 🟡 Medium | ✅ Covered | Essential for tool delivery but requires prior access |
| **T1218.005** | Mshta | Both | 🟠 High | ✅ Covered | Executes scripts through trusted binary, bypassing application control |
| **T1218.010** | Regsvr32 | Lazarus | 🟠 High | ✅ Covered | Loads and executes code through legitimate COM component registration |
| **T1218.011** | Rundll32 | Both | 🟠 High | ✅ Covered | Executes payloads through trusted Windows binary with various file types |
| **T1573** | Encrypted Channel | APT29 | 🟠 High | ✅ Covered | Evades network monitoring by concealing C2 traffic in encryption |
| **T1001.002** | Data Obfuscation: Steganography | APT29 | 🟠 High | ❌ Not Covered | Extremely difficult to detect without specialized analysis tools |
| **T1195.002** | Supply Chain Compromise | APT29 | 🔴 Critical | ❌ Not Covered | Affects thousands of organizations through trusted software updates |
| **T1558.003** | Kerberoasting | APT29 | 🔴 Critical | ❌ Not Covered | Extracts service account credentials enabling golden ticket attacks |
| **T1484.002** | Domain Trust Modification | APT29 | 🔴 Critical | ❌ Not Covered | Allows complete domain federation takeover and identity manipulation |
| **T1606.002** | Forge SAML Tokens | APT29 | 🔴 Critical | ❌ Not Covered | Enables complete cloud identity compromise and MFA bypass |
| **T1068** | Exploitation for Privilege Escalation | APT29 | 🟠 High | ❌ Not Covered | Leverages vulnerabilities for elevated access and persistence |
| **T1078.002** | Domain Accounts | APT29 | 🔴 Critical | ❌ Not Covered | Compromised domain accounts provide extensive access capabilities |
| **T1078.004** | Cloud Accounts | APT29 | 🔴 Critical | ❌ Not Covered | Cloud admin access enables widespread resource compromise |
| **T1090.004** | Proxy: Domain Fronting | APT29 | 🟠 High | ❌ Not Covered | Evades network blocking by hiding behind legitimate domains |
| **T1098.003** | Additional Cloud Roles | APT29 | 🔴 Critical | ❌ Not Covered | Grants administrative privileges enabling complete cloud control |
| **T1114.002** | Email Collection: Remote Email Collection | APT29 | 🟠 High | ❌ Not Covered | Targets sensitive executive communications and intelligence |
| **T1482** | Domain Trust Discovery | APT29 | 🟠 High | ❌ Not Covered | Maps trust relationships enabling cross-domain attacks |
| **T1528** | Steal Application Access Token | APT29 | 🟠 High | ❌ Not Covered | Compromises cloud application access and permissions |
| **T1539** | Steal Web Session Cookie | APT29 | 🟠 High | ❌ Not Covered | Bypasses authentication and MFA through session hijacking |
| **T1546.003** | WMI Event Subscription | APT29 | 🟠 High | ❌ Not Covered | Advanced persistence mechanism difficult to detect and remove |
| **T1550.003** | Pass the Ticket | APT29 | 🔴 Critical | ❌ Not Covered | Enables lateral movement using stolen Kerberos tickets |
| **T1552.004** | Unsecured Credentials: Private Keys | APT29 | 🔴 Critical | ❌ Not Covered | Compromises PKI infrastructure and digital certificates |
| **T1555.003** | Credentials from Web Browsers | APT29 | 🟠 High | ❌ Not Covered | Extracts saved passwords and authentication data |
| **T1562.002** | Disable Windows Event Logging | APT29 | 🟠 High | ❌ Not Covered | Blinds defenders by eliminating forensic evidence |
| **T1595.002** | Vulnerability Scanning | APT29 | 🟡 Medium | ❌ Not Covered | Identifies weaknesses for exploitation and initial access |
| **T1606.001** | Forge Web Cookies | APT29 | 🟠 High | ❌ Not Covered | Bypasses authentication through cookie manipulation |
| **T1649** | Steal or Forge Authentication Certificates | APT29 | 🔴 Critical | ❌ Not Covered | Compromises PKI infrastructure and digital trust |
| **T1651** | Cloud Administration Command | APT29 | 🔴 Critical | ❌ Not Covered | Executes privileged commands in cloud environments |
| **T1665** | Hide Infrastructure | APT29 | 🟠 High | ❌ Not Covered | Conceals C2 infrastructure from detection and blocking |
| **T1001.003** | Protocol Impersonation | Lazarus | 🟠 High | ❌ Not Covered | Evades detection by mimicking legitimate network protocols |
| **T1008** | Fallback Channels | Lazarus | 🟡 Medium | ❌ Not Covered | Maintains C2 connectivity through alternative methods |
| **T1010** | Application Window Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Identifies running applications for targeting and evasion |
| **T1012** | Query Registry | Lazarus | 🟡 Medium | ❌ Not Covered | Gathers system configuration and persistence information |
| **T1021.004** | SSH | Lazarus | 🟠 High | ❌ Not Covered | Provides secure remote access and lateral movement |
| **T1027.007** | Dynamic API Resolution | Lazarus | 🟠 High | ❌ Not Covered | Evades static analysis by resolving APIs at runtime |
| **T1027.009** | Embedded Payloads | Lazarus | 🟠 High | ❌ Not Covered | Hides malicious code within legitimate files and documents |
| **T1027.013** | Encrypted/Encoded File | Lazarus | 🟠 High | ❌ Not Covered | Obscures malware from detection and analysis |
| **T1033** | System Owner/User Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Identifies current users for targeting and privilege escalation |
| **T1036.003** | Rename Legitimate Utilities | Lazarus | 🟠 High | ❌ Not Covered | Evades detection by disguising malicious tools as legitimate |
| **T1036.008** | Masquerade File Type | Lazarus | 🟠 High | ❌ Not Covered | Bypasses file type restrictions and detection |
| **T1041** | Exfiltration Over C2 Channel | Lazarus | 🟠 High | ❌ Not Covered | Uses existing C2 channels for data theft |
| **T1046** | Network Service Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Identifies available services for exploitation |
| **T1048.003** | Exfiltration Over Unencrypted Protocol | Lazarus | 🟡 Medium | ❌ Not Covered | Simpler exfiltration but more easily detectable |
| **T1049** | System Network Connections Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Maps network connections and relationships |
| **T1056.001** | Keylogging | Lazarus | 🟠 High | ❌ Not Covered | Captures user input including credentials and sensitive data |
| **T1070** | Indicator Removal | Lazarus | 🟠 High | ❌ Not Covered | Eliminates forensic evidence and detection artifacts |
| **T1070.003** | Clear Command History | Lazarus | 🟡 Medium | ❌ Not Covered | Removes evidence of executed commands and activities |
| **T1074.001** | Local Data Staging | Lazarus | 🟡 Medium | ❌ Not Covered | Prepares data for exfiltration from local systems |
| **T1104** | Multi-Stage Channels | Lazarus | 🟠 High | ❌ Not Covered | Uses complex C2 chains for evasion and resilience |
| **T1106** | Native API | Lazarus | 🟠 High | ❌ Not Covered | Low-level system access bypassing higher-level security |
| **T1124** | System Time Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Gathers time information for operational planning |
| **T1132.001** | Standard Encoding | Lazarus | 🟡 Medium | ❌ Not Covered | Basic obfuscation for data and communications |
| **T1134.002** | Create Process with Token | Lazarus | 🟠 High | ❌ Not Covered | Executes processes with stolen tokens for privilege escalation |
| **T1189** | Drive-by Compromise | Lazarus | 🟠 High | ❌ Not Covered | Compromises systems through web browser vulnerabilities |
| **T1202** | Indirect Command Execution | Lazarus | 🟠 High | ❌ Not Covered | Evades detection by executing commands through intermediaries |
| **T1220** | XSL Script Processing | Lazarus | 🟠 High | ❌ Not Covered | Uses XSL scripts for execution and payload retrieval |
| **T1221** | Template Injection | Lazarus | 🟠 High | ❌ Not Covered | Injects malicious code through document templates |
| **T1485** | Data Destruction | Lazarus | 🔴 Critical | ❌ Not Covered | Destroys data and systems for impact and disruption |
| **T1489** | Service Stop | Lazarus | 🟠 High | ❌ Not Covered | Disables critical services for disruption and evasion |
| **T1491.001** | Internal Defacement | Lazarus | 🟡 Medium | ❌ Not Covered | Modifies internal content for psychological impact |
| **T1497.001** | System Checks | Lazarus | 🟠 High | ❌ Not Covered | Detects analysis environments and virtualized systems |
| **T1497.003** | Time Based Evasion | Lazarus | 🟠 High | ❌ Not Covered | Avoids detection through timing-based sandbox evasion |
| **T1505.004** | IIS Components | Lazarus | 🟠 High | ❌ Not Covered | Compromises web servers for persistence and C2 |
| **T1529** | System Shutdown/Reboot | Lazarus | 🟡 Medium | ❌ Not Covered | Disrupts operations and causes system downtime |
| **T1534** | Internal Spearphishing | Lazarus | 🟠 High | ❌ Not Covered | Targets internal users from compromised accounts |
| **T1542.003** | Bootkit | Lazarus | 🔴 Critical | ❌ Not Covered | Persistent low-level access difficult to detect and remove |
| **T1543.003** | Windows Service | Lazarus | 🟠 High | ❌ Not Covered | Reliable persistence through service installation |
| **T1547.009** | Shortcut Modification | Lazarus | 🟠 High | ❌ Not Covered | Persistence through manipulated shortcut files |
| **T1557.001** | LLMNR/NBT-NS Poisoning | Lazarus | 🟠 High | ❌ Not Covered | Intercepts network traffic for credential capture |
| **T1560.002** | Archive via Library | Lazarus | 🟡 Medium | ❌ Not Covered | Uses programming libraries for data compression |
| **T1560.003** | Archive via Custom Method | Lazarus | 🟠 High | ❌ Not Covered | Custom compression methods avoiding detection |
| **T1561.001** | Disk Content Wipe | Lazarus | 🔴 Critical | ❌ Not Covered | Destroys data making recovery impossible |
| **T1561.002** | Disk Structure Wipe | Lazarus | 🔴 Critical | ❌ Not Covered | Destroys disk structures causing complete data loss |
| **T1564.001** | Hidden Files and Directories | Lazarus | 🟠 High | ❌ Not Covered | Conceals malicious artifacts from discovery |
| **T1567.002** | Exfiltration to Cloud Storage | Lazarus | 🟠 High | ❌ Not Covered | Uses cloud services for data exfiltration and storage |
| **T1571** | Non-Standard Port | Lazarus | 🟡 Medium | ❌ Not Covered | Uses unusual ports to evade standard monitoring |
| **T1573.001** | Symmetric Cryptography | Lazarus | 🟠 High | ❌ Not Covered | Encrypts communications using symmetric algorithms |
| **T1574.001** | DLL Hijacking | Lazarus | 🟠 High | ❌ Not Covered | Executes code through DLL search order hijacking |
| **T1574.013** | KernelCallbackTable | Lazarus | 🟠 High | ❌ Not Covered | Advanced persistence through kernel callback manipulation |
| **T1583.004** | Acquire Infrastructure: Server | Lazarus | 🟠 High | ❌ Not Covered | Obtains servers for C2 and malware hosting |
| **T1585.002** | Establish Email Accounts | Lazarus | 🟠 High | ❌ Not Covered | Creates fake email accounts for social engineering |
| **T1587.002** | Code Signing Certificates | Lazarus | 🟠 High | ❌ Not Covered | Signs malware to evade detection and trust validation |
| **T1588.003** | Obtain Code Signing Certificates | Lazarus | 🟠 High | ❌ Not Covered | Acquires certificates for malware signing |
| **T1588.004** | Obtain Digital Certificates | Lazarus | 🟠 High | ❌ Not Covered | Gets digital certificates for various malicious purposes |
| **T1589.002** | Gather Email Addresses | Lazarus | 🟡 Medium | ❌ Not Covered | Collects target email addresses for phishing campaigns |
| **T1591** | Gather Victim Org Information | Lazarus | 🟡 Medium | ❌ Not Covered | Researches target organizations for social engineering |
| **T1591.004** | Identify Roles | Lazarus | 🟠 High | ❌ Not Covered | Targets specific organizational roles and responsibilities |
| **T1593.001** | Search Social Media | Lazarus | 🟡 Medium | ❌ Not Covered | Uses social media for target research and reconnaissance |
| **T1608.001** | Upload Malware | Lazarus | 🟠 High | ❌ Not Covered | Stages malware on infrastructure for distribution |
| **T1608.002** | Upload Tool | Lazarus | 🟠 High | ❌ Not Covered | Places tools on infrastructure for operations |
| **T1614.001** | System Language Discovery | Lazarus | 🟡 Medium | ❌ Not Covered | Avoids detection by skipping certain language systems |
| **T1620** | Reflective Code Loading | Lazarus | 🟠 High | ❌ Not Covered | Loads code without touching disk, evading file scanning |
| **T1622** | Debugger Evasion | Lazarus | 🟠 High | ❌ Not Covered | Detects and avoids debuggers and analysis environments |
| **T1656** | Impersonation | Lazarus | 🟠 High | ❌ Not Covered | Pretends to be legitimate entities for social engineering |

## Coverage Summary

**✅ Covered Techniques (12):** You have good coverage of core execution and defense evasion techniques used by both groups.

**❌ Not Covered Techniques (118):** Extensive opportunity to expand your project with additional techniques, particularly:
- APT29's advanced cloud and identity attacks (SAML, DCSync, Cloud roles)
- Lazarus Group's destructive and evasive techniques
- Both groups' reconnaissance and persistence methods
- Supply chain and software compromise techniques.