# APT29 vs. Lazarus Techniques Table

**Severity Legend:**
- 🔴 **Critical** (Immediate threat to core infrastructure)
- 🟠 **High** (Significant impact on security posture)  
- 🟡 **Medium** (Moderate risk, requires attention)
- 🔵 **Low** (Basic techniques, still important)

| Technique ID | Technique Name | Used By | Severity | MITRE Tactics |
|-------------|----------------|---------|----------|---------------|
| T1003.002 | OS Credential Dumping: SAM | APT29 | 🔴 | Credential Access |
| T1003.004 | OS Credential Dumping: LSA Secrets | APT29 | 🔴 | Credential Access |
| T1047 | Windows Management Instrumentation | Both | 🟠 | Execution, Lateral Movement |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Both | 🟠 | Persistence, Execution |
| T1055.001 | Process Injection: DLL Injection | Lazarus | 🟠 | Defense Evasion, Privilege Escalation |
| T1059.001 | Command Interpreter: PowerShell | Both | 🟠 | Execution |
| T1105 | Ingress Tool Transfer | Both | 🟡 | Command and Control |
| T1218.005 | Mshta | Both | 🟠 | Defense Evasion, Execution |
| T1218.010 | Regsvr32 | Lazarus | 🟠 | Defense Evasion, Execution |
| T1218.011 | Rundll32 | Both | 🟠 | Defense Evasion, Execution |
| T1573 | Encrypted Channel | APT29 | 🟠 | Command and Control |
| **T1001.002** | **Data Obfuscation: Steganography** | **APT29** | **🟠** | **Defense Evasion** |
| **T1027.003** | **Obfuscated Files: Steganography** | **APT29** | **🟠** | **Defense Evasion** |
| **T1546.003** | **WMI Event Subscription** | **APT29** | **🔴** | **Persistence, Privilege Escalation** |
| **T1558.003** | **Kerberoasting** | **APT29** | **🔴** | **Credential Access** |
| **T1562.002** | **Disable Windows Event Logging** | **APT29** | **🟠** | **Defense Evasion** |

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