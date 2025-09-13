| Technique ID |                                Technique name (short) | Tactic (MITRE)                         | Severity (easy/medium/hard/critical) | Quick notes / why severity                                                                                                                                                                                                     |
| ------------ | ----------------------------------------------------: | -------------------------------------- | -----------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| T1003.002    | OS Credential Dumping: Security Account Manager (SAM) | Credential Access                      |                         **critical** | SAM dumps grant direct access to local NTLM hashes — high value for lateral movement. Detection: suspicious `ntdsutil`, `lsass` read attempts, unusual access to `C:\Windows\System32\config\SAM` or `Procdump` to lsass.      |
| T1003.004    |                    OS Credential Dumping: LSA Secrets | Credential Access                      |                         **critical** | LSA secrets reveal cached credentials/keys — high impact. Detection: registry reads of `HKLM\SECURITY\Policy\PolSecretEncryptionKey` and `secrets` access; `mimikatz` patterns.                                                |
| T1047        |              Windows Management Instrumentation (WMI) | Lateral Movement / Execution           |                           **medium** | WMI is a common remote execution/persistence channel. Detection: `wmic.exe` or `wmiprvse` odd schedules, WMI event subscription creation.                                                                                      |
| T1053.005    |                    Scheduled Task/Job: Scheduled Task | Persistence                            |                           **medium** | Scheduled tasks are a common persistence vector. Detection: creation/modification of scheduled tasks (`schtasks`, `Register-ScheduledTask`) from non-admin tools or user profiles.                                             |
| T1055.001    |                      Process Injection: DLL Injection | Defense Evasion / Privilege Escalation |                         **critical** | DLL injection into high-privilege processes is powerful and stealthy. Detection: API call monitoring (CreateRemoteThread/WriteProcessMemory), anomalous DLL loads, mismatched signing.                                         |
| T1059.001    |                       Command Interpreter: PowerShell | Execution                              |                      **easy→medium** | PowerShell is prolific; encoded/obfuscated usage or network streams raise severity. Detection: `-EncodedCommand`, `Invoke-Expression`, `Invoke-WebRequest` from unusual parents.                                               |
| T1105        |                                 Ingress Tool Transfer | Impact / Collection                    |                           **medium** | Downloading tools/payloads into environment (certutil, bitsadmin, iwr). Detection: certutil /bitsadmin /curl/iwr to Temp, unusual outbound downloads, new files in startup/start menu.                                         |
| T1218.005    |                 Mshta (System Binary Proxy Execution) | Defense Evasion / Execution            |                           **medium** | mshta can execute remote HTA and spawn PowerShell; often abused. Detection: mshta executed from cmd/powershell with remote URL or HTA in startup folders.                                                                      |
| T1218.010    |                                     Regsvr32 (SCROBJ) | Defense Evasion / Execution            |                         **critical** | Regsvr32 with `/s /u /i:http... scrobj.dll` allows remote .sct script execution without disk write. Highly abused. Detection: regsvr32 with `/i:` remote URLs, execution from non-standard parents or temp.                    |
| T1218.011    |                                              Rundll32 | Defense Evasion / Execution            |                      **medium→high** | Rundll32 used to invoke arbitrary DLL exports, often from user folders or temp. Detection: rundll32 running a DLL from `%TEMP%`, user downloads, or with odd export names (StartW, krnl).                                      |
| T1573        |                      Encrypted Channel / Encrypted C2 | Command & Control                      |                         **critical** | Custom encrypted channels (SSL/TLS over custom ports or self-auth) hide C2. Detection: uncommon outbound SSL endpoints, non-browser processes making TLS handshakes to odd ports, embedded SSL streams in scripts (SslStream). |

Suggested additional techniques to improve your project (high ROI)

Below are techniques I recommend adding to your detection matrix next — with why, tactic, severity and short detection hints.

### T1059.003 — Windows Command Shell

Tactic: Execution

Severity: easy→medium

Why: many simple payloads and command chains start with cmd.exe /c. Detect parent-child anomalies, cmd.exe launched from Office/IE/HTA or from user temp directories.

### T1546.003 — Event Triggered Execution: WMI Event Subscription

Tactic: Persistence

Severity: hard

Why: stealthy persistence; detection: WMI permanent event consumers/subscriptions creation (__EventFilter, __EventConsumer).

### T1553.002 — Subvert Trust Controls: Code Signing

Tactic: Defense Evasion

Severity: hard

Why: signed malware bypasses controls. Detection: new unsigned binaries in system folders, mismatched signature issuer, or signed by unusual certs.


### T1090.003 — Proxy: Multi-hop Proxy

Tactic: Command and Control / Evasion

Severity: medium

Why: attackers use proxy chains; detection: unusual outbound connections that are internal internal->external patterns; pay attention to internal hops on odd ports.


### T1110.003 / T1110.001 — Password Spraying / Brute Force

Tactic: Credential Access

Severity: medium→high

Why: common; detection: many failed auths across many accounts, repeated connection attempts from one source.

### T1204.001 & T1204.002 — User Execution (malicious link/file)

Tactic: Initial Access / User Interaction

Severity: easy→medium

Why: practice in detecting user-triggered payload execution and delivering training / telemetry correlation.

### T1562.002 — Disable Windows Event Logging

Tactic: Defense Evasion

Severity: critical

Why: attackers often try to reduce visibility; detection: changes to event log service config, suddenly missing events, or clearing of logs.

### T1497. — Virtualization/Sandbox Evasion*

Tactic: Defense Evasion

Severity: medium

Why: detects adversary tests for sandbox/VM; detection: api checks or registry/BIOS strings used to detect VMs.