# TTP Scope – APT Detection Project

## Selected APT Groups
- **APT29 (Cozy Bear)** — stealthy intrusions, PowerShell-heavy, credential access, lateral movement.
- **Lazarus Group** — persistence via registry/run keys & tasks, WMI/SMB lateral movement, tool staging.

## Detection Scope & Data Sources
- **Windows endpoint telemetry** via **Sysmon** (EIDs 1/3/10/11/13) shipped by **Winlogbeat** to **Elastic**.
- Rule languages by use-case: **KQL** (single event), **EQL** (sequences), **ES|QL** (thresholds/aggregations).
- Sigma is the **source of truth**; we compile/adapt to Elastic query languages.

## Techniques in Scope (with rule language & simulation plan)
| Technique ID | Name | Primary Log Source(s) | Rule Lang | Sim / Trigger | Why in Scope | Mapping to Groups |
|---|---|---|---|---|---|---|
| **T1059.001** | PowerShell – EncodedCommand | Sysmon **EID 1** (ProcessCreate) | **KQL** | `powershell.exe -enc <b64>` | Common obfuscated exec path | APT29, Lazarus |
| **T1003.001** | OS Credential Dumping – LSASS | Sysmon **EID 1** (procdump/rundll32), **EID 10** (ProcessAccess→lsass) | **EQL** (sequence) | `procdump -ma lsass.exe` or `rundll32 comsvcs.dll, MiniDump` | Priv-esc & credential theft | APT29, Lazarus |
| **T1053.005** | Scheduled Task Creation | Sysmon **EID 1** | **KQL** | `schtasks /create ...` | Persistence + tasking | Lazarus, APT29 |
| **T1547.001** | Registry Run/RunOnce Persistence | Sysmon **EID 13** (Registry), fallback **EID 1** (`reg.exe`) | **KQL** | `reg add ...\Run ...` | Lightweight persistence | Lazarus, APT29 |
| **T1047** | WMI Execution | Sysmon **EID 1** (wmic.exe), optional **EID 3** (net connect) | **KQL** (single) / **EQL** (chain) | `wmic process call create "cmd /c calc"` | Remote/local exec & lateral move | Lazarus, APT29 |
| **T1105** | Ingress Tool Transfer (certutil) | Sysmon **EID 1** | **KQL** | `certutil -urlcache -f http://...` | Tool staging/download | APT29, Lazarus |
| **T1021.002** | SMB/PSExec Lateral Movement | Windows **7045** (Service install), Sysmon **EID 1** (psexesvc.exe), **EID 11** (FileCreate) | **EQL** (sequence) | PsExec to target host | Classic admin-share lateral move | Lazarus, APT29 |
| **T1055** (stretch) | Process Injection (generic) | Sysmon **EID 7/8/10/11** (if enabled) | **KQL/EQL** (depends) | Atomic or test harness | Stealthier in-memory exec | APT29, Lazarus |

### Status (today)
- ✅ **T1059.001 PowerShell EncodedCommand** — rule live & validated.
- 🔜 **T1003.001 LSASS**, **T1053.005 Tasks**, **T1547.001 Run Keys**, **T1047 WMI**, **T1105 certutil**, **T1021.002 PsExec**.

## Out of Scope (for this iteration)
- T1027 Obfuscated/Compressed Files & Info (content-level; higher FP)
- T1562 Impair Defenses (requires broader policy/EDR signals)

## Notes
- If Sysmon **EID 10/13** aren’t present, we’ll update the Sysmon config and redeploy.
- Each Sigma rule lives under `detections/sigma/windows/...` and is compiled to EQL/ES|QL or hand-translated to KQL for Elastic.
