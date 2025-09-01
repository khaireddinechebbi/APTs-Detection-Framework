# APTs-Detection-Framework
APTs &amp; Detection Framework

Perfect. We’ll go rule-by-rule (12 total), excluding your already-working **T1047, T1105, T1059.001, T1053.005**. For each: Sigma YAML, preferred query (KQL/EQL/ES|QL), severity, and a quick **manual test** you can run *before* Atomic. I’m aligning to your doc and tightening a few edges where useful.&#x20;

---

# T1573 — Encrypted Channel (suspicious TLS beaconing)

**Sigma (ES|QL focus)**

```yaml
title: Suspicious TLS Client Connections (Non-Browser, Low Egress)
id: 3f0f7f2e-2fb9-43d7-9a20-0f3a7b2d9c88
status: experimental
logsource: { product: windows, category: network_connection }
detection:
  sel:
    EventID: 3
    DestinationPort: [443, 8443, 9443]
  fp:
    Image|endswith:
      - \chrome.exe
      - \firefox.exe
      - \msedge.exe
      - \svchost.exe
      - \lsass.exe
  condition: sel and not fp
fields: [Image, DestinationIp, DestinationPort, Initiated]
falsepositives: [Updaters/telemetry using TLS]
level: medium
tags: [attack.command-and-control, attack.t1573]
```

**ES|QL**

```
from logs-*
| where event.code == 3 and destination.port in (443,8443,9443)
  and not process.executable in (
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\lsass.exe")
```

**Severity:** Medium
**Manual test:** (non-browser, low egress)

```powershell
# run several small HTTPS pulls from PowerShell (not a browser)
1..5 | % { iwr https://www.msftconnecttest.com/connecttest.txt -UseBasicParsing | Out-Null; Start-Sleep -Seconds 5 }
```



---

# T1003.002 — OS Credential Dumping: SAM

**Sigma (KQL focus)**

```yaml
title: Windows Credential Dumping via Reg Save or Shadow Copy (SAM/SYSTEM/SECURITY)
id: 3f8a3a8f-1d6a-4f0a-9dfc-1b9d6a34e0b2
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  regsave:
    Image|endswith: \reg.exe
    CommandLine|contains|all: [save]
    CommandLine|contains: ['hklm\sam','hklm\system','hklm\security']
  copycfg:
    CommandLine|contains: ['\Windows\System32\config\SAM','\Windows\System32\config\SYSTEM','\Windows\System32\config\SECURITY']
  vss:
    CommandLine|contains: HarddiskVolumeShadowCopy
  condition: regsave or copycfg or vss
fields: [CommandLine, ParentImage, User, IntegrityLevel]
falsepositives: [Backup/IR tooling exporting hives]
level: high
tags: [attack.credential-access, attack.t1003.002]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
(
 (process.name:"reg.exe" and process.command_line:("* save *")
   and process.command_line:("*hklm\\sam*" or "*hklm\\system*" or "*hklm\\security*"))
 or process.command_line:("*\\Windows\\System32\\config\\SAM*" or "*\\Windows\\System32\\config\\SYSTEM*"
   or "*\\Windows\\System32\\config\\SECURITY*" or "*HarddiskVolumeShadowCopy*")
)
```

**Severity:** High
**Manual test (Admin):**

```cmd
reg save HKLM\SAM C:\Users\Public\sam.save
reg save HKLM\SYSTEM C:\Users\Public\system.save
vssadmin create shadow /for=c:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Users\Public\SAM.shadow
```

*(If tamper protections block, run an elevated prompt.)*&#x20;

---

# T1003.004 — OS Credential Dumping: LSA Secrets

**Sigma (KQL focus)**

```yaml
title: LSA Secrets Enumeration via Registry/PowerShell
id: 7d0c2e5a-9c1c-40a7-9b7b-6a3b9b9c6f10
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  reg:
    Image|endswith: \reg.exe
    CommandLine|contains|all: [query,'HKLM\SECURITY\Policy\Secrets']
  ps:
    Image|endswith: [\powershell.exe,\pwsh.exe]
    CommandLine|contains:
      - 'HKLM:\\SECURITY\\Policy\\Secrets'
      - 'Registry::HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets'
  condition: reg or ps
fields: [CommandLine, ParentImage, User]
falsepositives: [Rare legit audits]
level: high
tags: [attack.credential-access, attack.t1003.004]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
process.name:("reg.exe" or "powershell.exe" or "pwsh.exe") and
process.command_line:("*HKLM\\SECURITY\\Policy\\Secrets*" or "*HKLM:\\SECURITY\\Policy\\Secrets*" or
"*.Registry::HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets*")
```

**Severity:** High
**Manual test:** Needs **SYSTEM** or special privileges to read SECURITY hive.

```cmd
reg query HKLM\SECURITY\Policy\Secrets
```

If access denied, simulate the *attempt* (still logs) or run a SYSTEM shell (e.g., scheduled task running as SYSTEM) to generate the query.&#x20;

---

# T1003.006 — OS Credential Dumping: DCSync

**Sigma (KQL focus)**

```yaml
title: DCSync / Directory Replication Privilege Abuse
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
status: test
logsource: { product: windows, service: security }
detection:
  sel:
    EventID: 4662
    Properties|contains:
      - Replicating Directory Changes All
      - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
      - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
      - 89e95b76-444d-4c62-991a-0facbeda640c
    AccessMask: '0x100'
  f_winmgr: { SubjectDomainName: 'Window Manager' }
  f_machine: { SubjectUserName|endswith: '$' }
  f_msol: { SubjectUserName|startswith: 'MSOL_' }
  condition: sel and not (f_winmgr or f_machine or f_msol)
fields: [SubjectUserName, ObjectName, Properties]
falsepositives: [Azure AD Connect/legit replication]
level: critical
tags: [attack.credential-access, attack.t1003.006]
```

**KQL**

```
winlog.channel:"Security" and event.code:4662 and
winlog.event_data.Properties:("*Replicating Directory Changes All*" or
"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" or "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" or
"*89e95b76-444d-4c62-991a-0facbeda640c*") and
winlog.event_data.AccessMask:"0x100" and not
winlog.event_data.SubjectUserName:("MSOL_*" or "*$")
```

**Severity:** Critical
**Manual test:** Requires a **Domain Controller** and an account with replication rights.
Example (lab/DC only): run a DCSync action (e.g., Mimikatz/Invoke-DCSync) against a test user to generate 4662. If you don’t have a DC, document “pre-req: DC + replication rights” and keep this rule as *design-validated* only.&#x20;

---

# T1562.001 — Impair Defenses (CLI)

**Sigma (KQL focus)**

```yaml
title: Disable or Weaken Microsoft Defender via CLI
id: 1f2c4d9e-0a8a-4a8b-9b3e-77b9d5e0f6a2
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  sel_img: { Image|endswith: [\powershell.exe, \pwsh.exe, \cmd.exe] }
  sel_cmd:
    CommandLine|contains:
      - Set-MpPreference
      - Add-MpPreference
      - DisableRealtimeMonitoring
      - MAPSReporting
      - SubmitSamplesConsent
      - DisableIOAVProtection
      - TurnOffRealTimeMonitoring
      - DisableBehaviorMonitoring
  condition: sel_img and sel_cmd
fields: [CommandLine, ParentImage, User]
falsepositives: [Admins configuring Defender]
level: high
tags: [attack.defense-evasion, attack.t1562.001]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe") and
process.command_line:("*Set-MpPreference*" or "*Add-MpPreference*" or "*DisableRealtimeMonitoring*" or
"*MAPSReporting*" or "*SubmitSamplesConsent*" or "*DisableIOAVProtection*" or
"*TurnOffRealTimeMonitoring*" or "*DisableBehaviorMonitoring*")
```

**Severity:** High
**Manual test (Admin; may be blocked by Tamper Protection):**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

You still get process creation logging even if Defender blocks the action.&#x20;

---

# T1562.001 — Impair Defenses (Registry; Sysmon EID 13)

**Sigma (KQL focus)**

```yaml
title: Disable or Weaken Microsoft Defender via Registry
id: 4b8e0c7a-2f18-4b9c-8c7d-2f0f6f3e9a66
status: experimental
logsource: { product: windows, category: registry_event }
detection:
  sel:
    EventID: 13
    TargetObject|contains:
      - '\Windows Defender\DisableAntiSpyware'
      - '\Windows Defender\DisableAntiVirus'
      - '\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring'
  condition: sel
fields: [TargetObject, Details, Image]
falsepositives: [Security baselines/MDM]
level: high
tags: [attack.defense-evasion, attack.t1562.001]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:13 and
winlog.event_data.TargetObject:("*\\Windows Defender\\DisableAntiSpyware" or
"*\\Windows Defender\\DisableAntiVirus" or
"*\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring")
```

**Severity:** High
**Manual test (requires Sysmon config for EID 13):**

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

*(In your report, note if Tamper Protection prevents the change.)*&#x20;

---

# T1055 — Process Injection (CreateRemoteThread; Sysmon EID 8)

**Sigma (EQL focus)**

```yaml
title: Process Injection via CreateRemoteThread (Sysmon EID 8)
id: d6d9d2a0-5c3a-4f6f-8a1c-9b1f2e3d4c5a
status: experimental
logsource: { product: windows, category: process_access }
detection:
  sel: { EventID: 8 }
  fp_sys:
    TargetImage|endswith:
      - \svchost.exe
      - \dllhost.exe
  condition: sel and not fp_sys
fields: [SourceImage, TargetImage, StartAddress, CallTrace]
falsepositives: [EDR/AV cross-process activity]
level: critical
tags: [attack.defense-evasion, attack.privilege-escalation, attack.t1055]
```

**EQL**

```
process where event.action == "CreateRemoteThread" and
  not process.Ext.target.image_path :
   ("C:\\Windows\\System32\\svchost.exe","C:\\Windows\\System32\\dllhost.exe")
```

**Severity:** Critical
**Manual test:** Realistically needs an injector (e.g., Atomic T1055 or a benign PoC) to generate **Sysmon EID 8**. There’s no safe built-in Windows command to emit EID-8 without injection. Note this constraint and proceed to Atomic for this one.&#x20;

---

# T1218.005 — Mshta (Proxy Execution)

**Sigma (KQL focus)**

```yaml
title: Mshta Execution of Remote or Scripted Content
id: 2a6b0c12-9f21-4a16-8a6b-1a4f7c3c0a55
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  img: { Image|endswith: \mshta.exe }
  cmd:
    CommandLine|contains: [http, https, 'file://', 'javascript:', 'vbscript:', 'about:blank']
  condition: img and cmd
fields: [CommandLine, ParentImage, User]
falsepositives: [Legacy intranet HTA apps]
level: high
tags: [attack.execution, attack.defense-evasion, attack.t1218.005]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
process.name:"mshta.exe" and process.command_line:
("http*" or "https*" or "file://*" or "*javascript:*" or "*vbscript:*" or "*about:blank*")
```

**Severity:** High
**Manual test:**

```cmd
mshta.exe javascript:alert("test")
```

Or host a tiny `.hta` locally and run `mshta.exe C:\path\test.hta`.&#x20;

---

# T1218.010 — Regsvr32 (Squiblydoo)

**Sigma (KQL focus)**

```yaml
title: Suspicious Regsvr32 Scriptlet Execution (Squiblydoo)
id: 0bcb7d4f-0a3a-4a54-9a7a-77f28b0d7f1c
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  sel_img: { Image|endswith: \regsvr32.exe }
  sel_ind:
    CommandLine|contains: [scrobj.dll, .sct, http, https]
  sel_switch: { CommandLine|contains: [' /s ', ' /u ', ' /i '] }
  condition: sel_img and (sel_ind or sel_switch)
fields: [CommandLine, ParentImage, User]
falsepositives: [Rare admin use of regsvr32]
level: high
tags: [attack.execution, attack.defense-evasion, attack.t1218.010]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
process.name:"regsvr32.exe" and
(process.command_line:("*scrobj.dll*" or "*.sct*" or "http*" or "https*")
 or process.command_line:("* /s *" or "* /u *" or "* /i *"))
```

**Severity:** High
**Manual test (no real payload needed):**

```cmd
regsvr32.exe /s /u /i:https://example.com/file.sct scrobj.dll
```

This still produces the process creation event even if the URL fails.&#x20;

---

# T1218.011 — Rundll32 (Suspicious Parameters)

**Sigma (KQL focus)**

```yaml
title: Suspicious Rundll32 Parameters
id: 5e3a3f2c-2b9c-4f1a-8b6d-9e3a2d5a0f44
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  img: { Image|endswith: \rundll32.exe }
  p1:
    CommandLine|contains:
      - 'javascript:'
      - 'mshtml,RunHTMLApplication'
      - '.cpl,'
      - http
      - https
  p2:
    CommandLine|contains: [DllRegisterServer, ShellExecute, '#1']
  condition: img and (p1 or p2)
fields: [CommandLine, ParentImage, User]
falsepositives: [Legacy admin scripts]
level: high
tags: [attack.execution, attack.defense-evasion, attack.t1218.011]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and
process.name:"rundll32.exe" and
(process.command_line:("*javascript:*" or "*mshtml,RunHTMLApplication*" or "*.cpl,*" or "http*" or "https*")
 or process.command_line:("*DllRegisterServer*" or "*ShellExecute*" or "*#1*"))
```

**Severity:** High
**Manual test (benign):**

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();close();
```

Should log process + params.&#x20;

---

# T1021.002 — Remote Services: SMB/Admin Shares (Security EID 5140)

**Sigma (KQL focus)**

```yaml
title: Lateral Movement via Admin Shares (ADMIN$ / C$)
id: a2f4b6c0-9b3d-4e9a-8f2a-1e0a4b7c9d22
status: experimental
logsource: { product: windows, service: security }
detection:
  sel:
    EventID: 5140
    ShareName|startswith: '\\\\'
    ShareName|contains: ['\ADMIN$','\C$']
  condition: sel
fields: [SubjectUserName, IpAddress, ShareName]
falsepositives: [Routine IT admin/deployment]
level: medium
tags: [attack.lateral-movement, attack.t1021.002]
```

**KQL**

```
(winlog.channel:"Security" and event.code:5140 and winlog.event_data.ShareName:"\\\\*\\ADMIN$")
or
(winlog.channel:"Security" and event.code:5140 and winlog.event_data.ShareName:"\\\\*\\C$")
```

**Severity:** Medium
**Manual test (enable auditing on the *target*):**

* Ensure **Audit Object Access → File Share** is enabled (Success).
* From another host/VM:

```cmd
net use \\TARGET\ADMIN$ /user:TARGET\Administrator
```

You should see 5140 on **TARGET**.&#x20;

---

# T1547.001 — Persistence: Run/RunOnce (Sysmon EID 13)

**Sigma (KQL focus)**

```yaml
title: Run/RunOnce Persistence – Suspicious Value (Sysmon EID 13)
id: e1a3c0b5-c0e9-4c5b-9cd0-bfb2a783b13f
status: experimental
logsource: { product: windows, category: registry_event }
detection:
  sel_key:
    EventID: 13
    TargetObject|contains:
      - \Software\Microsoft\Windows\CurrentVersion\Run\
      - \Software\Microsoft\Windows\CurrentVersion\RunOnce\
      - \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\
      - \Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\
      - \Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\
  sel_bad:
    Details|contains:
      - \AppData\
      - \Temp\
      - \Downloads\
      - '\\\\'
      - \powershell.exe
      - \wscript.exe
      - \cscript.exe
      - \cmd.exe
      - \rundll32.exe
      - .ps1
      - .vbs
  fp_common:
    Details|contains:
      - \Microsoft OneDrive\OneDrive.exe
      - \Microsoft\Teams\Update.exe
      - \NVIDIA Corporation\
      - \Google\Update\
  condition: sel_key and sel_bad and not fp_common
fields: [TargetObject, Details, Image]
falsepositives: [Legit updaters/IT agents; baseline first]
level: high
tags: [attack.persistence, attack.t1547.001]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:13 and
winlog.event_data.TargetObject:(
"*\\CurrentVersion\\Run\\*" or "*\\CurrentVersion\\RunOnce\\*" or "*\\Policies\\Explorer\\Run\\*" or "*\\WOW6432Node\\*\\Run\\*")
and winlog.event_data.Details:(
"*\\AppData\\*" or "*\\Temp\\*" or "*\\Downloads\\*" or "\\\\" or "*\\powershell.exe*" or "*\\wscript.exe*" or
"*\\cscript.exe*" or "*\\cmd.exe*" or "*\\rundll32.exe*" or "*.ps1" or "*.vbs")
and not winlog.event_data.Details:("*OneDrive.exe*" or "*\\Teams\\Update.exe*" or "*NVIDIA Corporation*" or "*\\Google\\Update\\*")
```

**Severity:** High
**Manual test (ensure Sysmon EID 13 enabled):**

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BadRun /t REG_SZ /d "powershell.exe -NoP -W Hidden -c whoami" /f
```

You should see the registry value set event.&#x20;

---

# T1547.001 — Persistence: Startup Folder FileDrop (Sysmon EID 11)

**Sigma (KQL focus)**

```yaml
title: Persistence via Startup Folder File Drop (Sysmon EID 11)
id: 9d7a0a51-9cb6-4b2d-9d3b-1b7f0f0f9d22
status: experimental
logsource: { product: windows, category: file_event }
detection:
  sel:
    EventID: 11
    TargetFilename|contains:
      - \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
      - \ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
  fp_onedrive:
    TargetFilename|endswith: \OneDrive.lnk
  condition: sel and not fp_onedrive
fields: [TargetFilename, Image]
falsepositives: [Legit software placing shortcuts in Startup]
level: high
tags: [attack.persistence, attack.t1547.001]
```

**KQL**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:11 and
winlog.event_data.TargetFilename:("*\\Start Menu\\Programs\\Startup\\*" or "*\\Programs\\StartUp\\*")
and not winlog.event_data.TargetFilename:"*\\OneDrive.lnk"
```

**Severity:** High
**Manual test (ensure Sysmon file create enabled):**

```cmd
copy %SystemRoot%\System32\notepad.exe "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\notepad.exe"
```

You should get EID 11 on file write.&#x20;

---

**That’s the 12.** Your lab blockers were mostly logging prerequisites (Security 5140; Sysmon EID 11/13; DC-only 4662) and test mismatch. If you want, I’ll now generate a one-page **checklist** (auditpol/sysmon config stanzas + exact commands) so you can rip through manual tests in \~20 minutes and then rerun Atomic.


