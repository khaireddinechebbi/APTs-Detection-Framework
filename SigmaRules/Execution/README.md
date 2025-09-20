# Execution

## Description:
Execution techniques involve methods adversaries use to run malicious code on local or remote systems. This includes leveraging built-in system utilities, scripting interpreters, and administrative tools to execute commands, deploy payloads, and maintain control over compromised environments while often blending with legitimate system activities.

## Techniques:
### T1047 - Windows Management Instrumentation
#### Description:
Adversaries abuse Windows Management Instrumentation (WMI) to execute commands and perform various malicious activities on local or remote systems. This technique involves using WMIC.exe to create, manipulate, or delete processes, enabling attackers to run code, conduct reconnaissance, and maintain persistence while leveraging a legitimate administrative tool that may bypass security monitoring.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name:"WMIC.exe"
and process.parent.name : ("cmd.exe" or "powershell.exe")
and (
    process.command_line:(* process * and * call * and * create *)
    or process.command_line:(* process * and * where * and  * delete *)
)
```

### T1059.001 - Command and Scripting Interpreter: PowerShell
#### Description:
Adversaries leverage PowerShell's extensive capabilities to execute malicious scripts, download additional payloads, and perform various attack activities while evading detection. This technique involves using encoded commands, obfuscated scripts, and living-off-the-land binaries to conduct reconnaissance, lateral movement, credential access, and data exfiltration while minimizing forensic evidence on target systems.

#### Kibana Query Language Code (KQL):
```
winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code: 1 and (
    (process.name: "powershell.exe"
    and process.parent.name: ("cmd.exe" or "powershell.exe")
    and (
        process.command_line: ((*-noprofile* or *-nop*) and (*New-Object* and *.ServerXmlHttp* and *.Open* and *.Send* and *.ResponseText*))
        or
        process.command_line: (*-e* or *-enc* or *-encodedcommand* or */enc* or */encodedcommand*)
        or
        process.command_line: (*New-PSSession* and *-ComputerName* and *COMPUTERNAME* and *Test-Connection* and *Set-Content* and *TEMP* and *Get-Content* and *Remove-Item -Force*)
        or
        process.command_line: (*$malcmdlets* and *$cmdlets* and (*Add-Persistence* or *Find-AVSignature* or *Get-GPPAutologon* or *Get-GPPPassword* or *Get-HttpStatus* or *Get-Keystrokes* or *Get-SecurityPackages* or *Get-TimedScreenshot* or *Get-VaultCredential* or *Get-VolumeShadowCopy* or *Install-SSP* or *Invoke-CredentialInjection* or *Invoke-DllInjection* or *Invoke-Mimikatz* or *Invoke-NinjaCopy* or *Invoke-Portscan* or *Invoke-ReflectivePEInjection* or *Invoke-ReverseDnsLookup* or *Invoke-Shellcode* or *Invoke-TokenManipulation* or *Invoke-WmiCommand* or *Mount-VolumeShadowCopy* or *New-ElevatedPersistenceOption* or *New-UserPersistenceOption* or *New-VolumeShadowCopy* or *Out-CompressedDll* or *Out-EncodedCommand* or *Out-EncryptedScript* or *Out-Minidump* or *PowerUp* or *PowerView* or *Remove-Comments* or *Remove-VolumeShadowCopy* or *Set-CriticalProcess* or *Set-MasterBootRecord*))
    ))
    or
    (process.name:"reg.exe"
    and process.parent.name: ("cmd.exe" or "powershell.exe")
    and process.command_line:(*add* and */d*)
    and process.parent.command_line:(*Set-Content*))
    or
    (process.name: "powershell.exe"
    and process.parent.name: "WmiPrvSE.exe"
    and process.parent.command_line: *-Embedding* 
    and process.command_line: (*-NoProfile* and (*-E* or *-EA* or *-EncodedArguments*)))
    or
    (process.name: "powershell.exe"
    and process.command_line: (*Remove-Item* and *-Force* and *-ErrorAction Ignore* and (*\\Windows\\Temp\\* or *HKCU\:*)))
)
```
