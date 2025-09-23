# Execution

## Description:
Execution techniques involve methods adversaries use to run malicious code on local or remote systems. This includes leveraging built-in system utilities, scripting interpreters, and administrative tools to execute commands, deploy payloads, and maintain control over compromised environments while often blending with legitimate system activities.

## Techniques:
### T1047 - Windows Management Instrumentation
#### Description:
Adversaries abuse Windows Management Instrumentation (WMI) to execute commands and perform various malicious activities on local or remote systems. This technique involves using WMIC.exe to create, manipulate, or delete processes, enabling attackers to run code, conduct reconnaissance, and maintain persistence while leveraging a legitimate administrative tool that may bypass security monitoring.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:WMIC.exe
AND process.parent.name :(cmd.exe OR powershell.exe)
AND (
    process.command_line:(* process * AND * call * AND * create *)
    OR process.command_line:(* process * AND * where * AND  * delete *)
)
```

### T1059.001 - Command and Scripting Interpreter: PowerShell
#### Description:
Adversaries leverage PowerShell's extensive capabilities to execute malicious scripts, download additional payloads, and perform various attack activities while evading detection. This technique involves using encoded commands, obfuscated scripts, and living-off-the-land binaries to conduct reconnaissance, lateral movement, credential access, and data exfiltration while minimizing forensic evidence on target systems.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND (
    (
        event.code:1
        AND process.name:powershell.exe
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*-noprofile* OR *-nop*)
        AND process.command_line:(*New-Object* AND *.ServerXmlHttp* AND *.Open* AND *.Send* AND *.ResponseText*)
    ) OR (
        event.code:1
        AND process.name:powershell.exe
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(* -e * OR *-enc* OR *-encodedcommand*)
    ) OR (
        event.code:1
        AND process.name:powershell.exe
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*New-PSSession* AND *-ComputerName* AND *COMPUTERNAME* AND *Test-Connection* AND *Set-Content* AND *TEMP* AND *Get-Content* AND *Remove-Item -Force*)
    ) OR (
        event.code:1
        AND process.name:powershell.exe
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*Add-Persistence* OR *Find-AVSignature* OR *Get-GPPAutologon* OR *Get-GPPPassword* OR *Get-HttpStatus* OR *Get-Keystrokes* OR *Get-SecurityPackages* OR *Get-TimedScreenshot* OR *Get-VaultCredential* OR *Get-VolumeShadowCopy* OR *Install-SSP* OR *Invoke-CredentialInjection* OR *Invoke-DllInjection* OR *Invoke-Mimikatz* OR *Invoke-NinjaCopy* OR *Invoke-Portscan* OR *Invoke-ReflectivePEInjection* OR *Invoke-ReverseDnsLookup* OR *Invoke-Shellcode* OR *Invoke-TokenManipulation* OR *Invoke-WmiCommand* OR *Mount-VolumeShadowCopy* OR *New-ElevatedPersistenceOption* OR *New-UserPersistenceOption* OR *New-VolumeShadowCopy* OR *Out-CompressedDll* OR *Out-EncodedCommand* OR *Out-EncryptedScript* OR *Out-Minidump* OR *PowerUp* OR *PowerView* OR *Remove-Comments* OR *Remove-VolumeShadowCopy* OR *Set-CriticalProcess* OR *Set-MasterBootRecord*)
    ) OR (
        event.code:1
        AND process.name:reg.exe
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*add* AND */d*)
        AND process.parent.command_line:*Set-Content*
    ) OR (
        event.code:1
        AND process.name:powershell.exe
        AND process.parent.name:WmiPrvSE.exe
        AND process.parent.command_line: *-Embedding* 
        AND process.command_line:*-NoProfile*
        AND process.command_line:(*-E* OR *-EA* OR *-EncodedArguments*)
    ) OR (
        event.code:1
        AND process.name:powershell.exe
        AND process.command_line:(*Remove-Item* AND *-Force* AND *-ErrorAction Ignore*) 
        AND process.command_line:(*\\Windows\\Temp\\* OR *HKCU\:*)
    )
) 
```
