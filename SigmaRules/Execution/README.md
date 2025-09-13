# Execution

## Description:

Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.

## Techniques:
### T1047 - Windows Management Instrumentation
#### Description:

Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems. WMI is an administration feature that provides a uniform environment to access Windows system components.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name:"WMIC.exe"
and (
    process.command_line:(* process * and * call * and * create *)
    or process.command_line:(* process * and * where * and  * delete *)
)
and process.parent.name : ("cmd.exe" or "powershell.exe")
```

### T1059.001 - Command and Scripting Interpreter: PowerShell
#### Description:

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

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
    and process.command_line: (*Remove-Item* *-Force* and *-ErrorAction Ignore* and (*\\Windows\\Temp\\* or *HKCU\:*)))
)
```
