KQL code

T1218.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and process.name:"mshta.exe"
    and process.parent.name: ("powershell.exe" or "cmd.exe")
    and process.command_line: (((*vbscript* or *VBScript*) and *Execute* and *Wscript.Shell* and *powershell*) or (*\\Microsoft\\Windows\\Start* and *Menu\\Programs\\Startup* and *.hta*))

T1218.010:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and process.name:"regsvr32.exe"
    and process.parent.name: ("cmd.exe" or "powershell.exe")
    and (
        process.command_line: */s*
        and (
            process.command_line: (*/i* and *.dll*)
            or process.parent.command_line: ((* IF * and * ELSE *) or *%temp%*)
        )
    )

T1218.011:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and process.name: "rundll32.exe"
    and (
        process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: (
            (*.dll* and *,#*)
            or not (*.dll* or *.cpl*)
            or (*shell32.dll,Control_RunDLL* and not *.cpl*)
        )
        or process.parent.name: "rundll32.exe"
    )

T1047:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and process.name:"WMIC.exe"
    and (
        process.command_line:(* process * and * call * and * create *)
        or process.command_line:(* process * and * where * and  * delete *)
    )
    and process.parent.name : ("cmd.exe" or "powershell.exe")

T1059.001:
    winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code: 1 and (
        (process.name: "powershell.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and (
            (process.args: ("-noprofile" or "-nop")
            and process.command_line: (*New-Object* and *.ServerXmlHttp* and *.Open* and *.Send* and *.ResponseText*))
            or
            (process.args: ("-e" or "-enc" or "-encodedcommand" or "/enc" or "/encodedcommand"))
            or
            (process.args: (*New-PSSession* and *-ComputerName*)
            and process.command_line:(*COMPUTERNAME* and *Test-Connection* and *Set-Content* and *TEMP* and *Get-Content* and *Remove-Item -Force*))
            or
            (process.args: (*$malcmdlets* and *$cmdlets*)
            and process.command_line:(*Add-Persistence* or *Find-AVSignature* or *Get-GPPAutologon* or *Get-GPPPassword* or *Get-HttpStatus* or *Get-Keystrokes* or *Get-SecurityPackages* or *Get-TimedScreenshot* or *Get-VaultCredential* or *Get-VolumeShadowCopy* or *Install-SSP* or *Invoke-CredentialInjection* or *Invoke-DllInjection* or *Invoke-Mimikatz* or *Invoke-NinjaCopy* or *Invoke-Portscan* or *Invoke-ReflectivePEInjection* or *Invoke-ReverseDnsLookup* or *Invoke-Shellcode* or *Invoke-TokenManipulation* or *Invoke-WmiCommand* or *Mount-VolumeShadowCopy* or *New-ElevatedPersistenceOption* or *New-UserPersistenceOption* or *New-VolumeShadowCopy* or *Out-CompressedDll* or *Out-EncodedCommand* or *Out-EncryptedScript* or *Out-Minidump* or *PowerUp* or *PowerView* or *Remove-Comments* or *Remove-VolumeShadowCopy* or *Set-CriticalProcess* or *Set-MasterBootRecord*))
        ))
        or
        (process.name:"reg.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.args:("add" and "/d") and process.parent.command_line:(*reg.exe add* and *Set-Content*))
        or
        (process.name: "powershell.exe"
        and process.parent.name: "WmiPrvSE.exe"
        and process.parent.args: *-Embedding* 
        and process.args: (*-NoProfile* and (*-E* or *-EA* or *-EncodedArguments*)))
        or
        (process.name: "powershell.exe"
        and process.command_line: (*Remove-Item* *-Force* and *-ErrorAction Ignore*))
    )