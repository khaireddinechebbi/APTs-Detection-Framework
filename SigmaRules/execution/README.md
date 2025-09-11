KQL code

T1218.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and ((process.parent.name:"mshta.exe" and (process.name:"cmd.exe" or process.name:"powershell.exe" or process.name:"rundll32.exe" or process.name:"regsvr32.exe" or process.name:"wscript.exe" or process.name:"cscript.exe" or process.name:"msiexec.exe" or process.name:"schtasks.exe" or process.name:"bitsadmin.exe" or process.name:"certutil.exe")) or (process.name:"mshta.exe" and (process.args:*hta* or process.args:*http* or process.args:*https*))or (process.name:"powershell.exe" and ((process.args:*Invoke-WebRequest* and process.args:*mshta*) or (process.args:*Invoke-ATHHTMLApplication* and process.args:*-HTAUri*))))

T1218.010:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and process.name:"regsvr32.exe"
    and process.parent.name: ("cmd.exe" or "powershell.exe")
    and (
        process.args: (scrobj.dll and */i* and *.sct)
        or process.parent.args: (("IF" and "ELSE") or *%temp%*)
    )

T1218.011:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:"rundll32.exe" and ((process.args:*pcwutl.dll* and process.args:*LaunchApplication* and process.args:*.exe) or (process.args:*shell32.dll* and process.args:*Control_RunDLL* and process.args:*.dll) or (process.args:*desk.cpl* and process.args:*InstallScreenSaver* and process.args:*.scr) or (process.args:*url.dll* and process.args:*FileProtocolHandler* and process.args:*.exe) or (process.args:*StartW* and not process.args:*.dll*))

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