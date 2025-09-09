#KQL code
T1003.002:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and (
        (
            process.name:"reg.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.command_line: (*reg* and (* save * or * export *))
            and process.command_line: (*\\sam* or *\\system* or *\\security*)
        )
        or
        (
            process.name:("cmd.exe" or "powershell.exe")
            and process.command_line: (*del* and *\>nul* and *2\>* and *%%temp%%* and (*\\sam* or *\\SAM* or *\\system* or *\\security*))
        )
        or
        (
            process.name: "cmd.exe"
            and process.command_line: (* esentutl.exe * and *%%SystemRoot%%/system32/config/SAM* and *%%temp%%/SAM*)
        )
    )

T1003.004:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and (
        (
            process.name:"reg.exe"
            and process.parent.name: "PSEXESVC.exe"
            and process.command_line: (*reg* and * save * and *\\security\\policy\\secrets* and *\\Temp\\secrets*) 
        )
        or
        (
            process.name: "powershell.exe"
            and process.command_line: (*Invoke-Expression* and *.WebClient* and *.DownloadString* and (*http* or *https*) and *.ps1*)
        )
        or
        (
            process.name:("cmd.exe" or "powershell.exe")
            and process.command_line: (*del* and *\>nul* and *2\>* and *%%temp%%* and *\\secrets*)
        )
    )
