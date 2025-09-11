KQL code:

T1053.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:1
    and (
        (process.name:"schtasks.exe"
        and process.parent.name:("cmd.exe" or "powershell.exe")
        and process.command_line: (
        ((* /create * or * /Create *) and (* /sc * or * /SC *) and (* /tr * or * /TR *) and (*cmd.exe* or *powershell.exe*))
        or ((* /delete * or * /Delete *) and (* /tn * or * /TN *) and (* /f * or * /F *))
        ))
        or 
        (process.command_line:(
            (
                (
            *Register-ScheduledTask* or
            *Set-ScheduledTask* or
            *New-ScheduledTaskAction* or
            *New-ScheduledTaskTrigger* or
            *New-ScheduledTaskPrincipal*
            )
            and 
            (
            (*-AtLogon* or *-AtStartup* or *-RunLevel Highest*)
            or (*-GroupId* and *Administrators*)
            or (*-Execute* and (*cmd.exe* or *powershell.exe* or *notepad.exe*))
            )
            ) or (
            (*Unregister-ScheduledTask* and *-TaskName*)
            and (*-confirm\:$false* or *\>$null* or *2\>&1*))
        ))
    )
