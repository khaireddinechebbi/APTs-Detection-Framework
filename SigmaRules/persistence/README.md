# Persistence

## Description:

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.

## Techniques:
### T1053.005 - Scheduled Task/Job: Scheduled Task
#### Description:

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and Windows Management Instrumentation (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet Invoke-CimMethod, which leverages WMI class PS_ScheduledTask to create a scheduled task via an XML path.

#### Kibana Query Language Code (KQL):

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
