# Persistence

## Description:
Persistence techniques consist of methods adversaries use to maintain access to systems across restarts, changed credentials, and other interruptions that could cut off their access. This includes creating scheduled tasks, WMI event subscriptions, and other mechanisms that allow attackers to automatically re-establish access and continue operations on compromised systems.

## Techniques:
### T1053.005 - Scheduled Task/Job: Scheduled Task
#### Description:
Adversaries create scheduled tasks to execute malicious code at system startup, user logon, or specific intervals to maintain persistence. This technique involves using schtasks.exe or PowerShell cmdlets to create, modify, or delete tasks that run commands, scripts, or binaries, often with elevated privileges and hidden execution to maintain long-term access to compromised systems.

#### Kibana Query Language Code (KQL):
```
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
            and (*-confirm\:$false* or *\>$null* or *2\>&1*)
        )
    ))
)
```

### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
#### Description:
Adversaries abuse Windows Management Instrumentation (WMI) event subscriptions to execute malicious code in response to system events. This technique involves creating permanent WMI event filters, consumers, and bindings that trigger payload execution when specific events occur (such as system startup or process creation), providing a stealthy persistence mechanism that operates through a legitimate system management framework.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (
    ((*New-CimInstance* or *Set-WmiInstance*) and *root/subscription* and (*__EventFilter* or *CommandLineEventConsumer* or *ActiveScriptEventConsumer* or *__FilterToConsumerBinding*))
    or (*mofcomp.exe* and *.mof*)
    or (*root/subscription* and *Get-WmiObject* and *Remove-WmiObject* and (*__EventFilter* or *CommandLineEventConsumer* or *ActiveScriptEventConsumer* or *__FilterToConsumerBinding*) and *-ErrorAction SilentlyContinue*)
)
```
