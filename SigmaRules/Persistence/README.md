# Persistence

## Description:

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.

## Techniques:
### T1053.005 - Scheduled Task/Job: Scheduled Task
#### Description:

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and Windows Management Instrumentation (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet Invoke-CimMethod, which leverages WMI class PS_ScheduledTask to create a scheduled task via an XML path.

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

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime.
Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may also compile WMI scripts – using mofcomp.exe –into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription.
WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

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
