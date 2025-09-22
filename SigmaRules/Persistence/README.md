# Persistence

## Description:
Persistence techniques consist of methods adversaries use to maintain access to systems across restarts, changed credentials, and other interruptions that could cut off their access. This includes creating scheduled tasks, WMI event subscriptions, and other mechanisms that allow attackers to automatically re-establish access and continue operations on compromised systems.

## Techniques:
### T1053.005 - Scheduled Task/Job: Scheduled Task
#### Description:
Adversaries create scheduled tasks to execute malicious code at system startup, user logon, or specific intervals to maintain persistence. This technique involves using schtasks.exe or PowerShell cmdlets to create, modify, or delete tasks that run commands, scripts, or binaries, often with elevated privileges and hidden execution to maintain long-term access to compromised systems.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational 
AND (
    (
        event.code:1 
        AND process.name:schtasks.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:(*/tr* OR */TR*) 
        AND process.command_line:(*/sc* OR */SC*) 
        AND process.command_line:(*create* OR *Create*) 
        AND process.command_line:(*onlogon* OR *onstart* OR */ru system* OR *ONCE* OR */ST* OR */RU* OR */U* OR */S* OR */F* OR */f* OR */tn* OR */TN*)
    ) OR (
        event.code:1 
        AND process.name:powershell.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*New-ScheduledTask* AND *Register-ScheduledTask* AND *Set-ScheduledTask*)
    ) OR (
        event.code:1 
        AND process.name:schtasks.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*/delete* OR */Delete*) 
        AND process.command_line:(*onlogon* OR *onstart* OR */ru system* OR *ONCE* OR */ST* OR */RU* OR */U* OR */S* OR */F* OR */f* OR */tn* OR */TN*)
    ) OR (
        event.code:1 
        AND process.name:powershell.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:*Unregister-ScheduledTask* AND process.command_line:*-TaskName* AND process.command_line:*-confirm\:$false*
    )
)
```

### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
#### Description:
Adversaries abuse Windows Management Instrumentation (WMI) event subscriptions to execute malicious code in response to system events. This technique involves creating permanent WMI event filters, consumers, and bindings that trigger payload execution when specific events occur (such as system startup or process creation), providing a stealthy persistence mechanism that operates through a legitimate system management framework.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational 
AND (
    (
        event.code:1 
        AND process.name:powershell.exe 
        AND process.command_line:(*__EventFilter* AND *__FilterToConsumerBinding*) 
        AND process.command_line:(*CommandLineEventConsumer* OR *ActiveScriptEventConsumer*)
    ) OR (
        event.code:1 
        AND process.name:powershell.exe 
        AND process.command_line:(*mofcomp.exe* AND *.mof*)
    ) OR (
        event.code:1 
        AND process.name:powershell.exe 
        AND process.command_line:(*Get-WmiObject* AND *Remove-WmiObject* AND *-ErrorAction SilentlyContinue*)
    )
)
```
