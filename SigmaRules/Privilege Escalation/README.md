# Privilege Escalation

## Description:
Privilege Escalation techniques consist of methods adversaries use to gain higher-level permissions on a system or network. This includes exploiting system vulnerabilities, injecting code into higher-privileged processes, and abusing system mechanisms to execute code with elevated privileges, enabling attackers to bypass security controls and access restricted resources.

## Techniques:
### T1055.001 - Process Injection: Dynamic-link Library Injection
#### Description:
Adversaries inject malicious code into running processes to execute payloads with the privileges of the target process. This technique involves using PowerShell to load and execute DLLs within the context of legitimate processes, potentially gaining elevated privileges by targeting system processes or services running with higher permissions than the current user context.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:"1"
and process.name:"powershell.exe"
and process.args:((*/INJECTRUNNING* and *-PassThru* and *mypid*) or (*iex* and *new-object* and *webclient* and *downloadstring*))
```

### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
#### Description:
Adversaries abuse Windows Management Instrumentation (WMI) event subscriptions to execute malicious code with elevated privileges in response to system events. This technique involves creating WMI event filters and consumers that trigger payload execution when specific system events occur, potentially allowing code to run with higher privileges than the initial compromise and maintaining persistent elevated access.

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