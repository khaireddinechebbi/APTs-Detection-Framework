# Privilege Escalation

## Description:

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include:

SYSTEM/root level
local administrator
user account with admin-like access
user accounts with access to specific system or perform specific function
These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.

## Techniques:
### T1055.001 - Process Injection: Dynamic-link Library Injection
#### Description:

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:"1"
and process.name:"powershell.exe"
and process.args:((*/INJECTRUNNING* and *-PassThru* and *mypid*) or (*iex* and *new-object* and *webclient* and *downloadstring*))
```
