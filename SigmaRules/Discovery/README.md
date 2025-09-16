# Discovery

## Description:
Discovery techniques consist of methods adversaries use to gain knowledge about the system and internal network environment. This includes exploring files, directories, user accounts, and network resources to understand the landscape for lateral movement, privilege escalation, and identifying valuable data for exfiltration.

## Techniques:
### T1083 - File and Directory Discovery
#### Description:
Adversaries enumerate files and directories to understand the structure of the compromised system and locate valuable information. This technique involves using native commands and scripts to explore directory contents, identify sensitive files, and map out storage locations that may contain credentials, configuration files, or other data of interest for further exploitation.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe")
and process.command_line: (
    (*dir* and (*/s* or */a* or *c:\\* or *d:\\*)) 
    or (*Get-ChildItem* and (*-Recurse* or *-Force* or *-Hidden*))
    or (*tree* and *c:\\*)
    or (*ls* and *-la* and */home*)
    or (*find* and */ -name* and (*pass* or *config* or *secret*))
)
```

### T1087.002 - Account Discovery: Domain Account
#### Description:
Adversaries attempt to identify domain accounts and understand the domain structure to facilitate lateral movement and privilege escalation. This technique involves using network enumeration commands to discover domain users, groups, and trust relationships, helping attackers map the domain environment and identify potential targets for credential theft or further compromise.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe")
and process.command_line: (
    (*net user* and */domain*)
    or (*net group* and */domain*)
    or (*Get-ADUser* and *-Filter*)
    or (*Get-ADGroup* and *-Filter*)
    or (*net localgroup* and *administrators*)
    or (*whoami* and */groups*)
    or (*net accounts* and */domain*)
    or (*dsquery* and *user*)
    or (*wmic* and *useraccount*)
)
```
