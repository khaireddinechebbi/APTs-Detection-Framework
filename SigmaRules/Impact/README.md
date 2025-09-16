# Impact

## Description:
Impact techniques involve methods adversaries use to manipulate, interrupt, or destroy systems and data. This includes data destruction, defacement, and other actions that compromise availability, integrity, or business operations, often serving as the final stage of an attack to cause maximum damage or disruption.

## Techniques:
### T1485 - Data Destruction
#### Description:
Adversaries destroy or corrupt data on target systems to disrupt operations, cause financial damage, or cover their tracks. This technique involves using system utilities and scripts to delete, overwrite, or encrypt files and directories, potentially targeting critical system files, databases, backups, and user data to maximize impact and recovery time.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" 
and event.code:1 
and process.parent.name: "wsmprovhost.exe"
and process.name: ("cmd.exe" or "powershell.exe")
and process.command_line: (
    (*plink.exe* and *.removeall*)
    or (*sdelete.exe* and *-accepteula*)
    or (*cipher* and */w\:*)
)
```

### T1491.001 - Defacement: Internal Defacement
#### Description:
Adversaries modify system or application content to display unauthorized messages, images, or content to users. This technique involves replacing legitimate web pages, application interfaces, or system messages with malicious content, often for psychological impact, propaganda, or to demonstrate compromise while potentially destroying original content in the process.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe")
and (
    process.command_line: (
        (*@'* and *'@* and *add-type* and *Win32*)
        or (*HKLM\:* and *LegalNoticeCaption* and *LegalNoticeText*)
    )
    or
    (
        process.parent.name: "wsmprovhost.exe"
        and process.command_line: (*plink.exe* and *root* and *esxcli*)
    )
)
```
