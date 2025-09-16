# Collection

## Description:
Collection techniques involve methods adversaries use to gather information and consolidate stolen data from target systems. This includes identifying, aggregating, and preparing valuable information from local systems, networks, and cloud environments for exfiltration, often using staging locations to organize data before transfer.

## Techniques:
### T1005 - Data from Local System
#### Description:
Adversaries search for and collect valuable data from local system sources, including files, directories, databases, and configuration stores. This technique involves using system utilities and custom scripts to locate sensitive information such as credentials, intellectual property, configuration files, and other data of interest that can be leveraged for further attacks or exfiltration.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe" or "findstr.exe" or "find.exe")
and process.command_line: (
    (*dir* and (*/s* or */a*)) 
    or (*Get-ChildItem* and (*-Recurse* or *-Include*))
    or (*findstr* and (*/i* and (*password* or *secret* or *key* or *token*)))
    or (*select-string* and (*-Pattern* and (*pass* or *cred* or *config*)))
    or (*copy* and (*.config* or *.xml* or *.txt* or *.doc* or *.xls*))
    or (*robocopy* and (**.doc* or *.xls* or *.pdf* or *.txt*))
    or (*type* and (*NUL >* and (*.tmp* or *.temp*)))
)
```

### T1074.001 - Data Staged: Local Data Staging
#### Description:
Adversaries collect and stage captured data in centralized locations or archives on local systems before exfiltration. This technique involves creating temporary directories, compressing files, and organizing stolen information into structured formats to facilitate efficient transfer while minimizing the number of connections required for data exfiltration.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe" or "rar.exe" or "zip.exe" or "7z.exe")
and process.command_line: (
    (*mkdir* and (*Temp* or *tmp* or *staging* or *collect*))
    or (*Compress-Archive* and (*-Path* and *-DestinationPath*))
    or (*tar* and (*-cf* or *-czf*))
    or (*zip* and (*-r* and *-q*))
    or (*copy* and (*\\* and (*.zip* or *.rar* or *.7z*)))
    or (*move* and (*C:\\Users\\* and *C:\\Temp\\*))
    or (*robocopy* and (*/S* and */MOV* and *.dat*))
)
```
