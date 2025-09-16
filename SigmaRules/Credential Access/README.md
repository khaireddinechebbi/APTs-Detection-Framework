# Credential Access

## Description:
Credential Access techniques involve methods adversaries use to steal account credentials, such as passwords, hashes, kerberos tickets, and other authentication materials. This includes extracting credentials from the Security Account Manager (SAM) database, Local Security Authority (LSA) secrets, and other protected storage locations within the operating system.

## Techniques:
### T1003.002 - OS Credential Dumping: Security Account Manager
#### Description:
Adversaries attempt to extract credential information from the Security Account Manager (SAM) database, which contains local account passwords and hashes. This technique involves using native Windows utilities like reg.exe to export the SAM, SYSTEM, and SECURITY registry hives to disk for offline extraction of credentials, often followed by cleanup activities to remove evidence of the dumping process.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and (
    (
        process.name:"reg.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: (*reg* and (* save * or * export *))
        and process.command_line: (*\\sam* or *\\system* or *\\security*)
    )
    or
    (
        process.name:("cmd.exe" or "powershell.exe")
        and process.command_line: (*del* and *\>nul* and *2\>* and *%%temp%%* and (*\\sam* or *\\SAM* or *\\system* or *\\security*))
    )
    or
    (
        process.name: "cmd.exe"
        and process.command_line: (* esentutl.exe * and *%%SystemRoot%%/system32/config/SAM* and *%%temp%%/SAM*)
    )
)
```

### T1003.004 - OS Credential Dumping: LSA Secrets
#### Description:
Adversaries target the Local Security Authority (LSA) secrets, which store various sensitive credentials including service account passwords, cached domain credentials, and other authentication data. This technique involves exporting the SECURITY registry hive to access LSA secrets, often using tools like reg.exe and potentially involving remote download of specialized dumping tools, followed by cleanup operations to remove temporary files and cover tracks.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and (
    (
        process.name:"reg.exe"
        and process.parent.name: "PSEXESVC.exe"
        and process.command_line: (*reg* and * save * and *\\security\\policy\\secrets* and *\\Temp\\secrets*) 
    )
    or
    (
        process.name: "powershell.exe"
        and process.command_line: (*Invoke-Expression* and *.WebClient* and *.DownloadString* and (*http* or *https*) and *.ps1*)
    )
    or
    (
        process.name:("cmd.exe" or "powershell.exe")
        and process.command_line: (*del* and *\>nul* and *2\>* and *%%temp%%* and *\\secrets*)
    )
)
```
