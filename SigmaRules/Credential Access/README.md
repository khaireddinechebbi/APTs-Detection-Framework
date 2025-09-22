# Credential Access

## Description:
Credential Access techniques involve methods adversaries use to steal account credentials, such as passwords, hashes, kerberos tickets, and other authentication materials. This includes extracting credentials from the Security Account Manager (SAM) database, Local Security Authority (LSA) secrets, and other protected storage locations within the operating system.

## Techniques:
### T1003.002 - OS Credential Dumping: Security Account Manager
#### Description:
Adversaries attempt to extract credential information from the Security Account Manager (SAM) database, which contains local account passwords and hashes. This technique involves using native Windows utilities like reg.exe to export the SAM, SYSTEM, and SECURITY registry hives to disk for offline extraction of credentials, often followed by cleanup activities to remove evidence of the dumping process.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational 
AND event.code:1 
AND (
    (
        process.name:reg.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:*reg* 
        AND process.command_line:(* save * OR * export *)
        AND process.command_line:(*\\sam* OR *\\system* OR *\\security*)
    ) OR (
        process.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:(*del* AND *%temp%*) 
        AND process.command_line:(*\\sam* OR *\\SAM* OR *\\system* OR *\\security*)
    ) OR (
        process.name: cmd.exe 
        AND process.command_line:*esentutl.exe* 
        AND process.command_line:(* /y * AND * /vss * AND */config/SAM*)
    )
)
```

### T1003.004 - OS Credential Dumping: LSA Secrets
#### Description:
Adversaries target the Local Security Authority (LSA) secrets, which store various sensitive credentials including service account passwords, cached domain credentials, and other authentication data. This technique involves exporting the SECURITY registry hive to access LSA secrets, often using tools like reg.exe and potentially involving remote download of specialized dumping tools, followed by cleanup operations to remove temporary files and cover tracks.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational 
AND event.code:1 
AND (
    (
        process.name:reg.exe 
        AND process.command_line:(*reg* AND * save * AND *\\security\\policy\\secrets* AND */y*)
        AND process.command_line:(*%temp%* OR *\\Temp\\*)
    ) OR (
        process.name:powershell.exe 
        AND process.command_line:(*Invoke-Expression* AND *WebClient* AND *DownloadString* AND *.ps1*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*del* AND *\\secrets*) 
        AND process.command_line:(*%temp%* OR *\\Temp\\*)
    )
)
```
