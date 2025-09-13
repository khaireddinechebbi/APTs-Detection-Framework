# Credential Access

## Description:

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.

## Techniques:
### T1003.002 - OS Credential Dumping: Security Account Manager
#### Description:

Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the net user command. Enumerating the SAM database requires SYSTEM level access.

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

Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. LSA secrets can also be dumped from memory.

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
