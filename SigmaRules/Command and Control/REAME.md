# Command and Control

## Description
Command and Control (C2) refers to techniques that adversaries use to communicate with compromised systems and control them remotely. This includes methods for transferring tools into the environment, maintaining persistence, and exfiltrating data while often using encryption to evade detection.

## Techniques:
### T1105 - Ingress Tool Transfer
#### Description:
Adversaries transfer tools or other files from an external system into a compromised environment. This technique involves using native system tools or PowerShell to download, extract, and execute malicious payloads from remote servers, often followed by cleanup activities to remove evidence of the transfer.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and (
    (
        process.name: "certutil.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: (*-urlcache* and *-split* and *-f* and (*http* or *https*))
    )
    or
    (
        process.name: "bitsadmin.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: (*/transfer* and */Priority* and *HIGH* and (*http* or *https*))
    )
    or
    (
        process.name: "powershell.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: ((*New-Object* or *Out-File* or *Invoke-Item* or *Invoke-Expression*) and (*DownloadFile* or *DownloadString* or *WebClient*) and (*http* or *https*))
    )
    or
    (
        process.name: "cmd.exe"
        and process.command_line: (*Curl.exe* and *-k* and (*http* or *https*) and (*\\users\\* or *%%Temp%%* or *\\programdata\\*))
    )
    or
    (
        process.name: "powershell.exe"
        and process.parent.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: ((*iwr* or *Invoke-WebRequest*) and (*http* or *https*))
    )
    or
    (
        process.name: "powershell.exe"
        and process.command_line: (*sqlcmd* and (*http* or *https*) and *.zip*)
    )
    or
    (
        process.name: ("cmd.exe" or "powershell.exe")
        and process.command_line: ((* del * and *\>nul 2\>&1* ) or (*Remove-Item* and *$env\:TEMP* and *-Force* and *-ErrorAction Ignore*) or (*rm* and *2\>$null*))
    )
)
```

### T1573 - Encrypted Channel
#### Description:
Adversaries use encrypted communication channels to conceal their command and control traffic and evade network detection. This technique involves implementing custom encryption within PowerShell scripts using .NET classes like SslStream and TcpClient to establish secure, encrypted connections between compromised systems and attacker-controlled servers.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (*Net.Sockets.TcpClient* and *System.Net.Security.SslStream* and *$sslStream.AuthenticateAsClient* and *$sslStream.Write* and *$sslStream.Read* and (*iex* or *Invoke-Expression*))
```
