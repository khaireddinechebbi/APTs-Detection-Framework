# Command and Control

## Description
Command and Control (C2) refers to techniques that adversaries use to communicate with compromised systems and control them remotely. This includes methods for transferring tools into the environment, maintaining persistence, and exfiltrating data while often using encryption to evade detection.

## Techniques:
### T1105 - Ingress Tool Transfer
#### Description:
Adversaries transfer tools or other files from an external system into a compromised environment. This technique involves using native system tools or PowerShell to download, extract, and execute malicious payloads from remote servers, often followed by cleanup activities to remove evidence of the transfer.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND (
    (
        process.name: certutil.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:(*-urlcache* AND *-split* AND *-f*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:bitsadmin.exe
        AND process.parent.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:*/transfer* 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:powershell.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe)
        AND process.command_line:(*New-Object* OR *Out-File* OR *Invoke-Item* OR *Invoke-Expression*)
        AND process.command_line:(*DownloadFile* OR *DownloadString* OR *WebClient*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:cmd.exe 
        AND process.command_line:*Curl.exe* 
        AND process.command_line:(*-k* OR *--insecure* OR *-o* OR *--output*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:powershell.exe 
        AND process.parent.name:(cmd.exe OR powershell.exe) 
        AND process.command_line:(*iwr* OR *Invoke-WebRequest*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:powershell.exe 
        AND process.command_line:(*sqlcmd* AND *-i*) 
        AND process.command_line:(*http* OR *https*)
    ) OR (
        process.name:(cmd.exe OR powershell.exe) 
        AND (
            process.command_line:(* del * AND *\>nul 2\>&1*) 
            OR process.command_line:(*Remove-Item* AND *$env\:TEMP* AND *-Force* AND *-ErrorAction Ignore*) 
            OR process.command_line:(*rm* AND *2\>$null*)
        )
    )
)
```

### T1573 - Encrypted Channel
#### Description:
Adversaries use encrypted communication channels to conceal their command and control traffic and evade network detection. This technique involves implementing custom encryption within PowerShell scripts using .NET classes like SslStream and TcpClient to establish secure, encrypted connections between compromised systems and attacker-controlled servers.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:powershell.exe
AND process.command_line:(*TcpClient* AND *SslStream* AND *AuthenticateAsClient* AND *Tls12*) 
AND process.command_line:(*iex* OR *IEX* OR *Invoke-Expression*)
```
