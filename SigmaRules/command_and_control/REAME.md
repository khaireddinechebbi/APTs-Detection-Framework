# Command And Control

## Description

Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.

## Techniques:
### T1105 - Ingress Tool Transfer
#### Description:

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer).

#### Kibana Query Language Code (KQL):

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

### T1573 - Encrypted Channel
#### Description:

Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.

#### Kibana Query Language Code (KQL):

winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (*Net.Sockets.TcpClient* and *System.Net.Security.SslStream* and *$sslStream.AuthenticateAsClient* and *$sslStream.Write* and *$sslStream.Read* and (*iex* or *Invoke-Expression*))
