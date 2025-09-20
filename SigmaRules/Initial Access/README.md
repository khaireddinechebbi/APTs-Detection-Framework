# Initial Access

## Description:
Initial Access techniques consist of methods adversaries use to gain their first foothold within a network. This includes targeted phishing attacks with malicious attachments or links that exploit human trust to deliver payloads, execute code, and establish persistence on victim systems.

## Techniques:
### T1566.001 - Phishing: Spearphishing Attachment
#### Description:
Adversaries send targeted emails with malicious attachments to trick victims into executing code that provides initial access. This technique involves using PowerShell to download and execute malicious Office documents (like .xlsm files) that contain macros or exploit code, often followed by cleanup activities to remove evidence of the initial download and execution.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (
    ((*Invoke-WebRequest* or *iwr*) and (*http* or *https*) and *-OutFile* and *.xlsm*)
    or ((*IEX* or *Invoke-Expression*) and (*http* or *https*) and *Invoke-MalDoc* and *`* and *.jse*)
    or (*Remove-Item* and *C\:\\Users* and *-ErrorAction Ignore* and *.jse*)
    or (*Remove-Item* and *$env\:TEMP* and *-ErrorAction Ignore* and *.xlsm*)
)
```

### T1566.002 - Phishing: Spearphishing Link
#### Description:
Adversaries send targeted emails containing malicious links that lead to code execution when clicked. This technique involves using PowerShell to simulate keystrokes and automate the process of accessing malicious URLs, often employing base64 encoding to obfuscate the payload and bypass detection mechanisms while establishing a foothold on the victim system.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (*Add-Type* and *System.Windows.Forms* and *SendKeys* and *ToBase64String*)
```