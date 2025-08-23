KQL code:
T1547.001 - EID: 13
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:13 and winlog.event_data.TargetObject:("*\\CurrentVersion\\Run\\*" or "*\\CurrentVersion\\RunOnce\\*" or "*\\Policies\\Explorer\\Run\\*" or "*\\WOW6432Node\\*\\Run\\*") and winlog.event_data.Details:("*\\AppData\\*" or "*\\Temp\\*" or "*\\Downloads\\*" or "\\\\" or "*\\powershell.exe*" or "*\\wscript.exe*" or "*\\cscript.exe*" or "*\\cmd.exe*" or "*\\rundll32.exe*" or "*.ps1" or "*.vbs") and not winlog.event_data.Details:("*OneDrive.exe*" or "*\\Teams\\Update.exe*" or "*NVIDIA Corporation*" or "*\\Google\\Update\\*")

T1547.001 - EID: 11
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:11 and winlog.event_data.TargetFilename:("*\\Start Menu\\Programs\\Startup\\*" or "*\\Programs\\StartUp\\*") and not winlog.event_data.TargetFilename:"*\\OneDrive.lnk"
