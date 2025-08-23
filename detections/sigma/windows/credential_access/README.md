#KQL code
T1003.002:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and ((process.name:"reg.exe" and process.command_line:("* save *") and process.command_line:("*hklm\\sam*" or "*hklm\\system*" or "*hklm\\security*")) or process.command_line:("*\\Windows\\System32\\config\\SAM*" or "*\\Windows\\System32\\config\\SYSTEM*" or "*\\Windows\\System32\\config\\SECURITY*" or "*HarddiskVolumeShadowCopy*"))

T1003.004:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:("reg.exe" or "powershell.exe" or "pwsh.exe") and process.command_line:("*HKLM\\SECURITY\\Policy\\Secrets*" or "*HKLM:\\SECURITY\\Policy\\Secrets*" or "*Registry::HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets*")

T1003.006:
    winlog.channel:"Security" and event.code:4662 and winlog.event_data.Properties:("*Replicating Directory Changes All*" or "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" or "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" or "*89e95b76-444d-4c62-991a-0facbeda640c*") and winlog.event_data.AccessMask:"0x100" and not winlog.event_data.SubjectUserName:("MSOL_*" or "*$")
