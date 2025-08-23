KQL code

T1112:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:13 and (winlog.event_data.TargetObject:"*\\Image File Execution Options\\*\\Debugger" or (winlog.event_data.TargetObject:"*\\Policies\\System\\*" and winlog.event_data.TargetObject:("*\\EnableLUA" or "*\\ConsentPromptBehaviorAdmin")) or winlog.event_data.TargetObject:"*\\Software\\Policies\\Microsoft\\Windows Defender\\*" or winlog.event_data.TargetObject:"*\\System\\CurrentControlSet\\Control\\SafeBoot\\*" or (winlog.event_data.TargetObject:"*\\System\\CurrentControlSet\\Services\\*" and winlog.event_data.Details:"*DWORD (0x00000004)*"))

T1562.001:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:("powershell.exe" or "pwsh.exe" or "cmd.exe") and process.command_line:("*Set-MpPreference*" or "*Add-MpPreference*" or "*DisableRealtimeMonitoring*" or "*MAPSReporting*" or "*SubmitSamplesConsent*" or "*DisableIOAVProtection*" or "*TurnOffRealTimeMonitoring*" or "*DisableBehaviorMonitoring*")

T1562.001:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:13 and winlog.event_data.TargetObject:("*\\Windows Defender\\DisableAntiSpyware" or "*\\Windows Defender\\DisableAntiVirus" or "*\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring")

T1055 (EQL):
    process where event.action == "CreateRemoteThread" and not process.Ext.target.image_path : ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\dllhost.exe")

