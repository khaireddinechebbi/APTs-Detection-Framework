KQL code:

T1053.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and (process.name:"schtasks.exe" or process.executable:*\\schtasks.exe or winlog.event_data.Image:*\\schtasks.exe) and (process.command_line:"* /create *" or message:"* /create *")