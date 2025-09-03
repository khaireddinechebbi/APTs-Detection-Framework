KQL code

T1573:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:3 and destination.port:(443 or 8443 or 9443) and not process.executable.keyword:(*\\chrome.exe *\\firefox.exe *\\msedge.exe *\\svchost.exe *\\lsass.exe *\\msiexec.exe *\\OneDrive.exe *\\Teams.exe *\\outlook.exe)



T1105:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and (process.name:"certutil.exe" or winlog.event_data.Image:"*\\certutil.exe") and ( process.command_line:"* -urlcache *" or process.command_line:"* -split *" or process.command_line:"* http://*" or process.command_line:"* https://*" or message:"* -urlcache *" or message:"* -split *")