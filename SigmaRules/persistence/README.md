KQL code:

T1053.005:
    winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name: "schtasks.exe" and process.args: (("schtasks" or "SCHTASKS") and ("/create" or "/Create") and ("/tn" or "/TN") and ("/tr" or "/TR")) and process.parent.name: ("cmd.exe" or "powershell.exe")