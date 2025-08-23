KQL code

T1059.001:
    winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code: 1 and ( process.name: ("powershell.exe" or "pwsh.exe") or winlog.event_data.Image: "*\\powershell.exe" ) and ( process.command_line: ("* -enc *" or "* -encodedcommand *" or "* /enc *" or "* /encodedcommand *") or process.args: ("-enc" or "-encodedcommand" or "/enc" or "/encodedcommand") or message: ("* -enc *" or "* -encodedcommand *" or "* /enc *" or "* /encodedcommand *") ) and not (process.parent.name:"ccmexec.exe" or process.parent.name:"SCClient.exe" or process.parent.name:"IntuneManagementExtension.exe")
