KQL code

T1573:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:3 and destination.port:(443 or 8443 or 9443) and not process.executable.keyword:(*\\chrome.exe *\\firefox.exe *\\msedge.exe *\\svchost.exe *\\lsass.exe *\\msiexec.exe *\\OneDrive.exe *\\Teams.exe *\\outlook.exe)

T1105:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and (
        (
            process.name: "certutil.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("-urlcache" and "-split" and "-f")
            and process.command_line.text: ("http" or "https")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: "bitsadmin.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("/transfer" and "/Priority" and "HIGH")
            and process.command_line.text: ("http" or "https")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: "powershell.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("{(New-Object" or "Out-File" or "Invoke-Item" or "Invoke-Expression")
            and process.command_line.text: ("DownloadFile" or "DownloadString" or "WebClient")
            and process.command_line.text: ("http" or "https")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: "cmd.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("C:\\Windows\\System32\\Curl.exe" and "-k")
            and process.command_line.text: ("http" or "https")
            and process.command_line.text: ("\\users\\" or "%%Temp%%" or "\\programdata\\")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: "powershell.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("iwr" or "Invoke-WebRequest")
            and process.command_line.text: ("http" or "https")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: "powershell.exe"
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.args: ("&" and "{sqlcmd")
            and process.command_line.text: (("http" or "https") and ".zip")
            and process.working_directory.text: "\\Temp\\"
        )
        or
        (
            process.name: ("cmd.exe" or "powershell.exe")
            and process.parent.name: ("cmd.exe" or "powershell.exe")
            and process.command_line: ((* del * and *\>nul 2\>&1*) or (*Remove-Item* and *$env\:TEMP* and *-Force* and *-ErrorAction Ignore*) or (*rm* and *2\>$null*))
        )
    )