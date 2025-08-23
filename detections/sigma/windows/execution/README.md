KQL code
T1218.010:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:"regsvr32.exe" and (process.command_line:("*scrobj.dll*" or "*.sct*" or "http*" or "https*") or process.command_line:("* /s *" or "* /u *" or "* /i *"))

T1218.011:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:"rundll32.exe" and (process.command_line:("*javascript:*" or "*mshtml,RunHTMLApplication*" or "*.cpl,*" or "http*" or "https*") or process.command_line:("*DllRegisterServer*" or "*ShellExecute*" or "*#1*"))

T1218.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:"mshta.exe" and process.command_line:("http*" or "https*" or "file://*" or "*javascript:*" or "*vbscript:*" or "*about:blank*")

T1569.002:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and ((process.name:"sc.exe" and process.command_line:("* create *" or "* config *")) or (process.name:("powershell.exe" or "pwsh.exe") and process.command_line:("*New-Service*" or "*Set-Service*")))

