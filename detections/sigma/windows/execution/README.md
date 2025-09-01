KQL code

T1218.005:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and ((process.parent.name:"mshta.exe" and (process.name:"cmd.exe" or process.name:"powershell.exe" or process.name:"rundll32.exe" or process.name:"regsvr32.exe" or process.name:"wscript.exe" or process.name:"cscript.exe" or process.name:"msiexec.exe" or process.name:"schtasks.exe" or process.name:"bitsadmin.exe" or process.name:"certutil.exe")) or (process.name:"mshta.exe" and (process.args:*hta* or process.args:*http* or process.args:*https*))or (process.name:"powershell.exe" and ((process.args:*Invoke-WebRequest* and process.args:*mshta*) or (process.args:*Invoke-ATHHTMLApplication* and process.args:*-HTAUri*))))

T1218.010:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and ((process.name:"regsvr32.exe" and (process.args:scrobj.dll or process.command_line:*scrobj.dll*) and (process.args:*/i* or process.command_line:*/i* ) and (process.args:*.sct or process.command_line:*.sct*)) or (process.name:"cmd.exe" and process.args:*regsvr32.exe* and process.args:*scrobj.dll* and (process.args:*.sct* or process.command_line:*.sct*)))

T1218.011:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and process.name:"rundll32.exe" and ((process.args:*pcwutl.dll* and process.args:*LaunchApplication* and process.args:*.exe) or (process.args:*shell32.dll* and process.args:*Control_RunDLL* and process.args:*.dll) or (process.args:*desk.cpl* and process.args:*InstallScreenSaver* and process.args:*.scr) or (process.args:*url.dll* and process.args:*FileProtocolHandler* and process.args:*.exe) or (process.args:*StartW* and not process.args:*.dll*))

T1047:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:1 and (process.name:"WMIC.exe" or process.executable:*\\WMIC.exe or winlog.event_data.Image:*\\WMIC.exe) and (process.command_line:"* process call create *" or message:"* process call create *")
