KQL code:

T1055.001:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and process.args:(("/INJECTRUNNING" and "-PassThru).id\nmavinject") or ("{iex(new-object")) and process.name:"powershell.exe" and event.code:"1"