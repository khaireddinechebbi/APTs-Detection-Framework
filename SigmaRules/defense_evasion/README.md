KQL code:

T1055.001:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational"
    and event.code:"1"
    and process.name:"powershell.exe"
    and process.args:((*/INJECTRUNNING* and *-PassThru* and *mypid*) or (*iex* and *new-object* and *webclient* and *downloadstring*))