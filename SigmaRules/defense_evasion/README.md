KQL code:

T1055.001:
    winlog.channel:"Microsoft-Windows-Sysmon/Operational" and ((event.code:8 and process.name:"mavinject.exe" and winlog.event_data.StartFunction:("LoadLibraryA" or "LoadLibraryW") and event.action:"CreateRemoteThread") or(event.code:7 and process.name:("mavinject.exe" or "UsoClient.exe") and file.extension:"dll"))