# Exfiltration

## Description:
Exfiltration techniques involve methods adversaries use to steal and remove data from compromised networks. This includes transferring collected information through command and control channels, using various protocols and techniques to evade detection while moving sensitive data to external systems controlled by attackers.

## Techniques:
### T1041 - Exfiltration Over C2 Channel
#### Description:
Adversaries exfiltrate stolen data through existing command and control channels rather than establishing separate connections. This technique involves embedding exfiltrated data within normal protocol communications, using encryption or encoding to obscure the content, and leveraging the same infrastructure used for ongoing command and control activities to blend data theft with legitimate-looking traffic.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("powershell.exe" or "cmd.exe" or "certutil.exe" or "bitsadmin.exe")
and process.command_line: (
    (*Invoke-WebRequest* and (*-Method Post* or *-Body*) and (*http* or *https*))
    or (*System.Net.WebClient* and *.UploadData* or *.UploadFile*)
    or (*certutil* and (*-encode* or *-decode*) and (*.exe* or *.dll*))
    or (*bitsadmin* and (*/transfer* and (*http* or *https*)))
    or (*curl* and (*-X POST* or *--data*) and (*http* or *https*))
    or (*ftp* and (*-s:* and (*.txt* or *.bat*)))
    or (*ping* and (*-n* and *-l* and *-w* and *> *))
    or (*nslookup* and (*.exe* or *.txt*))
)
```