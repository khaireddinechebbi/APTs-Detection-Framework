# Impact

## Description:
Impact techniques involve methods adversaries use to manipulate, interrupt, or destroy systems and data. This includes data destruction, defacement, and other actions that compromise availability, integrity, or business operations, often serving as the final stage of an attack to cause maximum damage or disruption.

## Techniques:
### T1485 - Data Destruction
#### Description:
Adversaries destroy or corrupt data on target systems to disrupt operations, cause financial damage, or cover their tracks. This technique involves using system utilities and scripts to delete, overwrite, or encrypt files and directories, potentially targeting critical system files, databases, backups, and user data to maximize impact and recovery time.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe" or "format.com" or "cipher.exe")
and process.command_line: (
    (*del* and (*/f* or */s* or */q*) and (*C:\\* or *D:\\* or *system32* or *.db* or *.mdf*))
    or (*format* and (*C:* or *D:* or *Q:* or */FS* or */Q*))
    or (*cipher* and (*/w* and *C:*))
    or (*Remove-Item* and (*-Recurse* and *-Force*) and (*C:\\Windows\\* or *C:\\ProgramData\\*))
    or (*rmdir* and (*/s* and */q*) and (*C:\\* or *D:\\*))
    or (*wevtutil* and (*cl* and *System* or *Security* or *Application*))
    or (*fsutil* and (*file* and *setZeroData*))
    or (*vssadmin* and (*Delete Shadows* and */All*))
)
```

### T1491.001 - Defacement: Internal Defacement
#### Description:
Adversaries modify system or application content to display unauthorized messages, images, or content to users. This technique involves replacing legitimate web pages, application interfaces, or system messages with malicious content, often for psychological impact, propaganda, or to demonstrate compromise while potentially destroying original content in the process.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("cmd.exe" or "powershell.exe" or "notepad.exe" or "echo.exe")
and process.command_line: (
    (*echo* and (*hacked* or *compromised* or *defaced*) and (*>* or *>>*) and (*.html* or *.htm* or *.aspx*))
    or (*copy* and (*con*) and (*index.html* or *default.aspx*))
    or (*Set-Content* and (*-Value* and (*hack* or *owned*)) and (*-Path* and (*inetpub* or *wwwroot*)))
    or (*ren* and (*index.html* or *default.aspx*) and (*.bak* or *.old*))
    or (*attrib* and (*+h* or *+s*) and (*defaced* or *hacked*))
    or (*icacls* and (*/grant* and *Everyone:F*) and (*C:\\inetpub\\wwwroot\\*))
    or (*takeown* and (*/f* and *C:\\inetpub\\wwwroot\\*))
)
```
