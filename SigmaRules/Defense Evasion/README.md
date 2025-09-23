# Defense Evasion

## Description:
Defense Evasion techniques consist of methods adversaries use to avoid detection throughout their compromise. This includes subverting security tools, manipulating system processes, and abusing trusted system utilities to execute malicious code while bypassing defensive measures and logging mechanisms.

## Techniques:
### T1055.001 - Process Injection: Dynamic-link Library Injection
#### Description:
Adversaries inject malicious code into running processes to conceal their activities and evade process-based defenses. This technique involves using PowerShell to inject DLLs into existing processes, often combining injection with code download from remote servers to execute payloads in memory without writing to disk.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
AND event.code:1
AND process.name:powershell.exe
AND (
    process.command_line:(*mavinject* AND */INJECTRUNNING*)
    OR process.command_line:(*iex* AND *new-object* AND *webclient* AND *downloadstring* AND *.ps1*)
)
```

### T1218.005 - System Binary Proxy Execution: Mshta
#### Description:
Adversaries abuse the Microsoft HTML Application Host (mshta.exe) to execute malicious scripts and bypass application control solutions. This technique involves using mshta to run VBScript or JScript code that typically launches PowerShell commands, often targeting startup directories for persistence or executing scripts directly from command-line interfaces.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:mshta.exe
AND process.parent.name:(powershell.exe OR cmd.exe)
AND (
    process.command_line:((*vbscript* OR *VBScript*) AND *Execute* AND *Wscript.Shell* AND *powershell*)
    OR process.command_line:(*\\Microsoft\\Windows\\Start* AND *\\Programs\\Startup* AND *.hta*)
)
```

### T1218.010 - System Binary Proxy Execution: Regsvr32
#### Description:
Adversaries misuse the regsvr32.exe utility to execute malicious DLLs while evading defense mechanisms. This technique leverages regsvr32's legitimate functionality to register DLLs while using silent execution flags and temporary directory patterns to load and execute malicious code without user interaction or visible indicators.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:regsvr32.exe
AND process.parent.name: (cmd.exe OR powershell.exe)
AND (
    process.command_line: (*/s* AND */i* AND *.dll*)
    OR process.parent.command_line: (*/s* AND * IF * AND * ELSE *)
    OR process.parent.command_line: (*/s* AND *%temp%*)
)
```

### T1218.011 - System Binary Proxy Execution: Rundll32
#### Description:
Adversaries exploit the rundll32.exe Windows utility to execute malicious code disguised as legitimate DLL functions. This technique involves calling unusual export functions, using non-standard file extensions, or creating chain executions where rundll32 processes spawn additional rundll32 instances to obscure the malicious activity and bypass security controls.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:rundll32.exe
AND (
    process.parent.name:(cmd.exe OR powershell.exe)
    AND (
        process.command_line:(*.dll* AND *,#*)
        OR not process.command_line:(*.dll* OR *.cpl*)
        OR process.command_line:(*shell32.dll,Control_RunDLL* AND not *.cpl*)
    )
    or process.parent.name:rundll32.exe
)
```
