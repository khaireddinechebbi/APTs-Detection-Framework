# Defense Evasion

## Description:

Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.

## Techniques:
### T1055.001 - Process Injection: Dynamic-link Library Injection
#### Description:

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.

#### Kibana Query Language Code (KQL):

winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:"1"
and process.name:"powershell.exe"
and process.args:((*/INJECTRUNNING* and *-PassThru* and *mypid*) or (*iex* and *new-object* and *webclient* and *downloadstring*))

### T1218.005 - System Binary Proxy Execution: Mshta
#### Description:

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code

#### Kibana Query Language Code (KQL):

winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name:"mshta.exe"
and process.parent.name: ("powershell.exe" or "cmd.exe")
and process.command_line: (((*vbscript* or *VBScript*) and *Execute* and *Wscript.Shell* and *powershell*) or (*\\Microsoft\\Windows\\Start* and *Menu\\Programs\\Startup* and *.hta*))

### T1218.010 - System Binary Proxy Execution: Regsvr32
#### Description:

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The Regsvr32.exe binary may also be signed by Microsoft.

#### Kibana Query Language Code (KQL):

winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name:"regsvr32.exe"
and process.parent.name: ("cmd.exe" or "powershell.exe")
and (
    process.command_line: */s*
    and (
        process.command_line: (*/i* and *.dll*)
        or process.parent.command_line: ((* IF * and * ELSE *) or *%temp%*)
    )
)

### T1218.011 - System Binary Proxy Execution: Rundll32
#### Description:

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: rundll32.exe {DLLname, DLLfunction}).

#### Kibana Query Language Code (KQL):

winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: "rundll32.exe"
and (
    process.parent.name: ("cmd.exe" or "powershell.exe")
    and process.command_line: (
        (*.dll* and *,#*)
        or not (*.dll* or *.cpl*)
        or (*shell32.dll,Control_RunDLL* and not *.cpl*)
    )
    or process.parent.name: "rundll32.exe"
)
