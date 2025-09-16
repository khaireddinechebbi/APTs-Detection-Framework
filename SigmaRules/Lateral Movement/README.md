# Lateral Movement

## Description:
Lateral Movement techniques consist of methods adversaries use to enter and control remote systems on a network. This includes leveraging remote services and protocols to extend access from initially compromised systems to other systems within the environment, enabling further discovery, privilege escalation, and persistence.

## Techniques:
### T1021.004 - Remote Services: SSH
#### Description:
Adversaries use Secure Shell (SSH) to move laterally between systems and execute commands on remote hosts. This technique involves enabling SSH services on compromised systems, using tools like plink.exe to establish encrypted connections, and executing commands remotely to extend control across the network while maintaining stealth through encrypted communications.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: ("powershell.exe" or "cmd.exe")
and process.command_line: (
    (*Connect-VIServer* and *Get-VMHostService* and *TSM-SSH* and (*Start-VMHostService* or *Stop-VMHostService*))
    or
    (*plink.exe* and *-ssh* and *vim-cmd* and (*enable_ssh* or *disable_ssh*))
)
```

### T1021.006 - Remote Services: Windows Remote Management
#### Description:
Adversaries abuse Windows Remote Management (WinRM) to execute commands and move laterally between Windows systems. This technique involves enabling PSRemoting on target systems, using legitimate management tools or frameworks like Evil-WinRM to establish remote PowerShell sessions, and executing commands on remote hosts to expand control across the network.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: "powershell.exe"
and process.command_line: (*Enable-PSRemoting* or *Disable-PSRemoting* or *evil-winrm*)
```