# Lateral Movement

## Description:
Lateral Movement techniques consist of methods adversaries use to enter and control remote systems on a network. This includes leveraging remote services and protocols to extend access from initially compromised systems to other systems within the environment, enabling further discovery, privilege escalation, and persistence.

## Techniques:
### T1021.004 - Remote Services: SSH
#### Description:
Adversaries use Secure Shell (SSH) to move laterally between systems and execute commands on remote hosts. This technique involves enabling SSH services on compromised systems, using tools like plink.exe to establish encrypted connections, and executing commands remotely to extend control across the network while maintaining stealth through encrypted communications.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND (
    (
        event.code:1
        AND process.name:(powershell.exe OR cmd.exe)
        AND process.command_line:(*Connect-VIServer* AND *Get-VMHostService* AND *TSM-SSH*)
        AND process.command_line:(*Start-VMHostService* OR *Stop-VMHostService*)
    ) OR (
        event.code:1
        AND process.name:(powershell.exe OR cmd.exe)
        AND process.command_line:(*plink.exe* AND *-ssh* AND *vim-cmd*)
        AND process.command_line:(*enable_ssh* OR *disable_ssh*)
    )
)
```

### T1021.006 - Remote Services: Windows Remote Management
#### Description:
Adversaries abuse Windows Remote Management (WinRM) to execute commands and move laterally between Windows systems. This technique involves enabling PSRemoting on target systems, using legitimate management tools or frameworks like Evil-WinRM to establish remote PowerShell sessions, and executing commands on remote hosts to expand control across the network.

#### Kibana Query Language Code (KQL):
```
winlog.channel:Microsoft-Windows-Sysmon/Operational
AND event.code:1
AND process.name:powershell.exe
AND process.command_line:(*Enable-PSRemoting* OR *Disable-PSRemoting* OR *evil-winrm*)
```