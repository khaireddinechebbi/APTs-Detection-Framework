# Lateral Movement

## Description:

Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.

## Techniques:
### T1021.004 - Remote Services: SSH
#### Description:

SSH is a protocol that allows authorized users to open remote shells on other computers. Many Linux and macOS versions come with SSH installed by default, although typically disabled until the user enables it. On ESXi, SSH can be enabled either directly on the host (e.g., via vim-cmd hostsvc/enable_ssh) or via vCenter.The SSH server can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password. In this authentication scenario, the user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user (i.e., SSH Authorized Keys).

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

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell. WinRM can be used as a method of remotely interacting with Windows Management Instrumentation.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code:1
and process.name: "powershell.exe"
and process.command_line: (*Enable-PSRemoting* or *Disable-PSRemoting* or *evil-winrm*)
```