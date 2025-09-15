# Initial Access

## Description:

Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.

## Techniques:
### T1566.001 - Phishing: Spearphishing Attachment
#### Description:

Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (
    ((*Invoke-WebRequest* or *iwr*) and (*http* or *https*) and *-OutFile* and *.xlsm*)
    or ((*IEX* or *Invoke-Expression*) and (*http* or *https*) and *Invoke-MalDoc* and (*`\* or *`$* or *`n*))
    or (*Remove-Item* and (*$env\:TEMP* or *C\:\\Users*) and *-ErrorAction Ignore*)
)
```

### T1566.002 - Phishing: Spearphishing Link
#### Description:

Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

#### Kibana Query Language Code (KQL):
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational"
and event.code: 1
and process.name: "powershell.exe"
and process.command_line: (*Add-Type* and *System.Windows.Forms* and *SendKeys* and *ToBase64String*)
```