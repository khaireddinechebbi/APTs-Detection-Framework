KQL code

T1573 (ES|QL):
    from logs-* | where event.code == 3 and destination.port in (443,8443,9443) and not process.executable in ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","C:\\Program Files\\Mozilla Firefox\\firefox.exe","C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe","C:\\Windows\\System32\\svchost.exe","C:\\Windows\\System32\\lsass.exe")


