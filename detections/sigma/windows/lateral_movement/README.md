KQL code

T1021.002:
    (winlog.channel:"Security" and event.code:5140 and winlog.event_data.ShareName:"\\\\*\\ADMIN$") or (winlog.channel:"Security" and event.code:5140 and winlog.event_data.ShareName:"\\\\*\\C$")

