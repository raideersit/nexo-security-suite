schtasks /create /tn s6 /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\nexo\vm-sec6.ps1" /sc once /st 00:00 /it /f
schtasks /run /tn s6
