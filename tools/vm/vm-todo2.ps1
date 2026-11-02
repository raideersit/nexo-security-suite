# PowerShell ADMIN en la VM:  powershell -ep bypass -File \\vboxsvr\stage\vm-todo2.ps1
Copy-Item '\\vboxsvr\stage\vm-sec7.ps1' C:\Users\nexo\ -Force
Remove-Item C:\Users\nexo\sec7.txt -ErrorAction SilentlyContinue
& powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\nexo\vm-sec7.ps1
Copy-Item C:\Users\nexo\sec7.txt '\\vboxsvr\stage\sec7.txt' -Force
'TERMINADO'