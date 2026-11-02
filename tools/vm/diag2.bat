@echo off
sc query NexoService > C:\Users\nexo\diag2.txt 2>&1
sc qc NexoService >> C:\Users\nexo\diag2.txt 2>&1
dir "C:\Program Files\Nexo\service\nexo-service.exe" "C:\Program Files\Nexo\service\appsettings.json" >> C:\Users\nexo\diag2.txt 2>&1
wevtutil qe System /c:6 /rd:true /f:text /q:"*[System[Provider[@Name='Service Control Manager']]]" >> C:\Users\nexo\diag2.txt 2>&1
