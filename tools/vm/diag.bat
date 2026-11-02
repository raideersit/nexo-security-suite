@echo off
dir C:\Users\nexo > C:\Users\nexo\diag.txt 2>&1
schtasks /query /tn s6 /v /fo list >> C:\Users\nexo\diag.txt 2>&1
tasklist >> C:\Users\nexo\diag.txt 2>&1
