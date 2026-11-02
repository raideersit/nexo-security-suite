# Lanzar en PowerShell ADMIN dentro de la VM:  powershell -ep bypass -File \\vboxsvr\stage\vm-todo.ps1
$dest = '\\vboxsvr\stage'
$log  = 'C:\Users\nexo\todo.txt'
Remove-Item $log, C:\Users\nexo\sec6.txt, C:\Users\nexo\sec7.txt -ErrorAction SilentlyContinue
function L($t) { ($t | Out-String).TrimEnd() | Out-File $log -Append -Encoding utf8 }
Copy-Item "$dest\rpc" C:\Users\nexo\rpc -Recurse -Force
Copy-Item "$dest\vm-sec6.ps1","$dest\vm-sec7.ps1" C:\Users\nexo\ -Force

L '== servicio'
L (sc.exe query NexoService); L (Get-Item 'C:\Program Files\Nexo\service\nexo-service.exe' | Select-Object Name, Length)
L (Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 6 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString('s') + ' ' + $_.Message })
if ((Get-Service NexoService).Status -ne 'Running') { try { Start-Service NexoService -ErrorAction Stop; Start-Sleep 6 } catch { L ('NO ARRANCA: ' + $_.Exception.Message) } }
L ('servicio ahora: ' + (Get-Service NexoService).Status)
if (-not (Get-Process clamd -ErrorAction SilentlyContinue)) { Start-Process 'C:\clam\clamd.exe' -ArgumentList '-c C:\clam\clamd.conf' -WindowStyle Minimized; Start-Sleep 25 }
if (-not (Test-Path C:\prueba\eicar.com.txt)) { & "$dest\prepara.ps1" | ForEach-Object { L $_ } }

# Seccion 6: como usuario ESTANDAR (token limitado) mediante tarea programada
L '== lanzando seccion 6 (no elevada)'
schtasks /create /tn s6 /tr 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\nexo\vm-sec6.ps1' /sc once /st 00:00 /it /rl limited /f | Out-Null
schtasks /run /tn s6 | Out-Null
for ($i = 0; $i -lt 60; $i++) { Start-Sleep 5; if ((Test-Path C:\Users\nexo\sec6.txt) -and (Select-String C:\Users\nexo\sec6.txt -Pattern '== fin' -Quiet)) { break } }
Copy-Item C:\Users\nexo\sec6.txt "$dest\sec6.txt" -Force -ErrorAction SilentlyContinue

# Seccion 7 (necesita admin)
L '== seccion 7'
& powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\nexo\vm-sec7.ps1
Copy-Item C:\Users\nexo\sec7.txt "$dest\sec7.txt" -Force -ErrorAction SilentlyContinue
L '== fin'
Copy-Item $log "$dest\todo.txt" -Force
'TERMINADO - ya puedes avisar a Claude'