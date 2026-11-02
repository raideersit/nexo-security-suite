$ErrorActionPreference = 'Continue'
$out = '\\vboxsvr\stage\inst.txt'
Remove-Item $out -ErrorAction SilentlyContinue
function Log($t) { ($t | Out-String).TrimEnd() | Out-File $out -Append -Encoding utf8 }
$script = '\\vboxsvr\stage\nexo-service.ps1'

Log '== admin?'
Log ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Log '== limpieza previa (servicio instalado con el instalador defectuoso)'
try { & $script -Accion desinstalar 2>&1 | ForEach-Object { Log "$_" } } catch { Log ('desinstalar: ' + $_.Exception.Message) }
Remove-Item 'C:\Program Files\Nexo' -Recurse -Force -ErrorAction SilentlyContinue
Log '== 1.3 instalar desde carpeta modificable (C:\src) -> debe negarse'
New-Item -ItemType Directory -Force C:\src\svc | Out-Null
Copy-Item \\vboxsvr\stage\svc\* C:\src\svc -Recurse -Force
try { & $script -Accion instalar -Ruta 'C:\src\svc\nexo-service.exe' 2>&1 | ForEach-Object { Log "$_" } } catch { Log ('NEGADO: ' + $_.Exception.Message) }
Log ('servicio existe tras 1.3: ' + [bool](Get-Service NexoService -ErrorAction SilentlyContinue))

Log '== copia a Program Files'
New-Item -ItemType Directory -Force 'C:\Program Files\Nexo' | Out-Null
Copy-Item \\vboxsvr\stage\svc  'C:\Program Files\Nexo\service' -Recurse -Force
Copy-Item \\vboxsvr\stage\tray 'C:\Program Files\Nexo\tray'    -Recurse -Force

Log '== 1.1 instalar'
try { & $script -Accion instalar -Ruta 'C:\Program Files\Nexo\service\nexo-service.exe' -Bandeja 'C:\Program Files\Nexo\tray\nexo-tray.exe' 2>&1 | ForEach-Object { Log "$_" } } catch { Log ('EXCEPCION: ' + $_ | Out-String) }
Log '== estado'
try { & $script -Accion estado 2>&1 | ForEach-Object { Log "$_" } } catch { Log ('EXCEPCION: ' + $_) }

Log '== 1.2 icacls ProgramData\Nexo'
Log (icacls "$env:ProgramData\Nexo" 2>&1)

Log '== 2.1 arrancar'
try { Start-Service NexoService -ErrorAction Stop; Start-Sleep 5 } catch { Log ('FALLO arranque: ' + $_.Exception.Message) }
Log (Get-Service NexoService | Format-List Name,Status,StartType | Out-String)
Log (Get-CimInstance Win32_Service -Filter "Name='NexoService'" | Select-Object StartName,PathName | Format-List | Out-String)
Log '== 2.2 vault'
Log (Get-ChildItem "$env:ProgramData\Nexo\Vault" -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName,Length | Out-String)
Log '== eventos'
Log (Get-WinEvent -LogName Application -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object ProviderName -match 'Nexo' | Select-Object TimeCreated,Message | Format-List | Out-String)

Log '== 2.3 matar proceso, esperar 15 s'
$p0 = (Get-Process nexo-service -ErrorAction SilentlyContinue).Id
Stop-Process -Name nexo-service -Force -ErrorAction SilentlyContinue
Start-Sleep 15
$p1 = (Get-Process nexo-service -ErrorAction SilentlyContinue).Id
Log "PID antes=$p0  PID despues=$p1  estado=$((Get-Service NexoService).Status)"
Log '== fin'


