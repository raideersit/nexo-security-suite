# Seccion 7 (tiempo real) - EJECUTAR EN POWERSHELL ADMIN. Prueba watcher y usn, aviso y carga alta.
$out = 'C:\Users\nexo\sec7.txt'
Remove-Item $out -ErrorAction SilentlyContinue
function Log($t) { ($t | Out-String).TrimEnd() | Out-File $out -Append -Encoding utf8 }
if (-not (Test-Path 'C:\Users\nexo\rpc')) { Copy-Item '\vboxsvr\stage\rpc' 'C:\Users\nexo\rpc' -Recurse }
$x = 'C:\Users\nexo\rpc\rpc.exe'
$cfgPath = 'C:\Program Files\Nexo\service\appsettings.json'
Copy-Item $cfgPath "$cfgPath.orig" -Force -ErrorAction SilentlyContinue
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Log ('admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not (Get-Process clamd -ErrorAction SilentlyContinue)) { Start-Process 'C:\clam\clamd.exe' -ArgumentList '-c C:\clam\clamd.conf' -WindowStyle Minimized; Start-Sleep 25 }
try { Add-MpPreference -ExclusionPath 'C:\rt' -ErrorAction Stop } catch { Log ('exclusion Defender: ' + $_.Exception.Message) }

function Probar($fuente) {
    Log "=============== fuente = $fuente"
    Remove-Item C:\rt -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory C:\rt | Out-Null
    $cfg = @{ Nexo = @{ PipeName = 'NexoIpc'; Limpieza = @{ Modo = 'papelera' }; TiempoReal = @{ Activo = $true; Fuente = $fuente; Raices = 'C:\rt' } }; Logging = @{ LogLevel = @{ Default = 'Warning' } } }
    $cfg | ConvertTo-Json -Depth 5 | Set-Content $cfgPath -Encoding utf8
    Restart-Service NexoService -Force; Start-Sleep 8
    Log ('servicio: ' + (Get-Service NexoService).Status)
    Log '--- 7.0 estado inicial';  Log (& $x NexoIpc tiempo-real.estado 2>&1)
    Log '--- 7.1 crear EICAR en carpeta vigilada'
    [IO.File]::WriteAllText('C:\rt\eicar-rt.com', $eicar); Set-Content C:\rt\limpio.txt 'hola'
    Start-Sleep 10
    Log (& $x NexoIpc tiempo-real.estado 2>&1)
    Log (& $x NexoIpc tiempo-real.detecciones 2>&1)
    Log '--- 7.2 carga alta: 3000 archivos'
    $t = Get-Date
    1..3000 | ForEach-Object { Set-Content "C:\rt\carga$_.ps1" ("contenido $_") }
    Log ('creados en ' + [int]((Get-Date) - $t).TotalSeconds + ' s')
    Start-Sleep 20
    Log (& $x NexoIpc tiempo-real.estado 2>&1)
    Log ('servicio sigue: ' + (Get-Service NexoService).Status)
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddMinutes(-3) } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Nexo' } | Select-Object -First 5 | ForEach-Object { Log ('evento: ' + $_.Message) }
}
Probar 'watcher'
Probar 'usn'

Log '--- restaurar configuracion original (tiempo real apagado)'
if (Test-Path "$cfgPath.orig") { Move-Item "$cfgPath.orig" $cfgPath -Force }
Restart-Service NexoService -Force; Start-Sleep 5
Log (& $x NexoIpc tiempo-real.estado 2>&1)
Remove-Item C:\rt -Recurse -Force -ErrorAction SilentlyContinue
Log '== fin'
