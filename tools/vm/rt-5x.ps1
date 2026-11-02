# Enciende el tiempo real vigilando C:\Users\Public\prueba y dispara la deteccion de EICAR (guion 5.1). Ejecutar en PowerShell ADMIN.
$cfg = 'C:\Program Files\Nexo\service\appsettings.json'
Copy-Item $cfg "$cfg.orig" -Force
if (-not (Get-Process clamd -ErrorAction SilentlyContinue)) {
    Start-Process 'C:\clam\clamd.exe' -ArgumentList '-c C:\clam\clamd.conf' -WindowStyle Minimized
    Start-Sleep 25
}
$carpeta = 'C:\Users\Public\prueba'
New-Item -ItemType Directory $carpeta -Force | Out-Null
$c = @{ Nexo = @{ PipeName = 'NexoIpc'; Limpieza = @{ Modo = 'papelera' }; TiempoReal = @{ Activo = $true; Fuente = 'watcher'; Raices = $carpeta } }; Logging = @{ LogLevel = @{ Default = 'Warning' } } }
$c | ConvertTo-Json -Depth 5 | Set-Content $cfg -Encoding utf8
Restart-Service NexoService -Force
Start-Sleep 8
Write-Host ('Servicio: ' + (Get-Service NexoService).Status)

Remove-Item "$carpeta\eicar.com" -ErrorAction SilentlyContinue
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
[IO.File]::WriteAllText("$carpeta\eicar.com", $eicar)
Write-Host ('eicar.com creado, bytes: ' + (Get-Item "$carpeta\eicar.com").Length)
Write-Host 'Espera 10 s y mira la bandeja del usuario estandar (icono rojo + globo).'
