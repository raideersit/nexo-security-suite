# Prueba puntual: activa el modulo Comportamiento en el servicio instalado, genera actividad y deja el resultado a la vista.
# Ejecutar como administrador:  powershell -NoProfile -ExecutionPolicy Bypass -File <esta ruta> [-Restaurar]
param([switch]$Restaurar)
$ErrorActionPreference = 'Stop'
$f = 'C:\Program Files\Nexo\service\appsettings.json'
$bak = $f + '.bak'

if ($Restaurar) {
    if (-not (Test-Path $bak)) { Write-Host 'No hay copia (.bak): nada que restaurar.'; exit 1 }
    Copy-Item $bak $f -Force
    Remove-Item $bak -Force
    Restart-Service NexoService
    Get-Service NexoService | Out-Host
    Write-Host 'Restaurado: Comportamiento vuelve a estar apagado.'
    exit 0
}

Copy-Item $f $bak -Force
$texto = Get-Content $f -Raw
$nuevo = $texto -replace '("Comportamiento":\s*\{\s*"Activo":\s*)false', '${1}true'
if ($nuevo -eq $texto) { Write-Host 'No cambio nada (ya estaba activo o el formato es distinto).' }
[IO.File]::WriteAllText($f, $nuevo, (New-Object Text.UTF8Encoding($false)))
Select-String -Path $f -Pattern '"Comportamiento"' -Context 0,2 | Out-Host
Restart-Service NexoService
Start-Sleep 5
Get-Service NexoService | Out-Host

# Actividad de prueba (se deshace sola)
$ini = [Environment]::GetFolderPath('Startup')
if (-not $ini) { throw 'No pude leer la carpeta Inicio.' }
$arch = Join-Path $ini 'nexo-prueba-etw.txt'
Set-Content -LiteralPath $arch -Value 'prueba'
try { $c = New-Object Net.Sockets.TcpClient('1.1.1.1', 443); $c.Close() } catch { Write-Host 'Sin red: la conexion no se pudo abrir (no importa).' }
sc.exe create NexoPruebaEtw binPath= 'C:\Windows\System32\cmd.exe' | Out-Null
Start-Sleep 1
sc.exe delete NexoPruebaEtw | Out-Null
Start-Sleep 3
Remove-Item -LiteralPath $arch -Force
Write-Host 'Listo. Ahora abre la ventana de Nexo, seccion Comportamiento, y pulsa revisar.'
