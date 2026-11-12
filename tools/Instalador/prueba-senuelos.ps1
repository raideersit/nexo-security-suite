# Prueba puntual de los senuelos con el servicio instalado. Solo usa C:\NexoPrueba\senuelos.
# Ejecutar como administrador, UNA fase cada vez:
#   powershell -NoProfile -ExecutionPolicy Bypass -File <esta ruta> -Fase preparar
#   powershell -NoProfile -ExecutionPolicy Bypass -File <esta ruta> -Fase atacar
#   powershell -NoProfile -ExecutionPolicy Bypass -File <esta ruta> -Fase restaurar
param([Parameter(Mandatory = $true)][ValidateSet('preparar', 'atacar', 'restaurar')][string]$Fase)
$ErrorActionPreference = 'Stop'
$cfg = 'C:\Program Files\Nexo\service\appsettings.json'
$bak = $cfg + '.senuelos.bak'
$carpeta = 'C:\NexoPrueba\senuelos'
$registro = Join-Path $env:ProgramData 'Nexo\senuelos.json'
$marca = 'C:\NexoPrueba\registro-era-nuevo.txt'

if ($Fase -eq 'preparar') {
    if (Test-Path $bak) { throw 'Ya hay una preparacion en curso (.senuelos.bak). Ejecuta primero -Fase restaurar.' }
    New-Item -ItemType Directory -Force -Path $carpeta | Out-Null
    if (-not (Test-Path $registro)) { Set-Content -LiteralPath $marca -Value 'el registro de senuelos no existia' }
    Copy-Item $cfg $bak -Force
    $texto = Get-Content $cfg -Raw
    $bloque = '"Senuelos": { "Activo": true, "SegundosEntreRevisiones": 5, "Ocultos": false, "Carpetas": "C:\\NexoPrueba\\senuelos" }'
    $nuevo = [regex]::Replace($texto, '"Senuelos":\s*\{[^}]*\}', $bloque.Replace('$', '$$'))
    if ($nuevo -eq $texto) { throw 'No pude cambiar la seccion Senuelos.' }
    [IO.File]::WriteAllText($cfg, $nuevo, (New-Object Text.UTF8Encoding($false)))
    Restart-Service NexoService
    Start-Sleep 12
    Get-Service NexoService | Out-Host
    Write-Host 'Senuelos creados en la carpeta de prueba:'
    Get-ChildItem -LiteralPath $carpeta -Force | Select-Object Name, Length | Out-Host
    Write-Host 'Si la lista esta vacia, espera 10 segundos y mira otra vez. Luego ejecuta -Fase atacar.'
}
elseif ($Fase -eq 'atacar') {
    $archivos = @(Get-ChildItem -LiteralPath $carpeta -Force -File)
    if ($archivos.Count -lt 2) { throw 'Hay menos de 2 senuelos: todavia no se crearon.' }
    Add-Content -LiteralPath $archivos[0].FullName -Value 'cifrado por ransomware de mentira'
    Remove-Item -LiteralPath $archivos[1].FullName -Force
    Write-Host ('Modificado: ' + $archivos[0].Name)
    Write-Host ('Borrado:    ' + $archivos[1].Name)
    Start-Sleep 10
    Write-Host 'Abre Nexo > Seguridad > Revisar todo y mira la seccion de senuelos. Luego -Fase restaurar.'
}
else {
    if (Test-Path $bak) {
        Copy-Item $bak $cfg -Force
        Remove-Item $bak -Force
        Restart-Service NexoService
        Start-Sleep 3
        Get-Service NexoService | Out-Host
    } else { Write-Host 'No habia copia de la configuracion (nada que restaurar ahi).' }
    if (Test-Path $carpeta) { Remove-Item -LiteralPath $carpeta -Recurse -Force }
    if ((Test-Path $marca) -and (Test-Path $registro)) { Remove-Item -LiteralPath $registro -Force }
    if (Test-Path $marca) { Remove-Item -LiteralPath $marca -Force }
    if ((Test-Path 'C:\NexoPrueba') -and -not (Get-ChildItem 'C:\NexoPrueba' -Force)) { Remove-Item 'C:\NexoPrueba' -Force }
    Write-Host 'Restaurado: senuelos apagados, carpeta de prueba borrada.'
}
