# Prueba puntual de la copia versionada con el servicio instalado. Solo usa C:\NexoPrueba (origen y destino de mentira).
# Ejecutar como administrador, UNA fase cada vez, desde esta carpeta:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\prueba-copia.ps1 -Fase preparar
#   (en la ventana de Nexo: pestana Copias, pulsar hacer copia)
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\prueba-copia.ps1 -Fase cambiar
#   (en la ventana de Nexo: otra copia)
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\prueba-copia.ps1 -Fase restaurar
param([Parameter(Mandatory = $true)][ValidateSet('preparar', 'cambiar', 'restaurar')][string]$Fase)
$ErrorActionPreference = 'Stop'
$cfg = 'C:\Program Files\Nexo\service\appsettings.json'
$bak = $cfg + '.copia.bak'
$raiz = 'C:\NexoPrueba'
$origen = Join-Path $raiz 'origen'
$destino = Join-Path $raiz 'copia'

if ($Fase -eq 'preparar') {
    if (Test-Path $bak) { throw 'Ya hay una preparacion en curso (.copia.bak). Ejecuta primero -Fase restaurar.' }
    New-Item -ItemType Directory -Force -Path $origen, $destino | Out-Null
    Set-Content -LiteralPath (Join-Path $origen 'a.txt') -Value 'contenido A, version 1'
    Set-Content -LiteralPath (Join-Path $origen 'b.txt') -Value 'contenido B, version 1'
    New-Item -ItemType Directory -Force -Path (Join-Path $origen 'sub') | Out-Null
    Set-Content -LiteralPath (Join-Path $origen 'sub\c.txt') -Value 'contenido C, version 1'
    Copy-Item $cfg $bak -Force
    $texto = Get-Content $cfg -Raw
    $bloque = '"Copia": { "Activo": true, "Destino": "C:\\NexoPrueba\\copia", "Versiones": 3, "CadaHoras": 0, "Carpetas": "C:\\NexoPrueba\\origen" }'
    $nuevo = [regex]::Replace($texto, '"Copia":\s*\{[^}]*\}', $bloque.Replace('$', '$$'))
    if ($nuevo -eq $texto) { throw 'No pude cambiar la seccion Copia.' }
    [IO.File]::WriteAllText($cfg, $nuevo, (New-Object Text.UTF8Encoding($false)))
    Restart-Service NexoService
    Start-Sleep 8
    Get-Service NexoService | Out-Host
    Write-Host 'Preparado: origen con 3 archivos. Ahora, en Nexo > Copias, pulsa hacer copia.'
}
elseif ($Fase -eq 'cambiar') {
    Set-Content -LiteralPath (Join-Path $origen 'a.txt') -Value 'contenido A, version 2 (cambiado)'
    Remove-Item -LiteralPath (Join-Path $origen 'b.txt') -Force
    Set-Content -LiteralPath (Join-Path $origen 'd.txt') -Value 'archivo nuevo D'
    Write-Host 'Cambiado: a.txt modificado, b.txt borrado, d.txt nuevo. Ahora haz otra copia en Nexo > Copias.'
    Write-Host 'Lo que hay en el destino ahora:'
    Get-ChildItem -LiteralPath $destino -Recurse -Force | Select-Object FullName, Length | Out-Host
}
else {
    if (Test-Path $bak) {
        Copy-Item $bak $cfg -Force
        Remove-Item $bak -Force
        Restart-Service NexoService
        Start-Sleep 3
        Get-Service NexoService | Out-Host
    } else { Write-Host 'No habia copia de la configuracion (nada que restaurar ahi).' }
    if (Test-Path $raiz) { Remove-Item -LiteralPath $raiz -Recurse -Force }
    Write-Host 'Restaurado: copia apagada, carpeta de prueba borrada.'
}
