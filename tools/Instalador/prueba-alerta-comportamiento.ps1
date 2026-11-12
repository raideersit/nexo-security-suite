# Prueba puntual: un "programa" sin firma valida, en Descargas, que escribe en Inicio y abre una conexion.
# Debe dar una alerta ALTA en la seccion Comportamiento (con el modulo activo). Todo se borra al final.
# Uso:  powershell -NoProfile -ExecutionPolicy Bypass -File <esta ruta>
$ErrorActionPreference = 'Stop'
$desc = Join-Path $env:USERPROFILE 'Downloads'
$falso = Join-Path $desc 'nexo-prueba-alerta.exe'
$ini = [Environment]::GetFolderPath('Startup')
if (-not $ini -or -not (Test-Path $desc)) { throw 'No encuentro Descargas o Inicio.' }
$arch = Join-Path $ini 'nexo-prueba-alerta.txt'
try {
    # Copia de powershell.exe con 1 byte anadido: la firma deja de ser valida.
    Copy-Item (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') $falso -Force
    $fs = [IO.File]::Open($falso, 'Append'); $fs.WriteByte(0); $fs.Close()
    $guion = "Set-Content -LiteralPath '$arch' -Value prueba; try { `$c = New-Object Net.Sockets.TcpClient('1.1.1.1',443); `$c.Close() } catch {}; Start-Sleep -Seconds 8"
    $p = Start-Process -FilePath $falso -ArgumentList @('-NoProfile', '-Command', $guion) -PassThru -WindowStyle Hidden
    $p.WaitForExit(40000) | Out-Null
    Start-Sleep 3
    Write-Host 'Hecho. Abre Nexo > Seguridad > Revisar todo y mira la seccion Comportamiento.'
}
finally {
    Remove-Item -LiteralPath $arch -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $falso -Force -ErrorAction SilentlyContinue
}
