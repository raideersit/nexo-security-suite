$out = '\\vboxsvr\stage\ipc.txt'
Remove-Item $out -ErrorAction SilentlyContinue
function Log($t) { ($t | Out-String).TrimEnd() | Out-File $out -Append -Encoding utf8 }
$x = '\\vboxsvr\stage\ipccli\ipccli.exe'
if (-not (Test-Path 'C:\Users\nexo\ipccli')) { Copy-Item '\\vboxsvr\stage\ipccli' 'C:\Users\nexo\ipccli' -Recurse }
$x = 'C:\Users\nexo\ipccli\ipccli.exe'

Log ('usuario: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + '  admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Log ('servicio: ' + (Get-Service NexoService).Status)

if (-not (Get-Process clamd -ErrorAction SilentlyContinue)) {
    Start-Process 'C:\clam\clamd.exe' -ArgumentList '-c C:\clam\clamd.conf' -WindowStyle Minimized
}
for ($i = 0; $i -lt 40; $i++) { Start-Sleep 5; if (netstat -an | Select-String '3310.*LISTENING') { break } }
Log ('clamd escuchando: ' + [bool](netstat -an | Select-String '3310.*LISTENING'))

Log '--- 3.1 / estado por el servicio';            Log (& $x NexoIpc estado 2>&1)
Log '--- 5.1 escanear C:\prueba por el servicio';  Log (& $x NexoIpc escanear C:\prueba 2 2>&1)
Log '--- 3.2 pipe inexistente (servicio parado)';  Log (& $x NexoIpc-NoExiste estado 2>&1); Log "exit=$LASTEXITCODE"
Log '--- matar clamd -> debe dar -32020'
Stop-Process -Name clamd -Force -ErrorAction SilentlyContinue; Start-Sleep 2
Log (& $x NexoIpc estado 2>&1)
Log (& $x NexoIpc escanear C:\prueba 1 2>&1)
Log '== fin'
