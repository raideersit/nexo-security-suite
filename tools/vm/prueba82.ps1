$env:DOTNET_ROOT = 'C:\Users\nexo\dotnet'
$exe = 'C:\Users\nexo\scanrun\nexo-scan.exe'
$out = 'Z:\res82.txt'
function Log($t) { $t | Out-File $out -Append -Encoding utf8 }
Remove-Item $out -ErrorAction SilentlyContinue

Log '== estado'
Log ((& $exe estado) -join "`n")

foreach ($p in 1, 4) {
    Log "== 8.3 escaneo normal --paralelo $p"
    $t = Measure-Object -InputObject 0 | Out-Null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $o = & $exe escanear C:\grande --paralelo $p
    $sw.Stop()
    Log ($o -join "`n")
    Log ("exit=$LASTEXITCODE  reloj={0:N1}s" -f $sw.Elapsed.TotalSeconds)
}

Log '== 8.2 matar clamd a mitad de escaneo'
$job = Start-Job { $env:DOTNET_ROOT = 'C:\Users\nexo\dotnet'; $o = & 'C:\Users\nexo\scanrun\nexo-scan.exe' escanear C:\grande --paralelo 1; $o; "exit=$LASTEXITCODE" }
Start-Sleep -Seconds 4
Stop-Process -Name clamd -Force
Log 'clamd matado a los 4 s'
Wait-Job $job -Timeout 180 | Out-Null
Log ((Receive-Job $job) -join "`n")
Log '== fin'
