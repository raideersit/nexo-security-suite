$d = 'C:\prueba'
New-Item -ItemType Directory -Force "$d\sub" | Out-Null
try { Add-MpPreference -ExclusionPath $d -ErrorAction Stop; 'exclusion Defender: ok' } catch { 'exclusion Defender: FALLO ' + $_.Exception.Message }
1..20 | ForEach-Object { Set-Content "$d\limpio$_.txt" ("archivo limpio numero $_") }
Set-Content "$d\sub\notas.txt" 'nada raro'
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
$b = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
[IO.File]::WriteAllText("$d\eicar.com.txt", $a + $b)
[IO.File]::WriteAllText("$d\sub\eicar2.txt", $a + $b)
Start-Sleep 3
Get-ChildItem $d -Recurse -File | Measure-Object | ForEach-Object { 'archivos en corpus: ' + $_.Count }
