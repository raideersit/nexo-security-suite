$d = 'C:\grande'
New-Item -ItemType Directory -Force $d | Out-Null
$r = New-Object Random 42
$buf = New-Object byte[] (512KB)
1..400 | ForEach-Object { $r.NextBytes($buf); [IO.File]::WriteAllBytes("$d\f$_.bin", $buf) }
'archivos: ' + (Get-ChildItem $d).Count
