# Seccion 6 (limpieza por el servicio con suplantacion) + 5.2/5.5 (previsualizar cuarentena). Como usuario estandar, SIN elevar.
$out = 'C:\Users\nexo\sec6.txt'
Remove-Item $out -ErrorAction SilentlyContinue
function Log($t) { ($t | Out-String).TrimEnd() | Out-File $out -Append -Encoding utf8 }
if (-not (Test-Path 'C:\Users\nexo\rpc')) { Copy-Item '\vboxsvr\stage\rpc' 'C:\Users\nexo\rpc' -Recurse }
$x = 'C:\Users\nexo\rpc\rpc.exe'
function Papelera { $sh = New-Object -ComObject Shell.Application; $sh.NameSpace(10).Items().Count }
Log ('usuario: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + '  servicio: ' + (Get-Service NexoService).Status)

Log '--- 6.0 reglas'
$reglas = & $x NexoIpc limpieza.reglas 2>&1; Log $reglas
$cfg = Get-Content 'C:\Program Files\Nexo\service\appsettings.json' -Raw -ErrorAction SilentlyContinue; Log ('modo en appsettings: ' + ($cfg -match '"Modo":\s*"(\w+)"' | ForEach-Object { $Matches[1] }))

# basura sintetica: 60 thumbcache viejos
$d = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
New-Item -ItemType Directory -Force $d | Out-Null
1..60 | ForEach-Object { $f = "$d\thumbcache_9$_.db"; Set-Content $f ('x' * 2048); (Get-Item $f).LastWriteTime = (Get-Date).AddDays(-3) }
Log ("creados: " + (Get-ChildItem $d -Filter 'thumbcache_9*.db').Count)
$testigo = 'C:\prueba\limpio1.txt'

Log '--- 6.1 previsualizar (solo perfil de nexo)'
$prev = & $x NexoIpc limpieza.previsualizar 2>&1; Log $prev
$tot = ($prev | ConvertFrom-Json -ErrorAction SilentlyContinue)
if ($tot) { Log ('total_archivos=' + $tot.total_archivos + '  fuera del perfil: ' + @($tot.ejemplos | Where-Object { $_.ruta -notlike 'C:\Users\nexo\*' }).Count) }

Log '--- 6.3 regla inventada y ruta ajena -> error'
Log (& $x NexoIpc limpieza.previsualizar "{'reglas':['../../Windows']}" 2>&1)
Log (& $x NexoIpc limpieza.previsualizar "{'reglas':['regla-que-no-existe']}" 2>&1)
Log (& $x NexoIpc limpieza.aplicar "{'token':'inventado'}" 2>&1)

Log '--- 6.2 aplicar (modo del servicio)'
$p0 = Papelera
$r = & $x NexoIpc flujo limpieza.previsualizar limpieza.aplicar 2>&1; Log $r
Start-Sleep 2
$p1 = Papelera
Log ("Papelera de nexo: antes=$p0 despues=$p1 ; thumbcache restantes: " + (Get-ChildItem $d -Filter 'thumbcache_9*.db' -ErrorAction SilentlyContinue).Count)
Log ("testigo fuera del catalogo intacto: " + (Test-Path $testigo))
Log ('token reutilizado -> ' + (& $x NexoIpc limpieza.aplicar "{'token':'inventado'}" 2>&1))

Log '--- 5.2 previsualizar cuarentena (no mueve nada)'
$ini = & $x NexoIpc escaneo.iniciar "{'rutas':['C:\\prueba']}" 2>&1; Log $ini
$id = ($ini | ConvertFrom-Json).id
Start-Sleep 6
Log (& $x NexoIpc escaneo.resultado ("{'id':'$id'}") 2>&1)
$q = & $x NexoIpc cuarentena.previsualizar ("{'escaneo':'$id'}") 2>&1; Log $q
Log ('eicar sigue en su sitio: ' + (Test-Path 'C:\prueba\eicar.com.txt'))
Log '--- 5.3 aplicar con token inventado (sin UAC) -> debe fallar'
Log (& $x NexoIpc cuarentena.aplicar "{'token':'inventado'}" 2>&1)
Log (& $x NexoIpc cuarentena.listar 2>&1)
Log '== fin'
