<#
.SYNOPSIS
  Instala, desinstala o consulta Nexo Service y, si se indica, la bandeja. Requiere PowerShell como administrador.

.DESCRIPTION
  NO se ejecuta solo: nada en el repositorio lo lanza. Pruebalo primero en una VM
  (snapshot 'limpia'). El servicio corre como LocalSystem; ver Salida 0, §2.

  Instalar deja el servicio en inicio MANUAL (-Automatico lo cambia) y no lo arranca.
  El vault (%ProgramData%\Nexo\Vault) y la cuarentena guardan datos del equipo: se restringen a
  SYSTEM y Administradores.

  -Bandeja <ruta a nexo-tray.exe> ademas la registra para arrancar con Windows en cada usuario
  (HKLM\...\Run). La bandeja se relanza ELEVADA (aviso de UAC) para aprobar acciones, asi que su
  carpeta no puede ser modificable por un usuario normal: si lo es, el script se niega, igual que
  con el servicio (quien pudiera cambiar ese .exe ejecutaria codigo como administrador).

.EXAMPLE
  dotnet publish src\Nexo.Service -c Release -o "C:\Program Files\Nexo\service"
  dotnet publish src\Nexo.Ui.Tray -c Release -o "C:\Program Files\Nexo\tray"
  .\nexo-service.ps1 -Accion instalar -Ruta "C:\Program Files\Nexo\service\nexo-service.exe" -Bandeja "C:\Program Files\Nexo\tray\nexo-tray.exe"
  Start-Service NexoService
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('instalar', 'desinstalar', 'estado')][string]$Accion,
    [string]$Ruta,
    [string]$Bandeja,
    [switch]$Automatico
)

$ErrorActionPreference = 'Stop'
$Nombre = 'NexoService'
$ClaveRun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$ValorRun = 'NexoTray'

function Test-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Un ejecutable que se va a lanzar con permisos altos no debe poder reemplazarlo un usuario normal.
# Se rechaza si el archivo o su carpeta permiten escribir/borrar/cambiar permisos a Users, Everyone o Authenticated Users.
function Assert-UbicacionSegura([string]$Exe, [string]$Para) {
    $objetivos = @($Exe, (Split-Path $Exe))
    foreach ($o in $objetivos) {
        $abierta = (Get-Acl -LiteralPath $o).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -match '(BUILTIN\\Users|Everyone|Authenticated Users|NT AUTHORITY\\INTERACTIVE)$' -and
            $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|Delete|ChangePermissions|TakeOwnership'
        }
        if ($abierta) {
            throw "$o admite escritura a usuarios normales: quien lo edite podria ejecutar codigo con permisos altos ($Para). Instala en una carpeta como C:\Program Files\Nexo."
        }
    }
}

if ($Accion -ne 'estado' -and -not (Test-Admin)) {
    throw 'Hace falta PowerShell como administrador.'
}

switch ($Accion) {
    'instalar' {
        if (-not $Ruta) { throw 'Indica -Ruta con la ruta completa de nexo-service.exe.' }
        $Ruta = (Resolve-Path -LiteralPath $Ruta).Path
        if ($Ruta -notmatch '\.exe$') { throw 'La ruta debe ser un .exe.' }
        if (Get-Service -Name $Nombre -ErrorAction SilentlyContinue) {
            throw "El servicio $Nombre ya existe. Desinstalalo antes."
        }

        Assert-UbicacionSegura $Ruta 'el servicio corre como SYSTEM'

        if ($Bandeja) {
            $Bandeja = (Resolve-Path -LiteralPath $Bandeja).Path
            if ($Bandeja -notmatch '\.exe$') { throw 'La ruta de la bandeja debe ser un .exe.' }
            Assert-UbicacionSegura $Bandeja 'la bandeja se relanza elevada para aprobar acciones'
        }

        $inicio = if ($Automatico) { 'auto' } else { 'demand' }
        & sc.exe create $Nombre binPath= "`"$Ruta`"" start= $inicio obj= LocalSystem DisplayName= 'Nexo Security Suite' | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'sc create fallo.' }
        & sc.exe description $Nombre 'Higiene y monitoreo de seguridad. Complementa a Windows Defender.' | Out-Null
        # Si se cae, que Windows lo reinicie (a los 5 s, 30 s y 60 s), y que reinicie el contador al dia.
        & sc.exe failure $Nombre reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null

        # %ProgramData%\Nexo guarda el vault y la cuarentena (esta ultima lleva las claves junto a los archivos):
        # solo SYSTEM y Administradores. Si un usuario normal pudiera escribir ahi, fabricaria una entrada de
        # cuarentena valida y haria que "restaurar" escribiera donde quisiera.
        $datos = Join-Path $env:ProgramData 'Nexo'
        foreach ($sub in 'Vault', 'Quarantine') { New-Item -ItemType Directory -Force -Path (Join-Path $datos $sub) | Out-Null }
        & icacls.exe $datos /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

        if ($Bandeja) {
            Set-ItemProperty -Path $ClaveRun -Name $ValorRun -Value "`"$Bandeja`"" -Type String
            Write-Host "Bandeja registrada para arrancar con Windows: $Bandeja"
        }
        else {
            Write-Host 'Sin -Bandeja: no habra icono ni aviso de detecciones, y aprobar acciones exigira otra consola de administrador.'
        }

        Write-Host "Instalado ($inicio). Arrancalo con: Start-Service $Nombre"
    }

    'desinstalar' {
        $s = Get-Service -Name $Nombre -ErrorAction SilentlyContinue
        if (-not $s) { Write-Host "$Nombre no esta instalado." }
        else {
            if ($s.Status -ne 'Stopped') { Stop-Service -Name $Nombre -Force }
            & sc.exe delete $Nombre | Out-Host
        }
        if (Get-ItemProperty -Path $ClaveRun -Name $ValorRun -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $ClaveRun -Name $ValorRun
            Write-Host 'Bandeja quitada del arranque.'
        }
        Write-Host 'Desinstalado. El vault y la cuarentena no se borran.'
    }

    'estado' {
        $s = Get-Service -Name $Nombre -ErrorAction SilentlyContinue
        if ($s) { $s | Format-Table Name, Status, StartType -AutoSize } else { Write-Host "$Nombre no esta instalado." }
        $r = Get-ItemProperty -Path $ClaveRun -Name $ValorRun -ErrorAction SilentlyContinue
        if ($r) { Write-Host "Bandeja en el arranque: $($r.$ValorRun)" } else { Write-Host 'La bandeja no esta en el arranque.' }
    }
}
