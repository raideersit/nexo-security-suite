<#
.SYNOPSIS
  Instala, desinstala o consulta Nexo Service. Requiere PowerShell como administrador.

.DESCRIPTION
  NO se ejecuta solo: nada en el repositorio lo lanza. Pruebalo primero en una VM
  (snapshot 'limpia'). El servicio corre como LocalSystem; ver Salida 0, §2.

  Instalar deja el servicio en inicio MANUAL (-Automatico lo cambia) y no lo arranca.
  El vault (%ProgramData%\Nexo\Vault) guarda datos del equipo en texto plano: se
  restringe a SYSTEM y Administradores.

.EXAMPLE
  dotnet publish src\Nexo.Service -c Release -o C:\Nexo\service
  .\nexo-service.ps1 -Accion instalar -Ruta C:\Nexo\service\nexo-service.exe
  Start-Service NexoService
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('instalar', 'desinstalar', 'estado')][string]$Accion,
    [string]$Ruta,
    [switch]$Automatico
)

$ErrorActionPreference = 'Stop'
$Nombre = 'NexoService'

function Test-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

        # El ejecutable de un servicio LocalSystem no debe poder reemplazarlo un usuario normal:
        # eso seria una escalada de privilegios. Se avisa si la carpeta admite escritura de Users.
        $acl = Get-Acl -LiteralPath (Split-Path $Ruta)
        $abierta = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -match '(BUILTIN\\Users|Everyone|Authenticated Users)$' -and
            $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl'
        }
        if ($abierta) {
            throw "La carpeta $(Split-Path $Ruta) admite escritura a usuarios normales: quien la edite podria ejecutar codigo como SYSTEM. Instala en una carpeta como C:\Program Files\Nexo."
        }

        $inicio = if ($Automatico) { 'auto' } else { 'demand' }
        & sc.exe create $Nombre binPath= "`"$Ruta`"" start= $inicio obj= LocalSystem DisplayName= 'Nexo Security Suite' | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'sc create fallo.' }
        & sc.exe description $Nombre 'Higiene y monitoreo de seguridad. Complementa a Windows Defender.' | Out-Null
        # Si se cae, que Windows lo reinicie (a los 5 s, 30 s y 60 s), y que reinicie el contador al dia.
        & sc.exe failure $Nombre reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null

        $vault = Join-Path $env:ProgramData 'Nexo\Vault'
        New-Item -ItemType Directory -Force -Path $vault | Out-Null
        & icacls.exe (Split-Path $vault) /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

        Write-Host "Instalado ($inicio). Arrancalo con: Start-Service $Nombre"
    }

    'desinstalar' {
        $s = Get-Service -Name $Nombre -ErrorAction SilentlyContinue
        if (-not $s) { Write-Host "$Nombre no esta instalado."; break }
        if ($s.Status -ne 'Stopped') { Stop-Service -Name $Nombre -Force }
        & sc.exe delete $Nombre | Out-Host
        Write-Host 'Desinstalado. El vault no se borra.'
    }

    'estado' {
        $s = Get-Service -Name $Nombre -ErrorAction SilentlyContinue
        if ($s) { $s | Format-Table Name, Status, StartType -AutoSize } else { Write-Host "$Nombre no esta instalado." }
    }
}
