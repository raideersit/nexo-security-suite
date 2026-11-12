<#
.SYNOPSIS
  Instala, actualiza, desinstala o consulta Nexo completo (servicio, bandeja, ventana, autocompletado) en una carpeta protegida.

.DESCRIPTION
  Se ejecuta DESDE EL REPOSITORIO (publica el codigo con dotnet). Necesita PowerShell como administrador, salvo con -SoloPublicar.
  NO se ejecuta solo: nada en el repositorio lo lanza.

  instalar:
    1. Publica servicio, bandeja, ventana y el host del autocompletado (Release) en un lugar temporal.
    2. Copia todo a <Destino>\service, tray, desktop, autocompletado y extension, y copia los guiones a <Destino>\instalador.
    3. Protege <Destino>: SYSTEM y Administradores control total; Usuarios solo leer y ejecutar. Nexo eleva ejecutables (la bandeja
       pide UAC para aprobar acciones), asi que nadie sin permisos de administrador debe poder reemplazarlos.
    4. Registra el servicio (NexoService, LocalSystem, inicio MANUAL salvo -Automatico) y la bandeja en el arranque, con
       nexo-service.ps1 (que se niega si la ubicacion admite escritura a usuarios normales).
    5. Crea el acceso directo 'Nexo' en el menu Inicio (todos los usuarios) y la entrada de 'Aplicaciones' (desinstalar desde Windows).
    No activa ningun modulo opcional (todo sigue APAGADO en appsettings.json) y no arranca el servicio salvo con -Iniciar.
    El registro del autocompletado en el navegador es POR USUARIO (HKCU): al final se imprime el comando que debe ejecutar la
    persona SIN administrador (si tu cuenta de administrador es la misma de siempre, es la misma consola).

  desinstalar: para la bandeja y la ventana, quita servicio, arranque, acceso directo y la entrada de Aplicaciones, quita el registro
    del autocompletado del usuario actual y borra <Destino>. NO borra los datos (%ProgramData%\Nexo: vault y cuarentena;
    %LOCALAPPDATA%\Nexo: boveda de contrasenas) ni las copias de seguridad.

  -SoloPublicar: solo hace los pasos 1 y 2 en <Destino> (sin administrador, sin servicio, sin registro, sin permisos). Para probar.

.EXAMPLE
  .\tools\Instalador\instalar-nexo.ps1 -Accion instalar
  .\tools\Instalador\instalar-nexo.ps1 -Accion estado
  .\tools\Instalador\instalar-nexo.ps1 -Accion desinstalar
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('instalar', 'desinstalar', 'estado')][string]$Accion,
    [string]$Destino = (Join-Path $env:ProgramFiles 'Nexo'),
    [switch]$Automatico,
    [switch]$Iniciar,
    [switch]$Autocontenido,
    [switch]$SoloPublicar
)

$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Servicio = 'NexoService'
$ClaveApps = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nexo'
$Acceso = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Nexo.lnk'

function Test-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Proyectos a publicar: carpeta de salida, proyecto, y el marco (la ventana apunta a dos).
$Piezas = @(
    @{ Sub = 'service';        Proyecto = 'src\Nexo.Service\Nexo.Service.csproj';                       Marco = $null },
    @{ Sub = 'tray';           Proyecto = 'src\Nexo.Ui.Tray\Nexo.Ui.Tray.csproj';                       Marco = $null },
    @{ Sub = 'desktop';        Proyecto = 'src\Nexo.Ui.Desktop\Nexo.Ui.Desktop.csproj';                 Marco = 'net8.0-windows' },
    @{ Sub = 'autocompletado'; Proyecto = 'src\Nexo.Autocompletado.Host\Nexo.Autocompletado.Host.csproj'; Marco = $null }
)

function Publicar-Todo([string]$Preparacion) {
    foreach ($p in $Piezas) {
        $salida = Join-Path $Preparacion $p.Sub
        $pa = @('publish', (Join-Path $Repo $p.Proyecto), '-c', 'Release', '-o', $salida, '--nologo', '-v', 'q')
        if ($p.Marco) { $pa += @('-f', $p.Marco) }
        if ($Autocontenido) { $pa += @('--self-contained', 'true', '-r', 'win-x64') } else { $pa += @('--self-contained', 'false') }
        Write-Host "Publicando $($p.Sub)..."
        & dotnet @pa | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish fallo en $($p.Sub)." }
    }
    # La extension del navegador (sin compilacion): se carga 'descomprimida' desde aqui, una carpeta que un usuario normal no puede editar.
    Copy-Item -Recurse -Force (Join-Path $Repo 'src\Nexo.Autocompletado.Extension') (Join-Path $Preparacion 'extension')
    New-Item -ItemType Directory -Force -Path (Join-Path $Preparacion 'instalador') | Out-Null
    Copy-Item -Force (Join-Path $Repo 'src\Nexo.Service\Install\nexo-service.ps1') (Join-Path $Preparacion 'instalador')
    Copy-Item -Force $PSCommandPath (Join-Path $Preparacion 'instalador')
}

function Parar-Programas([string]$Carpeta) {
    foreach ($n in 'nexo-tray', 'nexo-desktop', 'nexo-autocompletar') {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and $_.Path.StartsWith($Carpeta, [StringComparison]::OrdinalIgnoreCase) } catch { $false }
        } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

if ($Accion -eq 'estado') {
    Write-Host "Destino: $Destino  ($(if (Test-Path $Destino) { 'existe' } else { 'no existe' }))"
    foreach ($s in 'service\nexo-service.exe', 'tray\nexo-tray.exe', 'desktop\nexo-desktop.exe', 'autocompletado\nexo-autocompletar.exe', 'extension\manifest.json') {
        Write-Host ("  {0,-40} {1}" -f $s, $(if (Test-Path (Join-Path $Destino $s)) { 'OK' } else { 'falta' }))
    }
    $svc = Get-Service -Name $Servicio -ErrorAction SilentlyContinue
    if ($svc) { Write-Host "Servicio: $($svc.Status), inicio $($svc.StartType)" } else { Write-Host 'Servicio: no instalado' }
    Write-Host ("Acceso directo: " + $(if (Test-Path $Acceso) { 'si' } else { 'no' }))
    Write-Host ("Entrada en Aplicaciones: " + $(if (Test-Path $ClaveApps) { 'si' } else { 'no' }))
    $host1 = Join-Path $Destino 'autocompletado\nexo-autocompletar.exe'
    if (Test-Path $host1) { Write-Host 'Autocompletado en este usuario:'; & $host1 --estado | Out-Host }
    return
}

if (-not $SoloPublicar -and -not (Test-Admin)) { throw 'Hace falta PowerShell como administrador (o usa -SoloPublicar para probar sin instalar).' }

switch ($Accion) {
    'instalar' {
        $prep = Join-Path ([IO.Path]::GetTempPath()) ('nexo-publicar-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $prep | Out-Null
        try {
            Publicar-Todo $prep

            if (-not $SoloPublicar) {
                # Actualizacion: se para lo que corre desde el destino y se quita el servicio viejo (los datos quedan).
                if (Get-Service -Name $Servicio -ErrorAction SilentlyContinue) {
                    Write-Host 'Ya habia una instalacion: se actualiza (los datos no se tocan).'
                    & (Join-Path $PSScriptRoot '..\..\src\Nexo.Service\Install\nexo-service.ps1') -Accion desinstalar | Out-Host
                }
                Parar-Programas $Destino
            }

            New-Item -ItemType Directory -Force -Path $Destino | Out-Null
            foreach ($d in 'service', 'tray', 'desktop', 'autocompletado', 'extension', 'instalador') {
                & robocopy.exe (Join-Path $prep $d) (Join-Path $Destino $d) /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
                if ($LASTEXITCODE -ge 8) { throw "robocopy fallo copiando $d (codigo $LASTEXITCODE)." }
            }
            $global:LASTEXITCODE = 0
        }
        finally { Remove-Item -Recurse -Force $prep -ErrorAction SilentlyContinue }

        if ($SoloPublicar) { Write-Host "Publicado en $Destino (sin servicio, sin permisos, sin registro)."; return }

        # Solo SYSTEM y Administradores escriben; los usuarios leen y ejecutan. Por SID: en Windows en espanol los nombres cambian.
        & icacls.exe $Destino /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'icacls fallo al proteger la carpeta.' }

        # Con una tabla hash (no una lista): una lista pasaria '-Accion' como TEXTO posicional y fallaria la validacion.
        $argsServicio = @{ Accion = 'instalar'; Ruta = (Join-Path $Destino 'service\nexo-service.exe'); Bandeja = (Join-Path $Destino 'tray\nexo-tray.exe') }
        if ($Automatico) { $argsServicio['Automatico'] = $true }
        & (Join-Path $Destino 'instalador\nexo-service.ps1') @argsServicio | Out-Host

        $ws = New-Object -ComObject WScript.Shell
        $lnk = $ws.CreateShortcut($Acceso)
        $lnk.TargetPath = Join-Path $Destino 'desktop\nexo-desktop.exe'
        $lnk.WorkingDirectory = Join-Path $Destino 'desktop'
        $lnk.Description = 'Nexo Security Suite'
        $lnk.Save()

        New-Item -Force -Path $ClaveApps | Out-Null
        $uninst = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $Destino 'instalador\instalar-nexo.ps1')`" -Accion desinstalar -Destino `"$Destino`""
        Set-ItemProperty $ClaveApps -Name DisplayName -Value 'Nexo Security Suite'
        Set-ItemProperty $ClaveApps -Name Publisher -Value 'Nexo'
        Set-ItemProperty $ClaveApps -Name InstallLocation -Value $Destino
        Set-ItemProperty $ClaveApps -Name UninstallString -Value $uninst
        Set-ItemProperty $ClaveApps -Name NoModify -Value 1 -Type DWord
        Set-ItemProperty $ClaveApps -Name NoRepair -Value 1 -Type DWord

        if ($Iniciar) { Start-Service -Name $Servicio; Write-Host 'Servicio iniciado.' }

        Write-Host ''
        Write-Host "Nexo instalado en $Destino."
        Write-Host '  - Abrelo desde el menu Inicio: 'Nexo'.'
        Write-Host '  - El servicio no esta iniciado ni activo en el arranque salvo que lo hayas pedido (-Iniciar, -Automatico): Start-Service NexoService'
        Write-Host '  - Autocompletado en el navegador (por usuario, SIN administrador), este comando:'
        Write-Host "      & `"$(Join-Path $Destino 'autocompletado\nexo-autocompletar.exe')`" --instalar"
        Write-Host "    y luego carga la extension descomprimida desde: $(Join-Path $Destino 'extension')"
    }

    'desinstalar' {
        Parar-Programas $Destino
        $svcScript = Join-Path $Destino 'instalador\nexo-service.ps1'
        if (-not (Test-Path $svcScript)) { $svcScript = Join-Path $Repo 'src\Nexo.Service\Install\nexo-service.ps1' }
        & $svcScript -Accion desinstalar | Out-Host

        # El registro del autocompletado es del usuario actual: se quita antes de borrar el exe que lo hace.
        $host1 = Join-Path $Destino 'autocompletado\nexo-autocompletar.exe'
        if (Test-Path $host1) { & $host1 --desinstalar | Out-Host }

        if (Test-Path $Acceso) { Remove-Item -Force $Acceso }
        if (Test-Path $ClaveApps) { Remove-Item -Recurse -Force $ClaveApps }
        if (Test-Path $Destino) {
            # Este guion puede estar ejecutandose desde dentro de $Destino: se borra todo lo demas y, si no se puede, se avisa.
            try { Remove-Item -Recurse -Force $Destino } catch { Write-Host "No se pudo borrar todo $Destino (probablemente este guion corre desde alli): borralo a mano." }
        }
        Write-Host 'Nexo desinstalado. NO se borraron tus datos: %ProgramData%\Nexo (vault y cuarentena), %LOCALAPPDATA%\Nexo (boveda) ni las copias.'
        Write-Host 'Si registraste el autocompletado con OTRO usuario, ese usuario debe ejecutar 'nexo-autocompletar --desinstalar' antes (o quedara una entrada huerfana en su navegador).'
    }
}
