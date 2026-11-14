# Comprueba, DESPUES de cerrar sesion y volver a entrar, que la bandeja de Nexo arranco sola con Windows.
# Solo LEE (no instala, no arranca, no cambia nada). No necesita administrador.
# ASCII puro a proposito (Windows PowerShell 5.1 lee mal el UTF-8 sin BOM).
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\prueba-bandeja-inicio.ps1
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NexoToken {
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acceso, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int clase, out int valor, int largo, out int devuelto);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acceso, bool heredar, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    // 1 = elevado, 0 = no elevado, -1 = no se pudo saber (p. ej. proceso de otro usuario o protegido)
    public static int Elevado(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);              // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) return -1;
        try {
            IntPtr t;
            if (!OpenProcessToken(h, 0x0008, out t)) return -1;  // TOKEN_QUERY
            try {
                int valor, dev;
                if (!GetTokenInformation(t, 20, out valor, 4, out dev)) return -1;   // TokenElevation
                return valor != 0 ? 1 : 0;
            } finally { CloseHandle(t); }
        } finally { CloseHandle(h); }
    }
}
'@

$ok = $true
function Linea([bool]$bien, [string]$texto) { if (-not $bien) { $script:ok = $false }; ('  [{0}] {1}' -f $(if ($bien) { 'OK ' } else { 'MAL' }), $texto) }

$exe = 'C:\Program Files\Nexo\tray\nexo-tray.exe'
"Sesion: $env:USERDOMAIN\$env:USERNAME  (sesion de Windows n.o $([Diagnostics.Process]::GetCurrentProcess().SessionId))"

# 1) El registro del arranque
$run = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).NexoTray
Linea ($run -eq ('"' + $exe + '"')) ("Arranque registrado en HKLM\...\Run\NexoTray = " + $run)

# 2) La bandeja corre, desde la carpeta protegida
$ses = [Diagnostics.Process]::GetCurrentProcess().SessionId
$t = @(Get-Process -Name 'nexo-tray' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $ses })
Linea ($t.Count -eq 1) ("Hay exactamente 1 bandeja en esta sesion (hay " + $t.Count + ")")
if ($t.Count -ge 1) {
    $p = $t[0]
    $ruta = try { $p.Path } catch { $null }
    Linea ($ruta -eq $exe) ("Corre desde la carpeta protegida: " + $ruta)

    # 3) NO elevada: la bandeja del arranque no debe tener privilegios de administrador (solo pide UAC cuando hace falta)
    $el = [NexoToken]::Elevado($p.Id)
    Linea ($el -eq 0) ("NO esta elevada (resultado: " + $(if ($el -eq 1) { 'ELEVADA' } elseif ($el -eq 0) { 'no elevada' } else { 'no se pudo saber' }) + ")")

    # 4) La lanzo el inicio de sesion, no una persona: arranco poco despues de explorer.exe y su padre fue el shell
    $expl = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $ses } | Sort-Object StartTime)
    if ($expl.Count -ge 1) {
        $seg = ($p.StartTime - $expl[0].StartTime).TotalSeconds
        Linea (($seg -ge -5) -and ($seg -le 300)) ("Arranco " + [math]::Round($seg, 0) + " s despues de explorer.exe (se espera 0-300 s si fue el inicio de sesion)")
    } else { Linea $false 'No encuentro explorer.exe en esta sesion' }
    $papa = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $p.Id) -ErrorAction SilentlyContinue
    if ($papa) {
        $pp = Get-Process -Id $papa.ParentProcessId -ErrorAction SilentlyContinue
        "  (info) proceso padre: " + $(if ($pp) { $pp.ProcessName + ' (' + $pp.Id + ')' } else { 'ya no existe (normal con el arranque por Run)' })
    }
    "  (info) iniciada: " + $p.StartTime + "   responde: " + $p.Responding
}

# 5) El servicio (solo informa: por omision es de inicio manual)
$s = Get-Service -Name NexoService -ErrorAction SilentlyContinue
if ($s) { "  (info) servicio NexoService: " + $s.Status + ", inicio " + $s.StartType } else { Linea $false 'El servicio NexoService no esta instalado' }

''
if ($ok) { 'RESULTADO: la bandeja arranco sola, desde Program Files y sin privilegios.' } else { 'RESULTADO: hay algo MAL (ver las lineas [MAL]).' }
