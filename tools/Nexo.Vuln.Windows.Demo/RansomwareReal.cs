using System;
using System.Diagnostics;
using System.Linq;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        /// <summary>
        /// Contra el Defender REAL de este equipo, sin administrador. Se cruza con PowerShell (<c>Get-MpPreference</c>, <c>Get-MpComputerStatus</c>
        /// y <c>Get-WinEvent</c>), que leen lo mismo por otro camino: si no coinciden, falla.
        /// </summary>
        private static void ProbarRansomwareReal()
        {
            Console.WriteLine("12. Protección contra ransomware REAL (Defender de este equipo, solo lectura)");
            DateTimeOffset ahora = DateTimeOffset.Now;
            LecturaDeCarpetasProtegidas l = LectorDeCarpetasProtegidasWindows.Leer(AnalizadorDeCarpetasProtegidas.PeriodoPorOmision, ahora);
            Console.WriteLine("      INFO: modo=" + l.ModoCrudo + ", motor=" + l.ModoDelMotor + ", tiempo real=" + l.TiempoReal + ", carpetas añadidas=" + (l.CarpetasExtra?.Count.ToString() ?? "no leídas") +
                              ", programas con permiso=" + (l.AplicacionesPermitidas?.Count.ToString() ?? "no leídos") + ", eventos=" + l.Eventos.Count + ", descartados=" + l.Descartados);
            foreach (string n in l.NoLeido) Console.WriteLine("        ! " + n);

            string ps = Powershell(
                "$p=Get-MpPreference; $s=Get-MpComputerStatus; $d=(Get-Date).AddDays(-30); " +
                "$b=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1123,1124,1127,1128; StartTime=$d} -ErrorAction SilentlyContinue).Count; " +
                "$c=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5007; StartTime=$d} -ErrorAction SilentlyContinue).Count; " +
                "'' + $p.EnableControlledFolderAccess + '|' + $s.AMRunningMode + '|' + $s.RealTimeProtectionEnabled + '|' + $b + '|' + $c + '|' + (@($p.ControlledFolderAccessAllowedApplications) -join ';')");
            string[] x = ps.Trim().Split('|');
            Console.WriteLine("      INFO: PowerShell dice: " + ps.Trim());
            if (x.Length < 6) { Check(false, "PowerShell respondió algo entendible", ps); return; }

            Check(l.ModoCrudo?.ToString() == x[0], "el modo del acceso controlado a carpetas coincide con Get-MpPreference (" + x[0] + ")");
            Check(l.ModoDelMotor == x[1], "el modo del motor coincide con Get-MpComputerStatus (" + x[1] + ")");
            Check(l.TiempoReal?.ToString() == x[2], "la protección en tiempo real coincide (" + x[2] + ")");
            int bloqueos = l.Eventos.Count(e => e.Id is 1123 or 1124 or 1127 or 1128), cambios = l.Eventos.Count(e => e.Id == 5007);
            // Los eventos pueden crecer entre las dos lecturas (Defender escribe 5007 a menudo): se admite que PowerShell, que lee DESPUES, vea alguno más.
            Check(bloqueos <= int.Parse(x[3]) && int.Parse(x[3]) - bloqueos <= 2, "bloqueos leídos = los de Get-WinEvent (" + bloqueos + " vs " + x[3] + ")");
            Check(cambios <= int.Parse(x[4]) && int.Parse(x[4]) - cambios <= 5 && l.Descartados == 0, "cambios de configuración (5007) = los de Get-WinEvent, ninguno descartado (" + cambios + " vs " + x[4] + ")");
            bool psSinAdmin = x[5].StartsWith("N/A", StringComparison.OrdinalIgnoreCase);
            Check(psSinAdmin == (l.AplicacionesPermitidas is null), "programas con permiso: Nexo dice «no leídos» exactamente cuando Windows no los da (" + (psSinAdmin ? "sin administrador" : "leídos") + ")");

            ResultadoDeAnalisis a = AnalizadorDeCarpetasProtegidas.Analizar(l);
            Console.WriteLine("      INFO: " + a.Hallazgos.Count + " hallazgo(s), completo=" + a.Completo + ", relevantes=" + AnalizadorDeCarpetasProtegidas.Relevantes(l));
            foreach (HallazgoDeSistema h in a.Hallazgos) Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));
            foreach (string n in a.NoEvaluado) Console.WriteLine("        ! " + n);
            if (x[0] == "0" && x[1] == "Normal")
                Check(a.Hallazgos.Any(h => h.Id == "CFA-APAGADO"), "en este equipo está apagado: se avisa (Media)");
            if (x[0] == "1")
                Check(a.Hallazgos.Any(h => h.Id == "CFA-ACTIVO"), "en este equipo está activado: se dice");
        }

        private static string Powershell(string comando)
        {
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"" + comando.Replace("\"", "\\\"") + "\"")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using Process p = Process.Start(psi)!;
            string salida = p.StandardOutput.ReadToEnd();
            p.WaitForExit(60_000);
            return salida;
        }
    }
}
