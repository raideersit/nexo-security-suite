using System;
using System.Diagnostics;
using Nexo.Modules.Cleanup.Perfiles;
using Nexo.Modules.Cleanup.Windows;
using Nexo.Native.Power;
using Nexo.Native.Shell;

namespace Nexo.Cleanup.Windows.Demo
{
    public static partial class Program
    {
        /// <summary>Las señales de actividad (energía y pantalla completa) contra Windows REAL, sin administrador.</summary>
        private static void ProbarActividad()
        {
            Console.WriteLine("Perfiles de actividad: lectura REAL de energía y pantalla (sin administrador)");

            // --- Bytes inventados: la interpretación no depende de este equipo ---
            LecturaDeEnergia a = EstadoDeEnergia.Interpretar(0, 8, 55, 0);
            Check(a.Corriente == LineaDeCorriente.Desconectada && a.BateriaPorCiento == 55 && a.AhorroActivo == false && !a.SinBateria, "ACLineStatus 0 y 55 %: desconectado con 55 %");
            a = EstadoDeEnergia.Interpretar(1, 8, 100, 1);
            Check(a.Corriente == LineaDeCorriente.Conectada && a.AhorroActivo == true, "ACLineStatus 1 y ahorro activado: enchufado con el ahorro");
            a = EstadoDeEnergia.Interpretar(255, 255, 255, 2);
            Check(a.Corriente == LineaDeCorriente.Desconocida && a.BateriaPorCiento is null && a.AhorroActivo is null, "todo 255: desconocido, sin inventar un porcentaje");
            a = EstadoDeEnergia.Interpretar(1, 128, 100, 0);
            Check(a.SinBateria && a.BateriaPorCiento is null && a.Corriente == LineaDeCorriente.Conectada, "BatteryFlag 128: equipo sin batería (sin porcentaje)");
            Check(NotificacionDeUsuario.Traducir(3) == NotificacionDeUsuario.Estado.JuegoD3D && NotificacionDeUsuario.Traducir(8) == NotificacionDeUsuario.Estado.Desconocido && NotificacionDeUsuario.Traducir(99) == NotificacionDeUsuario.Estado.Desconocido
                  && NotificacionDeUsuario.Traducir(0) == NotificacionDeUsuario.Estado.Desconocido, "SHQueryUserNotificationState: 3 es juego D3D; 0 y valores raros, desconocido");
            Check(LectorDeActividadWindows.Pantalla(NotificacionDeUsuario.Estado.Ausente) == EstadoDePantalla.Ausente
                  && LectorDeActividadWindows.Pantalla(NotificacionDeUsuario.Estado.AppDeLaTienda) == EstadoDePantalla.PantallaCompleta
                  && LectorDeActividadWindows.Pantalla(NotificacionDeUsuario.Estado.AceptaAvisos) == EstadoDePantalla.Libre
                  && LectorDeActividadWindows.Pantalla(NotificacionDeUsuario.Estado.NoMolestar) == EstadoDePantalla.NoMolestar, "la traducción de pantalla: ausente, Tienda, libre y no molestar");

            // --- Lectura real y cruce con .NET (SystemInformation.PowerStatus) ---
            LecturaDeEnergia real = EstadoDeEnergia.Leer();
            Check(real.Correcta, "GetSystemPowerStatus funciona en este equipo");
            string? ps = PowerShell("Add-Type -AssemblyName System.Windows.Forms; $p=[System.Windows.Forms.SystemInformation]::PowerStatus; '' + $p.PowerLineStatus + ' ' + [int]($p.BatteryLifePercent*100)");
            Console.WriteLine("      INFO: Nexo lee corriente=" + real.Corriente + ", batería=" + (real.BateriaPorCiento?.ToString() ?? "sin dato") + " %, sin batería=" + real.SinBateria + "; .NET dice «" + ps + "»");
            if (ps is not null)
            {
                string[] p = ps.Split(' ');
                bool linea = p[0] switch { "Online" => real.Corriente == LineaDeCorriente.Conectada, "Offline" => real.Corriente == LineaDeCorriente.Desconectada, _ => real.Corriente == LineaDeCorriente.Desconocida };
                Check(linea, "la corriente coincide con la de SystemInformation.PowerStatus (" + p[0] + ")");
                if (!real.SinBateria && real.BateriaPorCiento is int b && int.TryParse(p[1], out int pb)) Check(Math.Abs(b - pb) <= 1, "el porcentaje de batería coincide (±1) con el de .NET", b + " vs " + pb);
            }
            else Check(false, "no se pudo preguntar a PowerShell para el cruce");

            // --- Pantalla: en esta prueba hay una consola/terminal en primer plano, no un juego ---
            NotificacionDeUsuario.Estado n = NotificacionDeUsuario.Leer();
            Console.WriteLine("      INFO: Windows dice que la persona está en «" + n + "»");
            Check(n != NotificacionDeUsuario.Estado.Desconocido, "SHQueryUserNotificationState responde algo");

            SenalesDeActividad s = LectorDeActividadWindows.Leer(wifiAbierto: false);
            DecisionDePerfil d = ReglasDePerfil.Decidir(s);
            Console.WriteLine("      INFO: perfil ahora = " + d.Perfil + (d.Motivos.Count > 0 ? " (" + string.Join("; ", d.Motivos) + ")" : "") + (d.NoEvaluado.Count > 0 ? " · no evaluado: " + string.Join("; ", d.NoEvaluado) : ""));
            Check(s.Energia != FuenteDeEnergia.Desconocida && s.Pantalla != EstadoDePantalla.Desconocido && d.NoEvaluado.Count == 0, "con lecturas reales no queda nada «no evaluado»");
            Check(d.PosponerTareasPesadas == (d.Perfil != Perfil.Normal), "pospone si y solo si el perfil no es Normal");
        }

        private static string? PowerShell(string guion)
        {
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -Command \"" + guion.Replace("\"", "\\\"") + "\"") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using Process? p = Process.Start(psi);
            if (p is null) return null;
            string o = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit();
            return p.ExitCode == 0 && o.Length > 0 ? o : null;
        }
    }
}
