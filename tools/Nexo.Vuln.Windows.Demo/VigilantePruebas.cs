using System;
using Microsoft.Win32;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private static void ProbarVigilanteDeSesion()
        {
            Console.WriteLine("8. Vigilante de sesión de Windows (bloquea la bóveda al bloquear la sesión o suspender)");
            foreach (SessionSwitchReason r in new[] { SessionSwitchReason.SessionLock, SessionSwitchReason.SessionLogoff, SessionSwitchReason.ConsoleDisconnect, SessionSwitchReason.RemoteDisconnect })
                Check(VigilanteDeSesionWindows.MotivoDeSesion(r) is { Length: > 10 } m && m.StartsWith("La bóveda se bloqueó porque"), "«" + r + "» bloquea la bóveda y lo explica");
            foreach (SessionSwitchReason r in new[] { SessionSwitchReason.SessionUnlock, SessionSwitchReason.SessionLogon, SessionSwitchReason.ConsoleConnect, SessionSwitchReason.RemoteConnect, SessionSwitchReason.SessionRemoteControl })
                Check(VigilanteDeSesionWindows.MotivoDeSesion(r) is null, "«" + r + "» NO bloquea nada (desbloquear o conectar no es una amenaza)");
            Check(VigilanteDeSesionWindows.MotivoDeEnergia(PowerModes.Suspend) is { } e && e.Contains("suspendió"), "suspender el equipo bloquea la bóveda");
            Check(VigilanteDeSesionWindows.MotivoDeEnergia(PowerModes.Resume) is null && VigilanteDeSesionWindows.MotivoDeEnergia(PowerModes.StatusChange) is null, "reanudar o cambiar de batería a corriente NO bloquea nada");

            // Suscripcion REAL a los eventos del sistema: no debe fallar ni lanzar nada al crearse y liberarse (dos veces seguidas es seguro).
            bool lanzo = false;
            try { using var v = new VigilanteDeSesionWindows(); v.Dispose(); v.Dispose(); } catch (Exception) { lanzo = true; }
            Check(!lanzo, "se suscribe a SystemEvents de verdad, se libera y volver a liberar es seguro");
            int avisos = 0;
            using (var v = new VigilanteDeSesionWindows()) { v.SesionAmenazada += _ => avisos++; }
            System.Threading.Thread.Sleep(300);
            Check(avisos == 0, "sin ningún evento real de sesión, no se lanza ningún aviso falso");
        }
    }
}
