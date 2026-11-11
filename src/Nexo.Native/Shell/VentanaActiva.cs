using System;
using System.Runtime.InteropServices;

namespace Nexo.Native.Shell
{
    /// <summary>El proceso dueño de la ventana en primer plano (para no vigilar como «segundo plano» un juego a pantalla completa).</summary>
    public static class VentanaActiva
    {
        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr ventana, out uint pid);

        /// <summary>PID del proceso en primer plano, o -1 si no se puede saber (escritorio bloqueado, sin ventana).</summary>
        public static int PidEnPrimerPlano()
        {
            try
            {
                IntPtr h = GetForegroundWindow();
                if (h == IntPtr.Zero) return -1;
                GetWindowThreadProcessId(h, out uint pid);
                return pid == 0 ? -1 : (int)pid;
            }
            catch { return -1; }
        }
    }
}
