using System;
using System.Threading;
using System.Windows.Forms;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Tray
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            string pipe = Argumento(args, "--pipe") ?? "NexoIpc";

            // Modo auxiliar: aplica UN plan ya aprobado. Lo abre la bandeja elevada (aviso de UAC) y termina.
            int i = Array.IndexOf(args, "--aplicar");
            if (i >= 0) return Auxiliar.Aplicar(args, i, pipe);

            // Modo de comprobacion: una consulta, escribe el resultado y sale (sin icono ni ventanas).
            if (Array.IndexOf(args, "--una-vez") >= 0) return Auxiliar.UnaVez(args, pipe);

            using var unica = new Mutex(true, "Nexo.Ui.Tray.UnicaInstancia", out bool primera);
            if (!primera) return 0;       // ya hay una bandeja en marcha

            ApplicationConfiguration.Initialize();
            using var bandeja = new Bandeja(pipe);
            Application.Run();
            return 0;
        }

        private static string? Argumento(string[] args, string nombre)
        {
            int i = Array.IndexOf(args, nombre);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
    }
}
