using System;
using Avalonia;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    internal static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            string pipe = Argumento(args, "--pipe") ?? "NexoIpc";
            App.Fuente = Fuentes.PorDefecto(pipe);
            App.Escaneo = Fuentes.EscaneoPorDefecto(pipe);
            App.Cuarentena = Fuentes.CuarentenaPorDefecto(pipe);
            App.Firewall = Fuentes.FirewallPorDefecto(pipe);
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }

        // Lo usa tambien el previsualizador de Avalonia.
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .LogToTrace();

        private static string? Argumento(string[] args, string nombre)
        {
            int i = Array.IndexOf(args, nombre);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
    }
}
