using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed class App : Application
    {
        /// <summary>La pone Program antes de arrancar; sin ella (diseñador, pruebas) no hay servicio y se dice.</summary>
        internal static IFuenteDeEstado? Fuente { get; set; }

        internal static IServicioDeEscaneo? Escaneo { get; set; }

        internal static IServicioDeCuarentena? Cuarentena { get; set; }

        internal static IServicioDeFirewall? Firewall { get; set; }

        internal static IServicioDeLimpieza? Limpieza { get; set; }

        public override void Initialize() => AvaloniaXamlLoader.Load(this);

        public override void OnFrameworkInitializationCompleted()
        {
            const string sinFuente = "la ventana se abrió sin conexión configurada";
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime escritorio)
                escritorio.MainWindow = new MainWindow(
                    new VentanaPrincipalModelo(Fuente ?? new FuenteNoDisponible(sinFuente)),
                    new EscaneoModelo(Escaneo ?? new ServicioDeEscaneoNoDisponible(sinFuente)),
                    new CuarentenaModelo(Cuarentena ?? new ServicioDeCuarentenaNoDisponible(sinFuente)),
                    new FirewallModelo(Firewall ?? new ServicioDeFirewallNoDisponible(sinFuente)),
                    new LimpiezaModelo(Limpieza ?? new ServicioDeLimpiezaNoDisponible(sinFuente)));
            base.OnFrameworkInitializationCompleted();
        }
    }
}
