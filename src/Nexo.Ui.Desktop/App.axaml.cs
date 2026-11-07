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

        internal static IServicioDeTiempoReal? TiempoReal { get; set; }

        internal static IServicioDeDisco? Disco { get; set; }

        internal static IServicioDeSeguridad? Seguridad { get; set; }

        /// <summary>Por donde la ventana avisa al servicio de lo que hizo (para el vault de reportes). Sin servicio, no deja rastro.</summary>
        internal static IRastroDeVentana? Rastro { get; set; }

        /// <summary>Donde esta la boveda (Program la fija con --boveda; por omision, el perfil del usuario).</summary>
        internal static string? Contrasenas { get; set; }

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
                    new LimpiezaModelo(Limpieza ?? new ServicioDeLimpiezaNoDisponible(sinFuente)),
                    new TiempoRealModelo(TiempoReal ?? new ServicioDeTiempoRealNoDisponible(sinFuente),
                                         Escaneo ?? new ServicioDeEscaneoNoDisponible(sinFuente)),
                    new DiscoModelo(Disco ?? new ServicioDeDiscoNoDisponible(sinFuente)),
                    new SeguridadModelo(Seguridad ?? new ServicioDeSeguridadNoDisponible(sinFuente)) { Rastro = Rastro ?? RastroNulo.Instancia },
                    // La boveda vive en el perfil del usuario y corre en este proceso; el portapapeles real se enlaza a la ventana al crearla.
                    new ContrasenasModelo(Contrasenas ?? ContrasenasModelo.RutaPorOmision(), portapapeles: new PortapapelesDeAvalonia()) { Rastro = Rastro ?? RastroNulo.Instancia });
            base.OnFrameworkInitializationCompleted();
        }
    }
}
