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

        public override void Initialize() => AvaloniaXamlLoader.Load(this);

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime escritorio)
                escritorio.MainWindow = new MainWindow(
                    new VentanaPrincipalModelo(Fuente ?? new FuenteNoDisponible("la ventana se abrió sin fuente de estado")));
            base.OnFrameworkInitializationCompleted();
        }
    }
}
