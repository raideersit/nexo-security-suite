using System;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Classic.Avalonia.Theme;
using Classic.CommonControls.Dialogs;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public partial class MainWindow : ClassicWindow
    {
        // El mismo ritmo que la bandeja.
        private static readonly TimeSpan Sondeo = TimeSpan.FromSeconds(5);

        private const int PestanaEscaneo = 1;
        private const int PestanaFirewall = 3;
        private const int PestanaLimpieza = 4;
        private const int PestanaCuarentena = 6;

        private readonly DispatcherTimer _temporizador;

        /// <summary>Solo para el previsualizador de Avalonia: sin servicio, y lo dice.</summary>
        public MainWindow() : this(new VentanaPrincipalModelo(new FuenteNoDisponible("vista de diseño"))) { }

        public MainWindow(VentanaPrincipalModelo modelo)
        {
            InitializeComponent();
            Iconos.Poner(BotonEscanear, "IconoEscanear");
            Iconos.Poner(BotonLimpiar, "IconoLimpiar");
            Iconos.Poner(BotonFirewall, "IconoFirewall");
            Iconos.Poner(BotonCuarentena, "IconoCuarentena");
            Iconos.Poner(BotonActualizar, "IconoActualizar");
            Modelo = modelo;
            DataContext = modelo;

            _temporizador = new DispatcherTimer { Interval = Sondeo };
            _temporizador.Tick += async (_, _) => await Modelo.ActualizarAsync();
            Opened += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                _temporizador.Start();
            };
            Closed += (_, _) => _temporizador.Stop();
            KeyDown += (_, e) =>
            {
                if (e.Key == Key.F5) _ = Modelo.ActualizarAsync();
            };
        }

        public VentanaPrincipalModelo Modelo { get; }

        private async void Actualizar(object? sender, RoutedEventArgs e) => await Modelo.ActualizarAsync();

        private void Salir(object? sender, RoutedEventArgs e) => Close();

        private void IrAEscaneo(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaEscaneo;
        private void IrAFirewall(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaFirewall;
        private void IrALimpieza(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaLimpieza;
        private void IrACuarentena(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaCuarentena;

        private async void AcercaDe(object? sender, RoutedEventArgs e)
            => await MessageBox.ShowDialog(this,
                "Nexo Security Suite\n\nSuite de higiene y monitoreo de seguridad. Complementa a Microsoft Defender; no lo reemplaza.\n\nLicencia MIT. Sin garantía de ningún tipo.",
                "Acerca de Nexo", MessageBoxButtons.Ok, MessageBoxIcon.Information);
    }
}
