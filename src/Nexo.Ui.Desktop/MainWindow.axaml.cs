using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Classic.Avalonia.Theme;
using Classic.CommonControls.Dialogs;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public partial class MainWindow : ClassicWindow
    {
        // El mismo ritmo que la bandeja para el estado; el avance de un escaneo, cada segundo.
        private static readonly TimeSpan Sondeo = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan SondeoDeEscaneo = TimeSpan.FromSeconds(1);

        private const int PestanaEscaneo = 1;
        private const int PestanaFirewall = 3;
        private const int PestanaLimpieza = 4;
        private const int PestanaCuarentena = 6;

        private readonly DispatcherTimer _temporizador;
        private readonly DispatcherTimer _temporizadorDeEscaneo;

        /// <summary>Solo para el previsualizador de Avalonia: sin servicio, y lo dice.</summary>
        public MainWindow() : this(new VentanaPrincipalModelo(new FuenteNoDisponible("vista de diseño")),
                                   new EscaneoModelo(new ServicioDeEscaneoNoDisponible("vista de diseño"))) { }

        public MainWindow(VentanaPrincipalModelo modelo, EscaneoModelo escaneo)
        {
            InitializeComponent();
            Iconos.Poner(BotonEscanear, "IconoEscanear");
            Iconos.Poner(BotonLimpiar, "IconoLimpiar");
            Iconos.Poner(BotonFirewall, "IconoFirewall");
            Iconos.Poner(BotonCuarentena, "IconoCuarentena");
            Iconos.Poner(BotonActualizar, "IconoActualizar");
            Modelo = modelo;
            Escaneo = escaneo;
            DataContext = modelo;
            PanelDeEscaneo.DataContext = escaneo;

            _temporizador = new DispatcherTimer { Interval = Sondeo };
            _temporizador.Tick += async (_, _) => await Modelo.ActualizarAsync();
            _temporizadorDeEscaneo = new DispatcherTimer { Interval = SondeoDeEscaneo };
            _temporizadorDeEscaneo.Tick += async (_, _) => await Escaneo.SondearAsync();
            Opened += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                _temporizador.Start();
                _temporizadorDeEscaneo.Start();
            };
            Closed += (_, _) =>
            {
                _temporizador.Stop();
                _temporizadorDeEscaneo.Stop();
            };
            KeyDown += (_, e) =>
            {
                if (e.Key == Key.F5) _ = Modelo.ActualizarAsync();
            };
        }

        public VentanaPrincipalModelo Modelo { get; }
        public EscaneoModelo Escaneo { get; }

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

        // ------------------------------------------------------------ Escaneo
        private async void IniciarEscaneo(object? sender, RoutedEventArgs e) => await Escaneo.IniciarAsync();

        private async void CancelarEscaneo(object? sender, RoutedEventArgs e) => await Escaneo.CancelarAsync();

        private async void ElegirCarpeta(object? sender, RoutedEventArgs e)
        {
            IReadOnlyList<IStorageFolder> elegidas = await StorageProvider.OpenFolderPickerAsync(
                new FolderPickerOpenOptions { Title = "Elija la carpeta que quiere analizar", AllowMultiple = false });
            string? ruta = elegidas.FirstOrDefault()?.TryGetLocalPath();
            if (ruta is not null) Escaneo.RutaOtra = ruta;
        }

        /// <summary>
        /// Dos pasos, como en la bandeja: el servicio prepara el plan (no cambia nada) y se muestra; solo si el usuario acepta
        /// se pide aplicarlo con el token. Si el servicio exige aprobacion de administrador, la pide nexo-tray.exe (UAC).
        /// </summary>
        private async void PonerEnCuarentena(object? sender, RoutedEventArgs e)
        {
            Consulta<PlanDeCuarentena> plan = await Escaneo.PrevisualizarCuarentenaAsync();
            if (plan.Valor is not PlanDeCuarentena p)
            {
                await MessageBox.ShowDialog(this, "No se pudo preparar la cuarentena: " + plan.Error + ".", "Cuarentena",
                    MessageBoxButtons.Ok, MessageBoxIcon.Warning);
                return;
            }
            if (!p.HayCambios || p.Token is null)
            {
                await MessageBox.ShowDialog(this, "No hay nada que mover.\n\n" + p.Descripcion, "Cuarentena",
                    MessageBoxButtons.Ok, MessageBoxIcon.Information);
                return;
            }

            string texto = p.Descripcion
                           + (p.Avisos.Count > 0 ? "\n\n" + string.Join("\n", p.Avisos.Select(a => "• " + a)) : "")
                           + "\n\n¿Mover estos archivos a la cuarentena? Se guardan cifrados y se pueden restaurar durante 30 días.";
            MessageBoxResult respuesta = await MessageBox.ShowDialog(this, texto, "Poner en cuarentena",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (respuesta != MessageBoxResult.Yes) return;

            ResultadoDeAccion r = await Escaneo.AplicarCuarentenaAsync(p.Token);
            await MessageBox.ShowDialog(this, r.Mensaje, "Cuarentena", MessageBoxButtons.Ok,
                r.Exito ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            await Modelo.ActualizarAsync();
        }
    }
}
