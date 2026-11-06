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
        private const int PestanaTiempoReal = 2;
        private const int PestanaFirewall = 3;
        private const int PestanaLimpieza = 4;
        private const int PestanaCuarentena = 6;

        private readonly DispatcherTimer _temporizador;
        private readonly DispatcherTimer _temporizadorDeEscaneo;

        /// <summary>Solo para el previsualizador de Avalonia: sin servicio, y lo dice.</summary>
        public MainWindow() : this(new VentanaPrincipalModelo(new FuenteNoDisponible("vista de diseño")),
                                   new EscaneoModelo(new ServicioDeEscaneoNoDisponible("vista de diseño")),
                                   new CuarentenaModelo(new ServicioDeCuarentenaNoDisponible("vista de diseño")),
                                   new FirewallModelo(new ServicioDeFirewallNoDisponible("vista de diseño")),
                                   new LimpiezaModelo(new ServicioDeLimpiezaNoDisponible("vista de diseño")),
                                   new TiempoRealModelo(new ServicioDeTiempoRealNoDisponible("vista de diseño"),
                                                        new ServicioDeEscaneoNoDisponible("vista de diseño"))) { }

        public MainWindow(VentanaPrincipalModelo modelo, EscaneoModelo escaneo, CuarentenaModelo cuarentena, FirewallModelo firewall,
                          LimpiezaModelo limpieza, TiempoRealModelo tiempoReal)
        {
            InitializeComponent();
            Iconos.Poner(BotonEscanear, "IconoEscanear");
            Iconos.Poner(BotonLimpiar, "IconoLimpiar");
            Iconos.Poner(BotonFirewall, "IconoFirewall");
            Iconos.Poner(BotonCuarentena, "IconoCuarentena");
            Iconos.Poner(BotonActualizar, "IconoActualizar");
            Modelo = modelo;
            Escaneo = escaneo;
            Cuarentena = cuarentena;
            Firewall = firewall;
            Limpieza = limpieza;
            TiempoReal = tiempoReal;
            DataContext = modelo;
            PanelDeEscaneo.DataContext = escaneo;
            PanelDeCuarentena.DataContext = cuarentena;
            PanelDeFirewall.DataContext = firewall;
            PanelDeLimpieza.DataContext = limpieza;
            PanelDeTiempoReal.DataContext = tiempoReal;
            // La lista de cuarentena se lee al abrir, al entrar en su pestaña, con «Actualizar» y tras cada accion.
            Pestanas.SelectionChanged += async (_, _) =>
            {
                if (Pestanas.SelectedIndex == PestanaCuarentena) await Cuarentena.ActualizarAsync();
                else if (Pestanas.SelectedIndex == PestanaFirewall) await Firewall.ActualizarAsync();
                else if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
                // El catalogo se lee una vez; la vista previa solo cuando el usuario la pide (recorre el perfil).
                else if (Pestanas.SelectedIndex == PestanaLimpieza) await Limpieza.CargarReglasAsync();
            };

            _temporizador = new DispatcherTimer { Interval = Sondeo };
            _temporizador.Tick += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                // El detalle del tiempo real, solo mientras se esta mirando su pestaña.
                if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
            };
            _temporizadorDeEscaneo = new DispatcherTimer { Interval = SondeoDeEscaneo };
            _temporizadorDeEscaneo.Tick += async (_, _) => await Escaneo.SondearAsync();
            Opened += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                await Cuarentena.ActualizarAsync();
                await Firewall.ActualizarAsync();
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
                if (e.Key == Key.F5) Actualizar(this, new RoutedEventArgs());
            };
        }

        public VentanaPrincipalModelo Modelo { get; }
        public EscaneoModelo Escaneo { get; }
        public CuarentenaModelo Cuarentena { get; }
        public FirewallModelo Firewall { get; }
        public LimpiezaModelo Limpieza { get; }
        public TiempoRealModelo TiempoReal { get; }

        private async void Actualizar(object? sender, RoutedEventArgs e)
        {
            await Modelo.ActualizarAsync();
            await Cuarentena.ActualizarAsync();
            await Firewall.ActualizarAsync();
            if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
        }

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
            string? token = await ConfirmarPlanAsync(await Escaneo.PrevisualizarCuarentenaAsync(), "Poner en cuarentena",
                "¿Mover estos archivos a la cuarentena? Se guardan cifrados y se pueden restaurar.");
            if (token is null) return;
            await MostrarResultadoAsync("Cuarentena", await Escaneo.AplicarCuarentenaAsync(token));
            await Modelo.ActualizarAsync();
            await Cuarentena.ActualizarAsync();
        }

        // ------------------------------------------------------------ Tiempo real
        private async void PonerEnCuarentenaLoDelTiempoReal(object? sender, RoutedEventArgs e)
        {
            string? token = await ConfirmarPlanAsync(await TiempoReal.PrevisualizarCuarentenaAsync(), "Poner en cuarentena",
                "¿Mover estos archivos a la cuarentena? Se guardan cifrados y se pueden restaurar.");
            if (token is null) return;
            await MostrarResultadoAsync("Cuarentena", await TiempoReal.AplicarCuarentenaAsync(token));
            await Modelo.ActualizarAsync();
            await Cuarentena.ActualizarAsync();
        }

        /// <summary>
        /// Lo ofrece, no lo lanza solo: un escaneo bajo demanda de las carpetas por revisar (solo lee). Se sigue en la pestaña
        /// «Escaneo»; cuando termina COMPLETO, el servicio las da por revisadas.
        /// </summary>
        private async void RevisarLoNoVisto(object? sender, RoutedEventArgs e)
        {
            IReadOnlyList<string> rutas = TiempoReal.RutasParaRevisar();
            if (rutas.Count == 0) return;
            int total = TiempoReal.PorRevisar.Count;
            string texto = "El tiempo real no pudo analizar todo lo que cambió en estas carpetas:\n\n"
                           + string.Join("\n", rutas.Select(x => "• " + x))
                           + (total > rutas.Count ? "\n\n(Hay más; se revisarán en otra pasada.)" : "")
                           + "\n\n¿Escanearlas ahora? Solo se leen los archivos: no se mueve ni borra nada. Puede tardar varios minutos.";
            if (await MessageBox.ShowDialog(this, texto, "Revisar lo que no se vio", MessageBoxButtons.YesNo, MessageBoxIcon.Question)
                != MessageBoxResult.Yes) return;

            if (await Escaneo.IniciarRevisionAsync(rutas)) Pestanas.SelectedIndex = PestanaEscaneo;
            else await MessageBox.ShowDialog(this, Escaneo.Mensaje, "Revisar lo que no se vio", MessageBoxButtons.Ok, MessageBoxIcon.Warning);
        }

        // ------------------------------------------------------------ Cuarentena
        private async void ActualizarCuarentena(object? sender, RoutedEventArgs e) => await Cuarentena.ActualizarAsync();

        private async void Restaurar(object? sender, RoutedEventArgs e)
        {
            string? token = await ConfirmarPlanAsync(await Cuarentena.PrevisualizarRestauracionAsync(), "Restaurar archivo",
                "¿Devolver este archivo a su ubicación original? Hágalo solo si está seguro de que es un falso positivo.");
            if (token is null) return;
            await MostrarResultadoAsync("Restaurar", await Cuarentena.RestaurarAsync(token));
            await Modelo.ActualizarAsync();
        }

        private async void EliminarVencidos(object? sender, RoutedEventArgs e)
        {
            string? token = await ConfirmarPlanAsync(await Cuarentena.PrevisualizarPurgaAsync(), "Eliminar vencidos",
                "¿Eliminar estos archivos de la cuarentena? Se borran de forma permanente y ya no se podrán restaurar.");
            if (token is null) return;
            await MostrarResultadoAsync("Eliminar vencidos", await Cuarentena.PurgarAsync(token));
            await Modelo.ActualizarAsync();
        }

        // ------------------------------------------------------------ Limpieza
        private async void PrevisualizarLimpieza(object? sender, RoutedEventArgs e) => await Limpieza.PrevisualizarAsync();

        /// <summary>La confirmacion es la vista previa en pantalla mas BORRAR escrito: no hay otro dialogo antes de aplicar.</summary>
        private async void Limpiar(object? sender, RoutedEventArgs e)
        {
            ResultadoDeAccion? r = await Limpieza.LimpiarAsync();
            if (r is not null) await MostrarResultadoAsync("Limpieza", r);
        }

        // ------------------------------------------------------------ Firewall
        private async void ActualizarFirewall(object? sender, RoutedEventArgs e) => await Firewall.ActualizarAsync();

        private async void BloquearPrograma(object? sender, RoutedEventArgs e)
        {
            IReadOnlyList<IStorageFile> elegidos = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Elija el programa que quiere bloquear",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("Programas") { Patterns = new[] { "*.exe" } } }
            });
            string? ruta = elegidos.FirstOrDefault()?.TryGetLocalPath();
            if (ruta is null) return;
            await AplicarPlanDeFirewallAsync(await Firewall.PrevisualizarBloqueoAsync(ruta), "Bloquear programa",
                "¿Crear estas reglas en el firewall de Windows?");
        }

        private async void QuitarRegla(object? sender, RoutedEventArgs e)
            => await AplicarPlanDeFirewallAsync(await Firewall.PrevisualizarQuitarAsync(), "Quitar regla", "¿Quitar esta regla de Nexo?");

        private async void CambiarSigiloso(object? sender, RoutedEventArgs e)
            => await AplicarPlanDeFirewallAsync(await Firewall.PrevisualizarSigilosoAsync(), "Modo sigiloso", "¿Aplicar este cambio?");

        private async System.Threading.Tasks.Task AplicarPlanDeFirewallAsync(Consulta<PlanDelServicio> plan, string titulo, string pregunta)
        {
            string? token = await ConfirmarPlanAsync(plan, titulo, pregunta);
            if (token is null) return;
            await MostrarResultadoAsync(titulo, await Firewall.AplicarAsync(token));
            await Modelo.ActualizarAsync();
        }

        // ------------------------------------------------------------ Dos pasos: vista previa y confirmacion
        /// <summary>
        /// Muestra el plan que preparo el servicio (no cambia nada) y devuelve su token solo si el usuario acepta. Si no se pudo
        /// preparar o no hay nada que hacer, lo dice y devuelve null.
        /// </summary>
        private async System.Threading.Tasks.Task<string?> ConfirmarPlanAsync(Consulta<PlanDelServicio> plan, string titulo, string pregunta)
        {
            if (plan.Valor is not PlanDelServicio p)
            {
                await MessageBox.ShowDialog(this, "No se pudo preparar: " + plan.Error + ".", titulo, MessageBoxButtons.Ok, MessageBoxIcon.Warning);
                return null;
            }
            if (!p.HayCambios || p.Token is null)
            {
                await MessageBox.ShowDialog(this, "No hay nada que hacer.\n\n" + p.Descripcion, titulo, MessageBoxButtons.Ok, MessageBoxIcon.Information);
                return null;
            }

            string texto = p.Descripcion
                           + (p.Avisos.Count > 0 ? "\n\n" + string.Join("\n", p.Avisos.Select(a => "• " + a)) : "")
                           + "\n\n" + pregunta;
            MessageBoxResult r = await MessageBox.ShowDialog(this, texto, titulo, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            return r == MessageBoxResult.Yes ? p.Token : null;
        }

        private async System.Threading.Tasks.Task MostrarResultadoAsync(string titulo, ResultadoDeAccion r)
            => await MessageBox.ShowDialog(this, r.Mensaje, titulo, MessageBoxButtons.Ok, r.Exito ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }
}
