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
        private const int PestanaDisco = 5;
        private const int PestanaCuarentena = 6;
        private const int PestanaSeguridad = 7;
        private const int PestanaContrasenas = 8;

        private readonly DispatcherTimer _temporizador;
        private readonly DispatcherTimer _temporizadorDeEscaneo;
        private readonly DispatcherTimer _temporizadorDeBoveda;
        private bool _cerrandoLaBoveda;

        /// <summary>Solo para el previsualizador de Avalonia: sin servicio, y lo dice.</summary>
        public MainWindow() : this(new VentanaPrincipalModelo(new FuenteNoDisponible("vista de diseño")),
                                   new EscaneoModelo(new ServicioDeEscaneoNoDisponible("vista de diseño")),
                                   new CuarentenaModelo(new ServicioDeCuarentenaNoDisponible("vista de diseño")),
                                   new FirewallModelo(new ServicioDeFirewallNoDisponible("vista de diseño")),
                                   new LimpiezaModelo(new ServicioDeLimpiezaNoDisponible("vista de diseño")),
                                   new TiempoRealModelo(new ServicioDeTiempoRealNoDisponible("vista de diseño"),
                                                        new ServicioDeEscaneoNoDisponible("vista de diseño")),
                                   new DiscoModelo(new ServicioDeDiscoNoDisponible("vista de diseño")),
                                   new SeguridadModelo(new ServicioDeSeguridadNoDisponible("vista de diseño")),
                                   new ContrasenasModelo(ContrasenasModelo.RutaPorOmision(), portapapeles: new PortapapelesDeAvalonia())) { }

        public MainWindow(VentanaPrincipalModelo modelo, EscaneoModelo escaneo, CuarentenaModelo cuarentena, FirewallModelo firewall,
                          LimpiezaModelo limpieza, TiempoRealModelo tiempoReal,
                          DiscoModelo disco, SeguridadModelo seguridad, ContrasenasModelo contrasenas)
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
            Disco = disco;
            Seguridad = seguridad;
            Contrasenas = contrasenas;
            // El portapapeles de Avalonia cuelga de la ventana: se enlaza aqui.
            if (contrasenas.Portapapeles is PortapapelesDeAvalonia puente) puente.Enlazar(this);
            DataContext = modelo;
            PanelDeEscaneo.DataContext = escaneo;
            PanelDeCuarentena.DataContext = cuarentena;
            PanelDeFirewall.DataContext = firewall;
            PanelDeLimpieza.DataContext = limpieza;
            PanelDeTiempoReal.DataContext = tiempoReal;
            PanelDeDisco.DataContext = disco;
            // «Seguridad» NO revisa sola al entrar en la pestaña: la de aplicaciones consulta Internet (winget), asi que solo corre cuando el usuario lo pide.
            PanelDeSeguridad.DataContext = seguridad;
            PanelDeContrasenas.DataContext = contrasenas;
            // La lista de cuarentena se lee al abrir, al entrar en su pestaña, con «Actualizar» y tras cada accion.
            Pestanas.SelectionChanged += async (_, e) =>
            {
                // SelectionChanged es un evento que SUBE por el arbol: sin esta guarda, elegir una fila de un ListBox de dentro de una pestaña (cuarentena,
                // reglas del firewall, entradas de la boveda...) se tomaba por «cambie de pestaña», relanzaba la lectura y, en la boveda, reconstruia la lista
                // (que cambia la seleccion, que vuelve a subir el evento: recursion infinita).
                if (!ReferenceEquals(e.Source, Pestanas)) return;
                if (Pestanas.SelectedIndex == PestanaCuarentena) await Cuarentena.ActualizarAsync();
                else if (Pestanas.SelectedIndex == PestanaEscaneo) await Escaneo.ActualizarProgramadasAsync();
                else if (Pestanas.SelectedIndex == PestanaFirewall) await Firewall.ActualizarAsync();
                else if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
                else if (Pestanas.SelectedIndex == PestanaDisco) await Disco.ActualizarAsync();
                // Solo mira si existe el archivo de la boveda: abrirla exige la contraseña maestra.
                else if (Pestanas.SelectedIndex == PestanaContrasenas) Contrasenas.Refrescar();
                // El catalogo se lee una vez; la vista previa solo cuando el usuario la pide (recorre el perfil).
                else if (Pestanas.SelectedIndex == PestanaLimpieza) await Limpieza.CargarReglasAsync();
            };

            _temporizador = new DispatcherTimer { Interval = Sondeo };
            _temporizador.Tick += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                // El detalle del tiempo real, solo mientras se esta mirando su pestaña.
                if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
                // Lo del escaneo programado (lo corre el servicio solo, sin que nadie mire): se ve aparecer.
                else if (Pestanas.SelectedIndex == PestanaEscaneo) await Escaneo.ActualizarProgramadasAsync();
                // Y el de los discos (barato: el servicio devuelve lo que ya leyo), para ver terminar una lectura pedida.
                else if (Pestanas.SelectedIndex == PestanaDisco) await Disco.ActualizarAsync();
            };
            _temporizadorDeEscaneo = new DispatcherTimer { Interval = SondeoDeEscaneo };
            _temporizadorDeEscaneo.Tick += async (_, _) => await Escaneo.SondearAsync();

            // La boveda se bloquea sola tras un rato sin tocar la ventana: cada tecla o movimiento cuenta como actividad.
            _temporizadorDeBoveda = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
            _temporizadorDeBoveda.Tick += (_, _) => Contrasenas.ComprobarInactividad();
            AddHandler(KeyDownEvent, (_, _) => Contrasenas.Actividad(), Avalonia.Interactivity.RoutingStrategies.Tunnel, handledEventsToo: true);
            AddHandler(PointerPressedEvent, (_, _) => Contrasenas.Actividad(), Avalonia.Interactivity.RoutingStrategies.Tunnel, handledEventsToo: true);
            AddHandler(PointerMovedEvent, (_, _) => Contrasenas.Actividad(), Avalonia.Interactivity.RoutingStrategies.Tunnel, handledEventsToo: true);

            Opened += async (_, _) =>
            {
                await Modelo.ActualizarAsync();
                await Cuarentena.ActualizarAsync();
                await Firewall.ActualizarAsync();
                await Escaneo.ActualizarProgramadasAsync();
                _temporizador.Start();
                _temporizadorDeEscaneo.Start();
                _temporizadorDeBoveda.Start();
            };

            // Al cerrar: la boveda se bloquea (clave a ceros). Si Nexo dejo una contraseña en el portapapeles, se espera a borrarla ANTES de cerrar de verdad.
            Closing += async (_, e) =>
            {
                if (_cerrandoLaBoveda) return;
                _cerrandoLaBoveda = true;
                bool habiaAlgoCopiado = Contrasenas.HayTextoEnElPortapapeles;
                Contrasenas.Bloquear();
                if (!habiaAlgoCopiado) return;
                e.Cancel = true;
                await Contrasenas.EsperarBorradoAsync();
                Close();
            };
            Closed += (_, _) =>
            {
                _temporizador.Stop();
                _temporizadorDeEscaneo.Stop();
                _temporizadorDeBoveda.Stop();
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
        public DiscoModelo Disco { get; }
        public SeguridadModelo Seguridad { get; }
        public ContrasenasModelo Contrasenas { get; }

        // ------------------------------------------------------------ Contraseñas (la boveda corre aqui, con el usuario; nunca por el servicio)
        private async void CrearBoveda(object? sender, RoutedEventArgs e)
        {
            if (await Contrasenas.CrearAsync(CajaMaestraNueva.Text ?? "", CajaMaestraRepetida.Text ?? ""))
            {
                CajaMaestraNueva.Text = "";
                CajaMaestraRepetida.Text = "";
            }
        }

        private async void DesbloquearBoveda(object? sender, RoutedEventArgs e)
        {
            if (await Contrasenas.DesbloquearAsync(CajaMaestra.Text ?? "")) CajaMaestra.Text = "";
        }

        private void TeclaEnCajaMaestra(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) DesbloquearBoveda(sender, new RoutedEventArgs());
        }

        private void BloquearBoveda(object? sender, RoutedEventArgs e) => Contrasenas.Bloquear();
        private void NuevaEntrada(object? sender, RoutedEventArgs e) => Contrasenas.NuevaEntrada();
        private void EditarEntrada(object? sender, RoutedEventArgs e) => Contrasenas.EditarSeleccionada();
        private void CancelarEntrada(object? sender, RoutedEventArgs e) => Contrasenas.CancelarEdicion();
        private void GenerarContrasena(object? sender, RoutedEventArgs e) => Contrasenas.GenerarContrasena();
        private void AlternarContrasena(object? sender, RoutedEventArgs e) => Contrasenas.AlternarContrasena();
        private async void GuardarEntrada(object? sender, RoutedEventArgs e) => await Contrasenas.GuardarEdicionAsync();
        private async void CopiarUsuario(object? sender, RoutedEventArgs e) => await Contrasenas.CopiarUsuarioAsync();
        private async void CopiarContrasena(object? sender, RoutedEventArgs e) => await Contrasenas.CopiarContrasenaAsync();
        private async void AuditarBoveda(object? sender, RoutedEventArgs e) => await Contrasenas.AuditarAsync();

        private async void EliminarEntrada(object? sender, RoutedEventArgs e)
        {
            FilaDeEntrada? fila = Contrasenas.Seleccionada;
            if (fila is null) return;
            bool si = await DialogoEnEspanol.PreguntarAsync(this,
                "¿Eliminar la entrada «" + fila.Sitio + "»?\n\nSe borra del archivo cifrado y no queda ninguna copia. No se puede deshacer.",
                "Eliminar entrada");
            if (si) await Contrasenas.EliminarSeleccionadaAsync();
        }

        private async void GuardarCopia(object? sender, RoutedEventArgs e)
        {
            // El selector pregunta por si mismo si ya existe el archivo (ShowOverwritePrompt): la respuesta del usuario es el permiso para sobrescribir.
            IStorageFile? archivo = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Guardar una copia de la bóveda",
                SuggestedFileName = ContrasenasModelo.NombreSugeridoDeCopia(),
                DefaultExtension = "nxv",
                ShowOverwritePrompt = true,
                FileTypeChoices = new[] { new FilePickerFileType("Bóveda de Nexo") { Patterns = new[] { "*.nxv" } } }
            });
            string? ruta = archivo?.TryGetLocalPath();
            if (ruta is null) return;
            await Contrasenas.GuardarCopiaAsync(ruta, sobrescribir: true);
        }

        private async void RestaurarCopia(object? sender, RoutedEventArgs e)
        {
            string pass = CajaMaestraDeCopia.Text ?? "";
            if (pass.Length == 0)
            {
                await Contrasenas.RestaurarAsync("", ""); // deja el mensaje «escribe primero la contraseña de la copia»
                return;
            }

            IReadOnlyList<IStorageFile> elegidos = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Elige la copia de la bóveda",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("Bóveda de Nexo") { Patterns = new[] { "*.nxv" } }, FilePickerFileTypes.All }
            });
            string? ruta = elegidos.FirstOrDefault()?.TryGetLocalPath();
            if (ruta is null) return;

            if (Contrasenas.ExisteBoveda)
            {
                bool si = await DialogoEnEspanol.PreguntarAsync(this,
                    "Ya tienes una bóveda en este equipo.\n\nSi sigues, se guardará aparte (con la fecha y la hora en el nombre) y no se borra. La copia ocupará su lugar.\n\n¿Restaurar la copia?",
                    "Restaurar copia");
                if (!si) return;
            }
            if (await Contrasenas.RestaurarAsync(ruta, pass)) CajaMaestraDeCopia.Text = "";
        }

        private async void CambiarMaestra(object? sender, RoutedEventArgs e)
        {
            if (await Contrasenas.CambiarMaestraAsync(CajaMaestraActual.Text ?? "", CajaMaestraNuevaCambio.Text ?? "", CajaMaestraRepetidaCambio.Text ?? ""))
            {
                CajaMaestraActual.Text = "";
                CajaMaestraNuevaCambio.Text = "";
                CajaMaestraRepetidaCambio.Text = "";
            }
        }

        private async void RevisarTodo(object? sender, RoutedEventArgs e) => await Seguridad.RevisarTodoAsync();

        private async void RevisarSeccion(object? sender, RoutedEventArgs e)
        {
            if (sender is Avalonia.Controls.Control { Tag: SeccionDeSeguridad seccion }) await Seguridad.RevisarAsync(seccion);
        }

        private async void Actualizar(object? sender, RoutedEventArgs e)
        {
            await Modelo.ActualizarAsync();
            await Cuarentena.ActualizarAsync();
            await Firewall.ActualizarAsync();
            await Escaneo.ActualizarProgramadasAsync();
            if (Pestanas.SelectedIndex == PestanaTiempoReal) await TiempoReal.ActualizarAsync();
            if (Pestanas.SelectedIndex == PestanaDisco) await Disco.ActualizarAsync();
        }

        private void Salir(object? sender, RoutedEventArgs e) => Close();

        private void IrAEscaneo(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaEscaneo;
        private void IrAFirewall(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaFirewall;
        private void IrALimpieza(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaLimpieza;
        private void IrACuarentena(object? sender, RoutedEventArgs e) => Pestanas.SelectedIndex = PestanaCuarentena;

        private async void AcercaDe(object? sender, RoutedEventArgs e)
            => await DialogoEnEspanol.InformarAsync(this,
                "Nexo Security Suite\n\nSuite de higiene y monitoreo de seguridad. Complementa a Microsoft Defender; no lo reemplaza.\n\nLicencia MIT. Sin garantía de ningún tipo.",
                "Acerca de Nexo");

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

        private async void PonerEnCuarentenaLoProgramado(object? sender, RoutedEventArgs e)
        {
            string? token = await ConfirmarPlanAsync(await Escaneo.PrevisualizarCuarentenaProgramadaAsync(), "Poner en cuarentena",
                "¿Mover estos archivos a la cuarentena? Se guardan cifrados y se pueden restaurar.");
            if (token is null) return;
            await MostrarResultadoAsync("Cuarentena", await Escaneo.AplicarCuarentenaProgramadaAsync(token));
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
            if (!await DialogoEnEspanol.PreguntarAsync(this, texto, "Revisar lo que no se vio", IconoDeDialogo.Pregunta)) return;

            if (await Escaneo.IniciarRevisionAsync(rutas)) Pestanas.SelectedIndex = PestanaEscaneo;
            else await DialogoEnEspanol.InformarAsync(this, Escaneo.Mensaje, "Revisar lo que no se vio", IconoDeDialogo.Advertencia);
        }

        // ------------------------------------------------------------ Disco
        private async void LeerDiscos(object? sender, RoutedEventArgs e)
        {
            await Disco.PedirLecturaAsync();
            await Modelo.ActualizarAsync();
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
                await DialogoEnEspanol.InformarAsync(this, "No se pudo preparar: " + plan.Error + ".", titulo, IconoDeDialogo.Advertencia);
                return null;
            }
            if (!p.HayCambios || p.Token is null)
            {
                await DialogoEnEspanol.InformarAsync(this, "No hay nada que hacer.\n\n" + p.Descripcion, titulo);
                return null;
            }

            string texto = p.Descripcion
                           + (p.Avisos.Count > 0 ? "\n\n" + string.Join("\n", p.Avisos.Select(a => "• " + a)) : "")
                           + "\n\n" + pregunta;
            bool acepta = await DialogoEnEspanol.PreguntarAsync(this, texto, titulo);
            return acepta ? p.Token : null;
        }

        private async System.Threading.Tasks.Task MostrarResultadoAsync(string titulo, ResultadoDeAccion r)
            => await DialogoEnEspanol.InformarAsync(this, r.Mensaje, titulo, r.Exito ? IconoDeDialogo.Informacion : IconoDeDialogo.Advertencia);
    }
}
