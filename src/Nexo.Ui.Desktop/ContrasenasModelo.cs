using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Modules.Identity.Boveda;
using Nexo.Modules.Identity.Filtraciones;
using Nexo.Ui.Desktop.Nucleo;
using Bov = Nexo.Modules.Identity.Boveda.Boveda;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeEntrada(Guid Id, string Sitio, string Usuario, string Filtracion, IBrush Color, bool TieneFiltracion);

    /// <summary>
    /// La pestaña «Contraseñas». Corre en el proceso de la ventana, con el usuario: la bóveda NUNCA pasa por el servicio (que es SYSTEM).
    ///
    /// Reglas (todas probadas):
    ///  - La contraseña maestra solo viaja como argumento de un metodo: el modelo no la guarda en ninguna propiedad.
    ///  - Bloquear (a mano o por inactividad) cierra la bóveda, sobrescribe la clave con ceros, olvida las entradas de la lista, oculta la
    ///    contraseña y borra el portapapeles si todavia tiene lo que puso Nexo.
    ///  - Una contraseña copiada se borra del portapapeles a los 30 s, solo si sigue siendo la misma.
    ///  - «Contraseña incorrecta o archivo alterado» no se distingue (AES-GCM no puede): el texto lo dice asi.
    ///  - La comprobación de filtraciones solo corre cuando el usuario la pide (sale a Internet un prefijo de 5 caracteres por contraseña);
    ///    «no aparece» no significa «es buena», y lo no comprobado nunca se muestra como bien.
    ///  - Lo limitado del lenguaje: las cadenas de .NET no se pueden borrar de la memoria a voluntad; solo la clave se pone a ceros.
    /// </summary>
    public sealed class ContrasenasModelo : INotifyPropertyChanged, IDisposable
    {
        public const int LongitudMinimaMaestra = Bov.LongitudMinimaDeContrasenaMaestra;
        public static readonly TimeSpan InactividadPorOmision = TimeSpan.FromMinutes(5);
        public static readonly TimeSpan BorradoPorOmision = TimeSpan.FromSeconds(30);
        private const string Oculta = "••••••••";

        private readonly string _ruta;
        private readonly ParametrosDeClave? _parametros;
        private readonly bool _permitirDebiles;
        private readonly Func<IConsultaDeRangos> _consulta;
        private readonly IPortapapeles _portapapeles;
        private readonly Func<DateTime> _reloj;
        private readonly TimeSpan _inactividad;
        private readonly TimeSpan _borrado;
        private readonly Func<TimeSpan, Task> _espera;

        private Bov? _boveda;
        private List<EntradaDeBoveda> _todas = new();
        private readonly Dictionary<Guid, string> _auditoria = new();
        private readonly HashSet<Guid> _filtradas = new();
        private string? _resumenDeAuditoria;
        private Indicador _indicadorDeAuditoria = Indicador.SinDatos;
        private DateTime _ultimaActividad;
        private Guid? _seleccionada;
        private string? _textoCopiado;
        private int _generacionDeCopia;
        private Task _borradoPendiente = Task.CompletedTask;

        private FaseDeBoveda _fase;
        private string _mensaje = "";
        private bool _ocupado;
        private string _filtro = "";
        private bool _mostrar;
        private bool _edicion;
        private bool _esNueva;
        private string _edSitio = "", _edUsuario = "", _edContrasena = "", _edNotas = "";

        public ContrasenasModelo(string ruta, ParametrosDeClave? parametros = null, bool permitirParametrosDebiles = false,
                                 Func<IConsultaDeRangos>? consulta = null, IPortapapeles? portapapeles = null, Func<DateTime>? reloj = null,
                                 TimeSpan? inactividad = null, TimeSpan? borrado = null, Func<TimeSpan, Task>? espera = null)
        {
            if (string.IsNullOrWhiteSpace(ruta) || !Path.IsPathRooted(ruta)) throw new ArgumentException("La ruta de la bóveda debe ser absoluta.", nameof(ruta));
            _ruta = ruta;
            _parametros = parametros;
            _permitirDebiles = permitirParametrosDebiles;
            _consulta = consulta ?? (() => new ConsultaDeRangosHttp());
            _portapapeles = portapapeles ?? new PortapapelesNoDisponible();
            _reloj = reloj ?? (() => DateTime.Now);
            _inactividad = inactividad ?? InactividadPorOmision;
            _borrado = borrado ?? BorradoPorOmision;
            _espera = espera ?? (t => Task.Delay(t));
            _ultimaActividad = _reloj();
            Refrescar();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>Donde se guarda por omision: el perfil del usuario, nunca ProgramData.</summary>
        public static string RutaPorOmision()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "boveda.nxv");

        // ---------------------------------------------------------------- lo que ve la ventana
        public FaseDeBoveda Fase { get => _fase; private set { if (_fase == value) return; _fase = value; Recalcular(); } }
        public bool EsSinBoveda => _fase == FaseDeBoveda.SinBoveda;
        public bool EsBloqueada => _fase == FaseDeBoveda.Bloqueada;
        public bool EsAbierta => _fase == FaseDeBoveda.Abierta;
        public string Archivo => "Archivo: " + _ruta;
        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }
        public bool Ocupado { get => _ocupado; private set { if (_ocupado == value) return; _ocupado = value; RecalcularEstado(); } }
        public bool NoOcupado => !_ocupado;

        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IReadOnlyList<FilaDeEntrada> Entradas { get; private set; } = Array.Empty<FilaDeEntrada>();
        public int Cantidad => _todas.Count;

        public string Filtro { get => _filtro; set { if (_filtro == value) return; _filtro = value ?? ""; Recalcular(); } }

        public FilaDeEntrada? Seleccionada
        {
            get => _seleccionada is Guid g ? Entradas.FirstOrDefault(f => f.Id == g) : null;
            set
            {
                // Al reemplazar la lista, el ListBox pierde su seleccion y empuja un null: es un efecto del propio control, no una eleccion del usuario.
                if (_reconstruyendo && value is null) return;
                Guid? nuevo = value?.Id;
                if (_seleccionada == nuevo) return;
                _seleccionada = nuevo;
                _mostrar = false;            // al cambiar de entrada, la contraseña vuelve a estar oculta
                _edicion = false;
                RecalcularEstado();          // NO se reconstruye la lista: hacerlo reiniciaria la seleccion y entraria en un bucle
            }
        }

        private EntradaDeBoveda? Actual => _seleccionada is Guid g ? _todas.FirstOrDefault(e => e.Id == g) : null;
        public bool HayEntradaSeleccionada => Actual is not null;
        public bool DetalleVisible => Actual is not null && !_edicion;
        public string DetalleSitio => Actual?.Sitio ?? "";
        public string DetalleUsuario => Actual?.Usuario ?? "";
        public string DetalleNotas => Actual?.Notas ?? "";
        public string DetalleFechas => Actual is { } e ? "Creada " + Resumir.Fecha(e.Creada) + " · modificada " + Resumir.Fecha(e.Modificada) : "";
        public bool MostrarContrasena => _mostrar;
        public string BotonMostrar => _mostrar ? "Ocultar" : "Mostrar";
        /// <summary>Oculta, siempre del mismo largo: ni siquiera el tamaño de la contraseña se ve.</summary>
        public string DetalleContrasena => Actual is null ? "" : _mostrar ? Actual.Contrasena : Oculta;

        public bool EdicionVisible => _edicion;
        public string EdicionTitulo => _esNueva ? "Nueva entrada" : "Editar entrada";
        public string EdSitio { get => _edSitio; set { value ??= ""; if (_edSitio == value) return; _edSitio = value; Avisar(); } }
        public string EdUsuario { get => _edUsuario; set { value ??= ""; if (_edUsuario == value) return; _edUsuario = value; Avisar(); } }
        public string EdContrasena { get => _edContrasena; set { value ??= ""; if (_edContrasena == value) return; _edContrasena = value; Avisar(); } }
        public string EdNotas { get => _edNotas; set { value ??= ""; if (_edNotas == value) return; _edNotas = value; Avisar(); } }
        /// <summary>El caracter con que se oculta el campo de contraseña al editar ('\0' = visible).</summary>
        public char CaracterDeClave => _mostrar ? '\0' : '•';

        public string Auditoria => _resumenDeAuditoria ?? "";
        public bool HayAuditoria => _resumenDeAuditoria is not null;
        public IBrush ColorDeAuditoria => Colores.De(_indicadorDeAuditoria);
        public Indicador IndicadorDeAuditoria => _indicadorDeAuditoria;

        /// <summary>El portapapeles que usa este modelo (la ventana lo enlaza con ella al crearse).</summary>
        public IPortapapeles Portapapeles => _portapapeles;

        /// <summary>true si Nexo puso una contraseña en el portapapeles que aun no se ha borrado: al cerrar hay que esperar a que se borre.</summary>
        public bool HayTextoEnElPortapapeles => _textoCopiado is not null;

        public string ResumenDeInactividad => "Se bloquea sola tras " + (int)_inactividad.TotalMinutes + (((int)_inactividad.TotalMinutes) == 1 ? " minuto" : " minutos") + " sin usarla.";

        // ---------------------------------------------------------------- estado inicial
        /// <summary>Mira si existe el archivo. No abre nada: abrir exige la contraseña maestra.</summary>
        public void Refrescar()
        {
            if (_boveda is not null) { Recalcular(); return; }
            _fase = File.Exists(_ruta) ? FaseDeBoveda.Bloqueada : FaseDeBoveda.SinBoveda;
            Recalcular();
        }

        // ---------------------------------------------------------------- crear, abrir, cerrar
        public async Task<bool> CrearAsync(string maestra, string repetida, CancellationToken ct = default)
        {
            if (_ocupado || _fase != FaseDeBoveda.SinBoveda) return false;
            if (maestra is null || maestra.Length < LongitudMinimaMaestra) { Mensaje = "La contraseña maestra debe tener al menos " + LongitudMinimaMaestra + " caracteres."; return false; }
            if (!string.Equals(maestra, repetida, StringComparison.Ordinal)) { Mensaje = "Las dos contraseñas no coinciden."; return false; }

            Ocupado = true;
            Mensaje = "Creando la bóveda...";
            try
            {
                _boveda = await Bov.CrearAsync(_ruta, maestra, null, _parametros, _permitirDebiles, ct);
                CargarEntradas();
                _fase = FaseDeBoveda.Abierta;
                Actividad();
                Mensaje = "Bóveda creada. Si olvidas la contraseña maestra, no hay forma de recuperar lo que guardes: apúntala en un lugar seguro.";
                return true;
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
            {
                Mensaje = "No se pudo crear la bóveda: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
            }
        }

        public async Task<bool> DesbloquearAsync(string maestra, CancellationToken ct = default)
        {
            if (_ocupado || _fase != FaseDeBoveda.Bloqueada) return false;
            if (string.IsNullOrEmpty(maestra)) { Mensaje = "Escribe la contraseña maestra."; return false; }

            Ocupado = true;
            Mensaje = "Abriendo la bóveda...";
            try
            {
                ResultadoDeApertura r = await Bov.AbrirAsync(_ruta, maestra, null, ct);
                if (r.Abierta && r.Boveda is not null)
                {
                    _boveda = r.Boveda;
                    CargarEntradas();
                    _fase = FaseDeBoveda.Abierta;
                    Actividad();
                    Mensaje = "";
                    return true;
                }
                Mensaje = r.Estado switch
                {
                    EstadoDeApertura.NoExiste => "El archivo de la bóveda ya no existe.",
                    EstadoDeApertura.ArchivoIlegible => "El archivo no es una bóveda de Nexo o está dañado." + (r.Detalle is null ? "" : " (" + r.Detalle + ")"),
                    EstadoDeApertura.VersionNoSoportada => "La bóveda es de una versión más nueva de Nexo: actualiza Nexo para abrirla.",
                    EstadoDeApertura.ParametrosFueraDeRango => "El archivo pide parámetros de cifrado fuera de lo aceptable: Nexo no lo abre (protección contra archivos hechos para agotar la memoria).",
                    EstadoDeApertura.ContrasenaIncorrectaOArchivoAlterado => "Contraseña incorrecta, o el archivo fue alterado: no se puede distinguir una cosa de la otra.",
                    _ => "No se pudo leer el archivo (permisos o disco)."
                };
                if (r.Estado == EstadoDeApertura.NoExiste) { _fase = FaseDeBoveda.SinBoveda; Recalcular(); }
                return false;
            }
            finally
            {
                Ocupado = false;
            }
        }

        /// <summary>Cierra la bóveda: clave a ceros, entradas olvidadas, contraseña oculta y portapapeles limpio (si sigue siendo lo que puso Nexo).</summary>
        public void Bloquear(string? aviso = null)
        {
            _generacionDeCopia++;
            if (_textoCopiado is not null) _borradoPendiente = BorrarSiSigueIgualAsync();

            _boveda?.Dispose();
            _boveda = null;
            _todas = new List<EntradaDeBoveda>();
            _auditoria.Clear();
            _filtradas.Clear();
            _resumenDeAuditoria = null;
            _indicadorDeAuditoria = Indicador.SinDatos;
            _ultimaCopia = null;     // «ultima copia de esta sesion»: una sesion nueva empieza sin ella
            _seleccionada = null;
            _mostrar = false;
            _edicion = false;
            _filtro = "";
            _edSitio = _edUsuario = _edContrasena = _edNotas = "";
            _fase = File.Exists(_ruta) ? FaseDeBoveda.Bloqueada : FaseDeBoveda.SinBoveda;
            Mensaje = aviso ?? "Bóveda bloqueada.";
            Recalcular();
        }

        // ---------------------------------------------------------------- inactividad
        /// <summary>La ventana la llama con cada tecla o movimiento del raton.</summary>
        public void Actividad() => _ultimaActividad = _reloj();

        /// <summary>true si bloqueo por inactividad. La ventana la llama cada pocos segundos.</summary>
        public bool ComprobarInactividad()
        {
            if (_fase != FaseDeBoveda.Abierta || _ocupado) return false;
            if (_reloj() - _ultimaActividad < _inactividad) return false;
            Bloquear("La bóveda se bloqueó por inactividad.");
            return true;
        }

        // ---------------------------------------------------------------- entradas
        public void NuevaEntrada()
        {
            if (_fase != FaseDeBoveda.Abierta) return;
            Actividad();
            _esNueva = true;
            _edicion = true;
            _edSitio = _edUsuario = _edContrasena = _edNotas = "";
            Mensaje = "";
            RecalcularEstado();
        }

        public void EditarSeleccionada()
        {
            if (_fase != FaseDeBoveda.Abierta || Actual is not { } e) return;
            Actividad();
            _esNueva = false;
            _edicion = true;
            _edSitio = e.Sitio; _edUsuario = e.Usuario; _edContrasena = e.Contrasena; _edNotas = e.Notas;
            Mensaje = "";
            RecalcularEstado();
        }

        public void CancelarEdicion()
        {
            if (!_edicion) return;
            Actividad();
            _edicion = false;
            _mostrar = false;
            _edSitio = _edUsuario = _edContrasena = _edNotas = "";
            RecalcularEstado();
        }

        /// <summary>Pone una contraseña aleatoria en el campo de edicion (generador criptografico, 20 caracteres).</summary>
        public void GenerarContrasena(OpcionesDeGenerador? opciones = null)
        {
            if (!_edicion) return;
            Actividad();
            EdContrasena = GeneradorDeContrasenas.Generar(opciones);
            _mostrar = true; // se ve lo generado, para poder anotarlo
            RecalcularEstado();
        }

        public async Task<bool> GuardarEdicionAsync()
        {
            if (_boveda is null || !_edicion || _ocupado) return false;
            Actividad();
            if (string.IsNullOrWhiteSpace(_edSitio)) { Mensaje = "El sitio no puede estar vacío."; return false; }

            Ocupado = true;
            try
            {
                if (_esNueva)
                {
                    EntradaDeBoveda e = await _boveda.AgregarAsync(_edSitio, _edUsuario, _edContrasena, _edNotas);
                    _seleccionada = e.Id;
                    Mensaje = "Entrada guardada.";
                }
                else if (_seleccionada is Guid id)
                {
                    await _boveda.ActualizarAsync(id, _edSitio, _edUsuario, _edContrasena, _edNotas);
                    _auditoria.Remove(id);    // la contraseña pudo cambiar: lo que se comprobó antes ya no vale
                    _filtradas.Remove(id);
                    Mensaje = "Entrada actualizada.";
                }
                _edicion = false;
                _mostrar = false;    // lo generado se vio para anotarlo; guardado, la contraseña vuelve a estar oculta
                _edSitio = _edUsuario = _edContrasena = _edNotas = "";
                CargarEntradas();
                return true;
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException or KeyNotFoundException)
            {
                Mensaje = "No se pudo guardar: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
            }
        }

        public async Task<bool> EliminarSeleccionadaAsync()
        {
            if (_boveda is null || _ocupado || _seleccionada is not Guid id) return false;
            Actividad();
            Ocupado = true;
            try
            {
                bool quitada = await _boveda.EliminarAsync(id);
                _auditoria.Remove(id);
                _filtradas.Remove(id);
                _seleccionada = null;
                _mostrar = false;
                Mensaje = quitada ? "Entrada eliminada (ya no está en el archivo)." : "Esa entrada ya no existía.";
                CargarEntradas();
                return quitada;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                Mensaje = "No se pudo eliminar: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
            }
        }

        public void AlternarContrasena()
        {
            if (Actual is null && !_edicion) return;
            Actividad();
            _mostrar = !_mostrar;
            RecalcularEstado();
        }

        // ---------------------------------------------------------------- portapapeles
        public async Task CopiarUsuarioAsync()
        {
            if (Actual is not { } e) return;
            Actividad();
            Mensaje = await _portapapeles.PonerAsync(e.Usuario) ? "Usuario copiado." : "No se pudo usar el portapapeles.";
        }

        public async Task CopiarContrasenaAsync()
        {
            if (Actual is not { } e) return;
            Actividad();
            if (e.Contrasena.Length == 0) { Mensaje = "Esta entrada no tiene contraseña."; return; }
            if (!await _portapapeles.PonerAsync(e.Contrasena)) { Mensaje = "No se pudo usar el portapapeles."; return; }

            _textoCopiado = e.Contrasena;
            int generacion = ++_generacionDeCopia;
            Mensaje = "Contraseña copiada. Se borrará del portapapeles en " + (int)_borrado.TotalSeconds + " s.";
            _borradoPendiente = BorrarDespuesAsync(generacion);
        }

        /// <summary>Solo para las pruebas: espera a que termine el borrado programado.</summary>
        public Task EsperarBorradoAsync() => _borradoPendiente;

        private async Task BorrarDespuesAsync(int generacion)
        {
            await _espera(_borrado);
            if (generacion != _generacionDeCopia) return; // se copio otra cosa despues, o se bloqueo: ese borrado ya no toca
            await BorrarSiSigueIgualAsync();
        }

        private async Task BorrarSiSigueIgualAsync()
        {
            string? puesto = _textoCopiado;
            _textoCopiado = null;
            if (puesto is null) return;
            string? actual = await _portapapeles.LeerAsync();
            if (actual == puesto)
            {
                await _portapapeles.BorrarAsync();
                Mensaje = "Portapapeles borrado.";
            }
            else
            {
                Mensaje = "El portapapeles ya tenía otra cosa: no se tocó.";
            }
        }

        // ---------------------------------------------------------------- filtraciones (Pwned Passwords)
        /// <summary>
        /// Comprueba las contraseñas guardadas contra filtraciones públicas. Sale a Internet SOLO el prefijo de 5 caracteres del hash de
        /// cada una; ni la contraseña ni el hash completo. Solo cuando el usuario lo pide.
        /// </summary>
        public async Task AuditarAsync(CancellationToken ct = default)
        {
            if (_boveda is null || _ocupado) return;
            Actividad();
            Ocupado = true;
            _resumenDeAuditoria = "Comprobando... (sale a Internet solo un prefijo de 5 caracteres por contraseña)";
            _indicadorDeAuditoria = Indicador.SinDatos;
            _auditoria.Clear();
            _filtradas.Clear();
            Recalcular();
            IConsultaDeRangos? consulta = null;
            try
            {
                consulta = _consulta();
                ResultadoDeAuditoria r = await AuditoriaDeBoveda.AuditarAsync(_boveda, new ComprobadorDeContrasenas(consulta), null, ct);
                foreach (HallazgoDeFiltracion h in r.Filtradas)
                {
                    // Miles con punto (usos del español de Chile), sin depender de que la cultura «es-CL» exista en el equipo.
                    _auditoria[h.EntradaId] = "Filtrada (" + h.Apariciones.ToString("N0", System.Globalization.CultureInfo.InvariantCulture).Replace(',', '.') + " veces)";
                    _filtradas.Add(h.EntradaId);
                }
                foreach (Guid id in r.SinComprobar) _auditoria[id] = "Sin comprobar";
                foreach (Guid id in r.SinContrasena) _auditoria[id] = "Sin contraseña";
                foreach (EntradaDeBoveda e in _todas)
                    if (!_auditoria.ContainsKey(e.Id)) _auditoria[e.Id] = "No aparece en filtraciones conocidas";

                if (_todas.Count == 0 || (r.Filtradas.Count == 0 && r.SinComprobar.Count == 0 && r.NoEncontradas == 0))
                {
                    // Nada que comprobar (bóveda vacía, o solo entradas sin contraseña): no se dice «ninguna aparece», que sonaría a garantía.
                    _indicadorDeAuditoria = Indicador.SinDatos;
                    _resumenDeAuditoria = "No hay contraseñas que comprobar.";
                }
                else if (r.Filtradas.Count > 0)
                {
                    _indicadorDeAuditoria = Indicador.Alerta;
                    _resumenDeAuditoria = r.Filtradas.Count + (r.Filtradas.Count == 1 ? " contraseña aparece" : " contraseñas aparecen") + " en filtraciones públicas: cámbialas.";
                }
                else if (r.SinComprobar.Count > 0)
                {
                    _indicadorDeAuditoria = Indicador.Atencion;
                    _resumenDeAuditoria = r.SinComprobar.Count + (r.SinComprobar.Count == 1 ? " contraseña no se pudo comprobar" : " contraseñas no se pudieron comprobar") + " (¿sin Internet?): esto no significa que estén bien.";
                }
                else
                {
                    _indicadorDeAuditoria = Indicador.Correcto;
                    _resumenDeAuditoria = "Ninguna contraseña aparece en filtraciones conocidas. Esto no significa que sean fuertes: solo que no se han filtrado.";
                }
            }
            catch (OperationCanceledException)
            {
                _resumenDeAuditoria = null;
                _auditoria.Clear();
                throw;
            }
            finally
            {
                (consulta as IDisposable)?.Dispose();
                Ocupado = false;
                Recalcular();
            }
        }

        // ---------------------------------------------------------------- copia de seguridad
        private DateTime? _ultimaCopia;

        /// <summary>Recordatorio: la bóveda es UN archivo; si se pierde o se daña, se pierde todo. Dice si ya se hizo una copia en esta sesión.</summary>
        public string TextoDeCopia => _ultimaCopia is DateTime f
            ? "Última copia de esta sesión: " + f.ToString("dd/MM HH:mm", System.Globalization.CultureInfo.InvariantCulture) + "."
            : "Todavía no guardaste ninguna copia en esta sesión.";
        public bool HayCopiaReciente => _ultimaCopia is not null;

        /// <summary>true si se puede restaurar una copia: solo con la bóveda cerrada (o sin bóveda) y sin otra operación en curso.</summary>
        public bool PuedeRestaurar => _fase != FaseDeBoveda.Abierta && !_ocupado;

        /// <summary>true si ya hay una bóveda en el archivo: restaurar la APARTARÁ (no la borra) y la ventana lo pregunta antes.</summary>
        public bool ExisteBoveda => _fase == FaseDeBoveda.Bloqueada;

        public static string NombreSugeridoDeCopia() => "boveda-copia-" + DateTime.Now.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture) + ".nxv";

        /// <summary>
        /// Guarda una copia cifrada del estado actual donde elija el usuario (idealmente otro disco). Se verifica que la copia descifra antes de darla
        /// por buena. Una copia conserva lo que había en ese momento, incluso lo que se borre después: se avisa.
        /// </summary>
        public async Task<bool> GuardarCopiaAsync(string destino, bool sobrescribir = false)
        {
            if (_boveda is null || _fase != FaseDeBoveda.Abierta || _ocupado) return false;
            Actividad();
            Ocupado = true;
            Mensaje = "Guardando la copia...";
            try
            {
                await _boveda.ExportarCopiaAsync(destino, sobrescribir);
                _ultimaCopia = _reloj();
                Mensaje = "Copia guardada en «" + destino + "». Se abre con tu contraseña maestra actual. Contiene lo que hay ahora: si luego borras una entrada, seguirá en esta copia. Guárdala en un lugar seguro, mejor en otro disco.";
                return true;
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                Mensaje = "No se pudo guardar la copia: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
                Recalcular();
            }
        }

        /// <summary>
        /// Restaura una copia como la bóveda de este equipo. Antes de tocar nada comprueba que la copia abre con su contraseña. Si ya había una bóveda NO se
        /// borra: se aparta con fecha y hora. La bóveda restaurada queda BLOQUEADA: hay que abrirla con la contraseña maestra de la copia.
        /// </summary>
        public async Task<bool> RestaurarAsync(string rutaDeLaCopia, string contrasenaDeLaCopia, CancellationToken ct = default)
        {
            if (_ocupado || _fase == FaseDeBoveda.Abierta) return false;
            if (string.IsNullOrEmpty(contrasenaDeLaCopia)) { Mensaje = "Escribe primero la contraseña maestra de la copia."; return false; }

            Ocupado = true;
            Mensaje = "Comprobando la copia...";
            try
            {
                ResultadoDeRestauracion r = await Bov.RestaurarAsync(rutaDeLaCopia, contrasenaDeLaCopia, _ruta, ct);
                if (r.Restaurada)
                {
                    _fase = FaseDeBoveda.Bloqueada;
                    Mensaje = "Copia restaurada. Escribe la contraseña maestra de la copia para abrirla."
                              + (r.ArchivoAnterior is null ? "" : " La bóveda que había se guardó aparte como «" + r.ArchivoAnterior + "»: no se borró.");
                    return true;
                }
                Mensaje = r.Estado switch
                {
                    EstadoDeRestauracion.CopiaNoExiste => "El archivo de la copia no existe.",
                    EstadoDeRestauracion.CopiaIlegible => "El archivo no es una copia de bóveda de Nexo o está dañado. No se cambió nada.",
                    EstadoDeRestauracion.VersionNoSoportada => "La copia es de una versión más nueva de Nexo: actualiza Nexo para usarla. No se cambió nada.",
                    EstadoDeRestauracion.ParametrosFueraDeRango => "La copia pide parámetros de cifrado fuera de lo aceptable: Nexo no la usa. No se cambió nada.",
                    EstadoDeRestauracion.ContrasenaIncorrectaOArchivoAlterado => "Contraseña incorrecta, o la copia fue alterada: no se puede distinguir una cosa de la otra. No se cambió nada.",
                    EstadoDeRestauracion.DestinoEsLaCopia => "Elegiste el archivo de la propia bóveda: no hay nada que restaurar.",
                    _ => "No se pudo restaurar" + (r.Detalle is null ? "." : ": " + r.Detalle + ".")
                };
                return false;
            }
            catch (Exception ex) when (ex is ArgumentException)
            {
                Mensaje = "No se pudo restaurar: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
                Recalcular();
            }
        }

        // ---------------------------------------------------------------- contraseña maestra
        public async Task<bool> CambiarMaestraAsync(string actual, string nueva, string repetida, CancellationToken ct = default)
        {
            if (_boveda is null || _ocupado) return false;
            Actividad();
            if (nueva is null || nueva.Length < LongitudMinimaMaestra) { Mensaje = "La contraseña nueva debe tener al menos " + LongitudMinimaMaestra + " caracteres."; return false; }
            if (!string.Equals(nueva, repetida, StringComparison.Ordinal)) { Mensaje = "Las dos contraseñas nuevas no coinciden."; return false; }

            Ocupado = true;
            Mensaje = "Cambiando la contraseña maestra...";
            try
            {
                await _boveda.CambiarContrasenaMaestraAsync(actual ?? "", nueva, ct);
                Mensaje = "Contraseña maestra cambiada. La anterior ya no abre la bóveda.";
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Mensaje = "La contraseña maestra actual no es correcta.";
                return false;
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or InvalidOperationException)
            {
                Mensaje = "No se pudo cambiar: " + Motivo(ex);
                return false;
            }
            finally
            {
                Ocupado = false;
            }
        }

        // ---------------------------------------------------------------- internos
        private void CargarEntradas()
        {
            _todas = _boveda is null ? new List<EntradaDeBoveda>() : _boveda.Entradas.OrderBy(e => e.Sitio, StringComparer.CurrentCultureIgnoreCase).ThenBy(e => e.Usuario, StringComparer.CurrentCultureIgnoreCase).ToList();
            if (_seleccionada is Guid g && _todas.All(e => e.Id != g)) _seleccionada = null;
            Recalcular();
        }

        /// <summary>Todo: la lista y el estado. Se usa cuando cambian los datos, el filtro, la fase o los resultados de filtraciones.</summary>
        private void Recalcular()
        {
            ReconstruirLista();
            RecalcularEstado();
        }

        private bool _reconstruyendo;

        private void ReconstruirLista()
        {
            string f = _filtro.Trim();
            IEnumerable<EntradaDeBoveda> visibles = _todas.Where(e => f.Length == 0
                || e.Sitio.Contains(f, StringComparison.CurrentCultureIgnoreCase) || e.Usuario.Contains(f, StringComparison.CurrentCultureIgnoreCase));
            Entradas = visibles.Select(e =>
            {
                bool tiene = _auditoria.TryGetValue(e.Id, out string? texto);
                Indicador ind = !tiene ? Indicador.SinDatos : _filtradas.Contains(e.Id) ? Indicador.Alerta : texto == "Sin comprobar" ? Indicador.Atencion : texto == "Sin contraseña" ? Indicador.SinDatos : Indicador.Correcto;
                return new FilaDeEntrada(e.Id, e.Sitio, e.Usuario, tiene ? texto! : "", Colores.De(ind), tiene);
            }).ToList();

            // Con la lista nueva, el ListBox pierde su seleccion y empuja un null (que se ignora); despues se le avisa de cual es la fila elegida.
            _reconstruyendo = true;
            try
            {
                Avisar(nameof(Entradas));
                Avisar(nameof(Seleccionada));
            }
            finally
            {
                _reconstruyendo = false;
            }
        }

        /// <summary>Todo menos la lista y la seleccion: titulos, detalle, formulario, mensajes. Cambiar de fila solo necesita esto.</summary>
        private void RecalcularEstado()
        {
            (Titulo, Explicacion) = _fase switch
            {
                FaseDeBoveda.SinBoveda => ("Todavía no tienes una bóveda", "Crea una para guardar tus contraseñas cifradas en este equipo. Se cifra con AES-256-GCM y la clave sale de tu contraseña maestra con Argon2id. Nada sale de este equipo."),
                FaseDeBoveda.Bloqueada => ("La bóveda está bloqueada", "Escribe tu contraseña maestra para abrirla. No hay forma de recuperarla si la olvidas."),
                _ => ("Bóveda abierta: " + _todas.Count + (_todas.Count == 1 ? " entrada" : " entradas"), ResumenDeInactividad)
            };

            foreach (string n in new[]
                     {
                         nameof(Fase), nameof(EsSinBoveda), nameof(EsBloqueada), nameof(EsAbierta), nameof(Archivo), nameof(Mensaje), nameof(Ocupado), nameof(NoOcupado),
                         nameof(Titulo), nameof(Explicacion), nameof(Cantidad), nameof(HayEntradaSeleccionada),
                         nameof(DetalleVisible), nameof(DetalleSitio), nameof(DetalleUsuario), nameof(DetalleNotas), nameof(DetalleFechas), nameof(MostrarContrasena),
                         nameof(BotonMostrar), nameof(DetalleContrasena), nameof(EdicionVisible), nameof(EdicionTitulo), nameof(EdSitio), nameof(EdUsuario),
                         nameof(EdContrasena), nameof(EdNotas), nameof(CaracterDeClave), nameof(Auditoria), nameof(HayAuditoria), nameof(ColorDeAuditoria),
                         nameof(IndicadorDeAuditoria), nameof(ResumenDeInactividad), nameof(TextoDeCopia), nameof(HayCopiaReciente), nameof(PuedeRestaurar), nameof(ExisteBoveda)
                     })
                Avisar(n);
        }

        /// <summary>
        /// El motivo de una excepcion para mostrarlo al usuario: sin el sufijo tecnico que .NET añade a las de argumento («(Parameter 'x')», o
        /// «(Parámetro 'x')» en un sistema en español).
        /// </summary>
        internal static string Motivo(Exception ex)
            => System.Text.RegularExpressions.Regex.Replace(ex.Message, @"\s*\((?:Parameter|Parámetro) '[^']*'\)\s*$", "");

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));

        public void Dispose() => Bloquear();
    }
}
