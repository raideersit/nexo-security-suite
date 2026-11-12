using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// Copia versionada (§2ap/§2aq del traspaso). Apagada por omisión: se activa solo en appsettings.json (Nexo:Copia:Activo).
    ///
    /// Por el pipe solo hay TRES métodos: <c>copia.estado</c>, <c>copia.hacer</c> (hacer una instantánea ahora) y <c>copia.descartar</c>
    /// (dar por buena una copia sospechosa, por su id: el destino es siempre el configurado, nunca una ruta que mande el cliente).
    /// No hay método de restaurar a propósito: el servicio corre como SYSTEM y no debe escribir donde le diga un proceso cualquiera;
    /// restaurar lo hace la ventana, con los permisos de la persona (solo necesita leer). Tampoco hay métodos para cambiar el destino
    /// ni las carpetas.
    ///
    /// La carpeta de copias se protege con permisos (solo SYSTEM y Administradores escriben) al crearla, y por eso «descartar» tuvo que
    /// pasar al servicio: la ventana, con los permisos de la persona, ya no puede reescribir la lista de una copia. Si el disco no admite
    /// permisos o no se pudo proteger, la copia se hace igual y el estado lleva <c>aviso_proteccion</c>.
    ///
    /// Copiar no cambia nada del usuario, así que no pide aprobación; sí tiene tope de frecuencia (un minuto entre copias) y una
    /// sola a la vez, para que un proceso no pueda saturar el disco. Si el destino (un disco externo) no está conectado, no es un
    /// error: se dice «destino no disponible» y se espera.
    /// </summary>
    public sealed class ModuloCopia : IModuloDelServicio, IAsyncDisposable
    {
        public const int CopiaEnCurso = -32012;
        public const int DemasiadoPronto = -32013;
        public static readonly TimeSpan EntreCopiasMinimo = TimeSpan.FromMinutes(1);

        private readonly Func<(IReadOnlyList<string> Carpetas, IReadOnlyList<CarpetaSinSenuelo> Descartadas)> _carpetas;
        private readonly string _destino;
        private readonly int _versiones;
        private readonly TimeSpan? _cada;
        private readonly IReportWriter _reportes;
        private readonly Func<ConfiguracionDeCopia, DateTimeOffset, CancellationToken, ResultadoDeCopia> _copiar;
        private readonly Func<string, bool> _destinoDisponible;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _esperar;
        private readonly Func<string, string?>? _proteger;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly SemaphoreSlim _paso = new SemaphoreSlim(1, 1);
        private readonly object _candado = new object();
        private Task? _bucle;
        private DateTimeOffset? _ultimoInicio;
        private DateTimeOffset? _ultimoIntento;
        private ResultadoDeCopia? _ultimo;
        private DateTimeOffset? _ultimaCorrecta;
        private string? _motivoDeEspera;
        private string? _avisoDeProteccion;       // por qué la última copia dejó las copias SIN proteger (null = protegidas, o aún no se sabe)
        // Cuántas copias sospechosas hay guardadas en el destino. Se lee del disco una vez y tras cada copia (no en cada consulta: la bandeja pregunta cada 5 s).
        private int? _sospechosas;
        private string? _firmaDeListas;   // con qué estado de las listas se contó; si cambia (p. ej. la persona descarta una sospecha), se vuelve a contar

        public ModuloCopia(Func<(IReadOnlyList<string>, IReadOnlyList<CarpetaSinSenuelo>)> carpetas, string destino, int versiones, TimeSpan? cada, IReportWriter reportes,
                           Func<ConfiguracionDeCopia, DateTimeOffset, CancellationToken, ResultadoDeCopia>? copiar = null,
                           Func<string, bool>? destinoDisponible = null, Func<DateTimeOffset>? reloj = null, Func<TimeSpan, CancellationToken, Task>? esperar = null,
                           Func<string, string?>? proteger = null, bool protegerPorOmision = true)
        {
            _carpetas = carpetas;
            _destino = destino;
            _versiones = Math.Max(1, versiones);
            _cada = cada;
            _reportes = reportes;
            _copiar = copiar ?? ((c, t, ct) => CopiaVersionada.Copiar(c, t, ct));
            _destinoDisponible = destinoDisponible ?? DestinoDisponiblePorOmision;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _esperar = esperar ?? ((t, ct) => Task.Delay(t, ct));
            // En Windows, por omisión se protege la carpeta con permisos NTFS; las pruebas portables pasan su propio gancho (o protegerPorOmision: false).
            _proteger = proteger ?? (protegerPorOmision && OperatingSystem.IsWindows() ? Nexo.Modules.Threats.Windows.ProteccionDeCopiaWindows.Proteger : null);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "copia.estado", "copia.hacer", "copia.descartar" };

        /// <summary>Perfiles de actividad (§2az): la copia AUTOMÁTICA pregunta aquí antes de arrancar. «Copiar ahora» (a mano) nunca espera.</summary>
        public Nexo.Modules.Cleanup.Perfiles.PuertaDeTareasPesadas Puerta { get; set; } = Nexo.Modules.Cleanup.Perfiles.PuertaDeTareasPesadas.Abierta;

        /// <summary>El destino cuenta como disponible si existe la raíz de su unidad (el disco externo está conectado).</summary>
        public static bool DestinoDisponiblePorOmision(string destino)
        {
            try
            {
                string? raiz = Path.GetPathRoot(Path.GetFullPath(destino));
                return !string.IsNullOrEmpty(raiz) && Directory.Exists(raiz);
            }
            catch { return false; }
        }

        public void Iniciar()
        {
            if (_bucle is not null || _cada is null) return;
            _bucle = Task.Run(() => BucleAsync(_cts.Token));
        }

        private async Task BucleAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await VueltaAsync(ct).ConfigureAwait(false);
                    await _esperar(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
        }

        /// <summary>Una vuelta del bucle automático: si toca, el destino está y hace falta, copia. Interno: lo usan las pruebas.</summary>
        internal async Task VueltaAsync(CancellationToken ct)
        {
            if (_cada is null) return;
            DateTimeOffset ahora = _reloj();
            lock (_candado)
            {
                // Se cuenta desde el último INTENTO, no desde la última copia buena: un destino roto no debe reintentarse cada minuto.
                if (_ultimoIntento is { } u && ahora - u < _cada.Value) return;
            }
            // Un juego, un vídeo o la batería posponen el ARRANQUE (con un máximo de espera); una copia ya empezada no se interrumpe.
            if (!Puerta.Permite("copia", ahora)) return;
            // Sin el disco conectado HacerAsync no copia ni cuenta el intento: en cuanto se conecte, copia.
            try { await HacerAsync(automatica: true, ct).ConfigureAwait(false); }
            catch (ErrorDeComando) { /* ya hay una en curso: la siguiente vuelta lo verá */ }
            finally { Puerta.Terminada("copia"); }
        }

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "copia.estado":
                    return Estado();
                case "copia.hacer":
                    return await HacerAsync(automatica: false, ct).ConfigureAwait(false);
                case "copia.descartar":
                    return await DescartarAsync(p, ct).ConfigureAwait(false);
                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        /// <summary>
        /// La persona revisó una copia sospechosa y la da por buena. Solo recibe el id (texto de la forma 20261112T201222Z, con sufijo opcional
        /// «-N»): el destino es el configurado, así que no se puede apuntar el servicio (SYSTEM) a otra ruta. No espera a una copia en curso:
        /// se turna con ella para no reescribir una lista mientras se podan.
        /// </summary>
        private async Task<object> DescartarAsync(JsonElement? p, CancellationToken ct)
        {
            string? id = null;
            if (p is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty("id", out JsonElement v) && v.ValueKind == JsonValueKind.String) id = v.GetString();
            if (string.IsNullOrEmpty(id) || id.Length > 40 || !id.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta el id de la copia (solo letras, números y guion)");
            if (!await _paso.WaitAsync(0, ct).ConfigureAwait(false))
                throw new ErrorDeComando(CopiaEnCurso, "ya hay una copia en marcha: espera a que termine");
            try
            {
                if (!_destinoDisponible(_destino)) return new { exito = false, error = "El destino no está disponible. ¿Está conectado el disco externo?" };
                (bool ok, string? error) = await Task.Run(() => CopiaVersionada.DescartarSospecha(_destino, id), ct).ConfigureAwait(false);
                if (ok)
                {
                    int? sosp = ContarSospechosas();
                    lock (_candado) { if (sosp is not null) _sospechosas = sosp; _firmaDeListas = CopiaVersionada.FirmaDeLasListas(_destino); }
                }
                return new { exito = ok, error };
            }
            finally { _paso.Release(); }
        }

        private async Task<object> HacerAsync(bool automatica, CancellationToken ct)
        {
            if (!await _paso.WaitAsync(0, ct).ConfigureAwait(false))
                throw new ErrorDeComando(CopiaEnCurso, "ya hay una copia en marcha");
            try
            {
                DateTimeOffset ahora = _reloj();
                // Primero el destino: un intento sin disco no cuenta para el tope de frecuencia (si no, conectar el disco y pedir
                // la copia al instante daría «demasiado pronto»).
                if (!_destinoDisponible(_destino))
                {
                    lock (_candado) { _motivoDeEspera = "el destino no está disponible (¿el disco externo está conectado?)"; }
                    return new { exito = false, error = "El destino no está disponible. ¿Está conectado el disco externo?" };
                }
                lock (_candado)
                {
                    if (!automatica && _ultimoInicio is { } u && ahora - u < EntreCopiasMinimo)
                        throw new ErrorDeComando(DemasiadoPronto, "hubo una copia hace menos de un minuto: espera un poco");
                    _ultimoInicio = ahora;
                    _ultimoIntento = ahora;
                }

                (IReadOnlyList<string> carpetas, _) = _carpetas();
                var cfg = new ConfiguracionDeCopia(carpetas.Where(Directory.Exists).ToList(), _destino, _versiones, ProtegerCarpeta: _proteger);
                // La copia lee y hashea todo: fuera del hilo del pipe.
                ResultadoDeCopia r = await Task.Run(() => _copiar(cfg, ahora, ct), ct).ConfigureAwait(false);
                int? sosp = r.Correcto ? ContarSospechosas() : null;
                lock (_candado)
                {
                    if (sosp is not null) { _sospechosas = sosp; _firmaDeListas = CopiaVersionada.FirmaDeLasListas(_destino); }
                    _ultimo = r;
                    _avisoDeProteccion = r.AvisoDeProteccion;
                    _motivoDeEspera = null;
                    if (r.Correcto) _ultimaCorrecta = ahora;
                }
                await EscribirEventoAsync(r, ct).ConfigureAwait(false);
                return new
                {
                    exito = r.Correcto,
                    error = r.Error,
                    id = r.Instantanea?.Id,
                    archivos = r.Instantanea?.Entradas.Count ?? 0,
                    nuevos = r.ArchivosNuevos,
                    omitidos = r.Instantanea?.Omitidos.Count ?? 0,
                    sospechosa = r.Instantanea?.Sospechosa ?? false,
                    motivo_sospecha = r.Instantanea?.MotivoSospecha,
                    aviso_proteccion = r.AvisoDeProteccion
                };
            }
            finally { _paso.Release(); }
        }

        private async Task EscribirEventoAsync(ResultadoDeCopia r, CancellationToken ct)
        {
            NexoEvent e;
            if (!r.Correcto)
            {
                e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.CopiaFallida, "La copia de seguridad falló")
                { Severidad = Severidad.Media, Accion = Accion.Registrada, Cuerpo = r.Error ?? "sin detalle" };
            }
            else if (r.Instantanea!.Sospechosa)
            {
                e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.CopiaSospechosa, "Copia de seguridad: muchos archivos cambiaron de golpe")
                {
                    Severidad = Severidad.Alta,
                    Accion = Accion.Registrada,
                    Cuerpo = r.Instantanea.MotivoSospecha + "\n\nNexo conservó todas las versiones anteriores. No restaures ni borres nada hasta revisar."
                };
            }
            else
            {
                e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.CopiaHecha, "Copia de seguridad hecha")
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = r.Instantanea!.Entradas.Count + " archivos (" + r.ArchivosNuevos + " nuevos, " + r.ArchivosReutilizados + " sin cambios); "
                             + r.Instantanea.Omitidos.Count + " omitidos."
                };
            }
            if (r.Instantanea is not null)
            {
                e.Campos["archivos"] = r.Instantanea.Entradas.Count;
                e.Campos["omitidos"] = r.Instantanea.Omitidos.Count;
            }
            try { await _reportes.EscribirAsync(e, ct).ConfigureAwait(false); }
            catch (Exception) when (!ct.IsCancellationRequested) { /* el vault puede no estar: la copia ya se hizo */ }
        }

        private int? ContarSospechosas()
        {
            try { return CopiaVersionada.Listar(_destino, out _).Count(i => i.Sospechosa); }
            catch { return null; }
        }

        private string? AvisoDeProteccion() { lock (_candado) return _avisoDeProteccion; }

        private object Estado()
        {
            ResultadoDeCopia? u; DateTimeOffset? ok; string? espera; DateTimeOffset? intento;
            lock (_candado) { u = _ultimo; ok = _ultimaCorrecta; espera = _motivoDeEspera; intento = _ultimoIntento; }
            bool disponible = _destinoDisponible(_destino);
            if (disponible)
            {
                string firma = CopiaVersionada.FirmaDeLasListas(_destino);
                bool falta; lock (_candado) falta = _sospechosas is null || _firmaDeListas != firma;
                if (falta) { int? c = ContarSospechosas(); lock (_candado) { _sospechosas = c ?? _sospechosas; _firmaDeListas = firma; } }
            }
            int? sospechosas; lock (_candado) sospechosas = _sospechosas;
            (IReadOnlyList<string> carpetas, IReadOnlyList<CarpetaSinSenuelo> descartadas) = _carpetas();
            int versiones = 0, ilegibles = 0;
            if (disponible)
            {
                try { versiones = CopiaVersionada.Listar(_destino, out ilegibles).Count; } catch { ilegibles = 1; }
            }
            return new
            {
                activo = true,
                destino = _destino,
                destino_disponible = disponible,
                versiones_a_conservar = _versiones,
                versiones_en_destino = versiones,
                listas_ilegibles = ilegibles,
                // null = no se sabe (el disco no ha estado conectado desde que arrancó el servicio).
                sospechosas_guardadas = sospechosas,
                automatica_cada_horas = _cada is null ? (double?)null : _cada.Value.TotalHours,
                en_curso = _paso.CurrentCount == 0,
                ultimo_intento = intento,
                ultima_correcta = ok,
                ultimo = u is null ? null : new
                {
                    correcto = u.Correcto,
                    error = u.Error,
                    archivos = u.Instantanea?.Entradas.Count ?? 0,
                    nuevos = u.ArchivosNuevos,
                    reutilizados = u.ArchivosReutilizados,
                    omitidos = u.Instantanea?.Omitidos.Count ?? 0,
                    primeros_omitidos = (u.Instantanea?.Omitidos ?? Array.Empty<OmitidoEnCopia>()).Take(20).Select(o => new { ruta = o.Ruta, motivo = o.Motivo }).ToList(),
                    sospechosa = u.Instantanea?.Sospechosa ?? false,
                    motivo_sospecha = u.Instantanea?.MotivoSospecha,
                    podadas = u.Podadas,
                    poda_suspendida = u.PodaSuspendida,
                    motivo_poda = u.MotivoDePoda
                },
                carpetas,
                sin_copia = descartadas.Select(x => new { carpeta = x.Carpeta, motivo = x.Motivo }).ToList(),
                aviso = espera,
                // null = protegida por la última copia, o todavía no se ha hecho ninguna en esta sesión del servicio.
                aviso_proteccion = AvisoDeProteccion(),
                nota = "La copia no está cifrada. La carpeta de copias solo la pueden cambiar SYSTEM y los administradores, pero un programa con permisos de administrador sí podría borrarla: lo ideal es un disco externo que solo se conecta para copiar."
            };
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            if (_bucle is not null)
            {
                try { await _bucle.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); }
                catch (TimeoutException) { }
            }
            _cts.Dispose();
        }
    }

    public sealed class ModuloCopiaApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "copia.estado", "copia.hacer", "copia.descartar" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo switch
            {
                "copia.estado" => Task.FromResult<object?>(new
                {
                    activo = false,
                    nota = "La copia versionada está apagada. Se activa en appsettings.json (Nexo:Copia:Activo y Nexo:Copia:Destino)."
                }),
                "copia.hacer" or "copia.descartar" => throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "la copia versionada está apagada"),
                _ => throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido")
            };
    }
}
