using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Escaner;
using Nexo.Reports;

namespace Nexo.Service
{
    /// <summary>
    /// Escaneo periodico de unas carpetas fijas, lanzado por el propio servicio.
    ///
    /// Decisiones de seguridad (las mismas que el tiempo real):
    ///  - Se configura SOLO en appsettings.json (carpeta del servicio, que solo Administradores escriben). No hay metodos
    ///    del pipe para activarlo, apagarlo, cambiar las carpetas ni el intervalo: un proceso del usuario los usaria
    ///    para quitar la proteccion.
    ///  - Solo DETECTA. Nunca mueve ni borra: llevar algo a cuarentena sigue siendo el flujo con vista previa y token,
    ///    usando el id de escaneo <see cref="IdDeEscaneo"/>.
    ///  - No hay llamador al que suplantar, asi que lee con la cuenta del servicio (por eso las carpetas las fija el
    ///    administrador y no el cliente).
    ///
    /// Honestidad del estado: «limpio» solo si el escaneo termino COMPLETO y sin nada omitido. Un escaneo incompleto, o que
    /// fallo, no cuenta como hecho: no se guarda como ultimo completo y se reintenta antes. Si el equipo estuvo apagado y
    /// la fecha ya paso, al arrancar se ejecuta (con una espera corta), no se espera a la proxima vuelta del intervalo.
    /// </summary>
    public sealed class ModuloEscaneoProgramado : IModuloDelServicio, IResultadosDeEscaneo, IAsyncDisposable
    {
        public const string IdDeEscaneo = "programado";

        public static readonly TimeSpan IntervaloMinimo = TimeSpan.FromMinutes(1);
        public static readonly TimeSpan IntervaloPorDefecto = TimeSpan.FromHours(24);
        public static readonly TimeSpan ReintentoPorDefecto = TimeSpan.FromHours(1);
        public static readonly TimeSpan EsperaInicialPorDefecto = TimeSpan.FromMinutes(2);

        private readonly IMotorDeFirmas _motor;
        private readonly IReportWriter _reportes;
        private readonly IReadOnlyList<string> _raices;
        private readonly IReadOnlyList<string> _excluir;
        private readonly TimeSpan _intervalo;
        private readonly TimeSpan _reintento;
        private readonly TimeSpan _esperaInicial;
        private readonly string _archivoDeEstado;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _esperar;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly object _candado = new object();
        private Task? _bucle;

        // Estado visible (bajo _candado).
        private DateTimeOffset? _ultimoCompleto;
        private DateTimeOffset? _ultimoIntento;
        private string _ultimoResultado = "nunca";   // nunca | limpio | con_detecciones | incompleto | fallido
        private string? _motivo;
        private int _analizados;
        private int _omitidos;
        private bool _corriendo;
        private DateTimeOffset? _proxima;
        private ResultadoDeEscaneo? _ultimo;
        private string? _avisoDeEstado;

        public ModuloEscaneoProgramado(
            IMotorDeFirmas motor, IReportWriter reportes, IEnumerable<string> raices, TimeSpan intervalo, string archivoDeEstado,
            IEnumerable<string>? excluir = null, TimeSpan? reintento = null, TimeSpan? esperaInicial = null,
            Func<DateTimeOffset>? reloj = null, Func<TimeSpan, CancellationToken, Task>? esperar = null)
        {
            _motor = motor;
            _reportes = reportes;
            _raices = raices.ToList();
            _excluir = (excluir ?? Array.Empty<string>()).ToList();
            _intervalo = intervalo < IntervaloMinimo ? IntervaloMinimo : intervalo;
            _reintento = reintento ?? ReintentoPorDefecto;
            _esperaInicial = esperaInicial ?? EsperaInicialPorDefecto;
            _archivoDeEstado = archivoDeEstado;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _esperar = esperar ?? ((t, ct) => Task.Delay(t, ct));
        }

        /// <summary>Un escaneo programado termino COMPLETO: mismas semantica y firma que el del pipe (el tiempo real lo usa).</summary>
        public event Action<IReadOnlyList<string>, DateTimeOffset, ResultadoDeEscaneo>? EscaneoCompleto;

        public IReadOnlyList<string> Metodos { get; } = new[] { "escaneo-programado.estado", "escaneo-programado.detecciones" };

        /// <summary>Quita las carpetas que el servicio no aceptaria escanear (mismas reglas que el pipe). Devuelve las validas.</summary>
        public static IReadOnlyList<string> Validar(IEnumerable<string> raices, out IReadOnlyList<string> rechazadas)
        {
            var ok = new List<string>();
            var mal = new List<string>();
            foreach (string r in raices)
            {
                string t = r.Trim();
                string? motivo = ModuloEscaneo.MotivoDeRechazo(t);
                if (motivo is null) ok.Add(t); else mal.Add(t + " (" + motivo + ")");
            }
            rechazadas = mal;
            return ok;
        }

        public void Iniciar()
        {
            if (_bucle is not null) return;
            CargarEstado();
            _bucle = Task.Run(() => BucleAsync(_cts.Token));
        }

        // ------------------------------------------------------------
        private async Task BucleAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    TimeSpan espera = CalcularEspera();
                    lock (_candado) _proxima = _reloj() + espera;
                    if (espera > TimeSpan.Zero) await _esperar(espera, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    await EjecutarUnaVezAsync(ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
        }

        /// <summary>Cuanto falta para el proximo escaneo: segun el ultimo COMPLETO, o el ultimo intento fallido.</summary>
        internal TimeSpan CalcularEspera()
        {
            DateTimeOffset ahora = _reloj();
            DateTimeOffset? completo, intento;
            string resultado;
            lock (_candado) { completo = _ultimoCompleto; intento = _ultimoIntento; resultado = _ultimoResultado; }

            // Un intento fallido o incompleto posterior al ultimo completo se reintenta antes que el intervalo normal.
            if (intento is not null && (completo is null || intento > completo) && resultado is "incompleto" or "fallido")
                return Max(TimeSpan.Zero, intento.Value + _reintento - ahora);

            if (completo is null) return _esperaInicial;
            // Un reloj atrasado (ultimo completo «en el futuro») no debe posponer el escaneo mas de un intervalo.
            DateTimeOffset vence = completo.Value + _intervalo;
            if (vence > ahora + _intervalo) vence = ahora + _intervalo;
            return Max(TimeSpan.Zero, vence - ahora);
        }

        private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

        /// <summary>Un escaneo ahora mismo. Interno: lo llama el bucle y las pruebas; no hay forma de pedirlo por el pipe.</summary>
        internal async Task EjecutarUnaVezAsync(CancellationToken ct)
        {
            DateTimeOffset inicio = _reloj();
            lock (_candado) { _corriendo = true; _ultimoIntento = inicio; _proxima = null; }
            ResultadoDeEscaneo? r = null;
            string resultado;
            string? motivo = null;
            try
            {
                // Con el motor caido no se arranca un escaneo que fallara: se anota y se reintenta.
                await _motor.VersionAsync(ct).ConfigureAwait(false);
                var opciones = new OpcionesDeEscaneo { Excluir = _excluir, Paralelismo = 2 };
                r = await new EscanerBajoDemanda(_motor, _reportes, opciones).EscanearAsync(_raices, null, ct).ConfigureAwait(false);

                if (r.Incompleto) { resultado = "incompleto"; motivo = r.MotivoIncompleto ?? "no se pudo revisar todo"; }
                else if (r.Detecciones.Count > 0) resultado = "con_detecciones";
                else if (r.CompletamenteLimpio) resultado = "limpio";
                else { resultado = "incompleto"; motivo = "quedaron " + r.Omitidos.Count + " elementos sin analizar"; }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                lock (_candado) _corriendo = false;
                throw;
            }
            catch (MotorNoDisponibleException ex) { resultado = "fallido"; motivo = "el motor de analisis no esta disponible: " + ex.Message; }
            catch (Exception) { resultado = "fallido"; motivo = "el escaneo fallo por un error interno"; }

            // «Completo» = termino sin quedar incompleto (con o sin detecciones): es lo que reinicia el intervalo.
            bool completo = resultado is "limpio" or "con_detecciones";
            lock (_candado)
            {
                _corriendo = false;
                _ultimoResultado = resultado;
                _motivo = motivo;
                if (r is not null) { _analizados = r.Analizados; _omitidos = r.Omitidos.Count; _ultimo = r; }
                if (completo) _ultimoCompleto = inicio;
            }
            if (completo)
            {
                GuardarEstado(inicio);
                try { EscaneoCompleto?.Invoke(_raices, inicio, r!); }
                catch (Exception) { /* un suscriptor roto no cambia el resultado del escaneo */ }
            }
        }

        // ------------------------------------------------------------
        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
        {
            switch (metodo)
            {
                case "escaneo-programado.estado":
                    lock (_candado)
                    {
                        DateTimeOffset ahora = _reloj();
                        // «vencido»: nunca hubo un escaneo completo, o ya paso un intervalo entero sin otro (el equipo estuvo
                        // apagado o los intentos fallan). Nunca se presenta «sin noticias» como «al dia».
                        bool vencido = _ultimoCompleto is null || ahora - _ultimoCompleto.Value > _intervalo;
                        return Task.FromResult<object?>(new
                        {
                            activo = true,
                            raices = _raices,
                            intervalo_horas = Math.Round(_intervalo.TotalHours, 2),
                            corriendo = _corriendo,
                            ultimo_resultado = _ultimoResultado,
                            ultimo_completo = _ultimoCompleto,
                            ultimo_intento = _ultimoIntento,
                            proxima = _proxima,
                            vencido,
                            motivo = _motivo,
                            analizados = _analizados,
                            omitidos = _omitidos,
                            detecciones = _ultimo?.Detecciones.Count ?? 0,
                            aviso = _avisoDeEstado,
                            nota = "Detecta y avisa; no borra ni mueve nada. Lee con la cuenta del servicio, en las carpetas fijadas en appsettings.json."
                        });
                    }

                case "escaneo-programado.detecciones":
                    lock (_candado)
                        return Task.FromResult<object?>(new
                        {
                            id_escaneo = IdDeEscaneo,
                            detecciones = (_ultimo?.Detecciones ?? Array.Empty<Deteccion>())
                                .Select(d => new { ruta = d.Ruta, firma = d.Firma, bytes = d.Bytes, sha256 = d.Sha256, modificado = d.Modificado }).ToList()
                        });

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        public ResultadoDeEscaneo? Obtener(string id)
        {
            if (id != IdDeEscaneo) return null;
            lock (_candado) return _ultimo;
        }

        // ------------------------------------------------------------
        internal void CargarEstado()
        {
            try
            {
                if (!File.Exists(_archivoDeEstado)) return;
                using JsonDocument d = JsonDocument.Parse(File.ReadAllText(_archivoDeEstado));
                if (d.RootElement.TryGetProperty("ultimo_completo", out JsonElement v) && v.ValueKind == JsonValueKind.String
                    && DateTimeOffset.TryParse(v.GetString(), null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset t))
                {
                    // El detalle del resultado anterior no se guarda: solo se sabe CUANDO termino uno completo.
                    lock (_candado) { _ultimoCompleto = t; _ultimoResultado = "desconocido"; }
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            {
                // Sin registro legible: se trata como «nunca». Se dice, no se oculta.
                lock (_candado) _avisoDeEstado = "No se pudo leer el registro del ultimo escaneo; se escaneara como si no hubiera uno.";
            }
        }

        private void GuardarEstado(DateTimeOffset completo)
        {
            try
            {
                string? dir = Path.GetDirectoryName(_archivoDeEstado);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                string tmp = _archivoDeEstado + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(new { ultimo_completo = completo.ToString("o") }));
                File.Move(tmp, _archivoDeEstado, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // Si no se puede guardar, tras un reinicio se volvera a escanear antes de tiempo: es lo seguro.
                lock (_candado) _avisoDeEstado = "No se pudo guardar el registro del ultimo escaneo; tras reiniciar se repetira.";
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            if (_bucle is not null)
                await Task.WhenAny(_bucle, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
            _cts.Dispose();
        }
    }

    /// <summary>Lo que contesta el servicio con el escaneo programado apagado: la interfaz lo dice claramente.</summary>
    public sealed class ModuloEscaneoProgramadoApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "escaneo-programado.estado", "escaneo-programado.detecciones" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo switch
            {
                "escaneo-programado.estado" => Task.FromResult<object?>(new
                {
                    activo = false,
                    vencido = true,
                    nota = "El escaneo programado esta apagado. Se activa en appsettings.json (Nexo:EscaneoProgramado:Activo)."
                }),
                "escaneo-programado.detecciones" => Task.FromResult<object?>(new { id_escaneo = ModuloEscaneoProgramado.IdDeEscaneo, detecciones = Array.Empty<object>() }),
                _ => throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido")
            };
    }
}
