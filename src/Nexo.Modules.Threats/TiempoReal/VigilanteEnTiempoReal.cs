using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.TiempoReal
{
    /// <summary>
    /// Analisis al vuelo de los archivos que cambian. En MODO USUARIO: detecta y avisa
    /// DESPUES de que el archivo se escribio; no puede impedir que se cree ni que se ejecute
    /// (eso exigiria un driver de minifiltro, fuera de alcance; ver README). Complementa a
    /// Windows Defender, que si bloquea; no lo sustituye.
    ///
    /// Reglas que gobiernan esta clase (las mismas del escaner, §«no pude leer != esta bien»):
    ///   - Lo que NO se pudo analizar (bloqueado, sin permisos, demasiado grande, motor caido)
    ///     se CUENTA como no analizado. Nunca se presenta como limpio.
    ///   - Lo que se descarta por exceso de pendientes se cuenta como PERDIDO (archivos distintos, no
    ///     eventos). Un desborde de la fuente se cuenta aparte: no se sabe cuantos archivos fueron.
    ///   - Las carpetas de lo perdido o no analizado quedan POR REVISAR hasta que un escaneo bajo demanda
    ///     completo las cubra (<see cref="MarcarRevisado"/>). Lo perdido no se olvida en silencio.
    ///   - No actua sobre los archivos: solo registra y avisa. Retirar un archivo es otra
    ///     accion, con vista previa y token (cuarentena).
    ///   - Un archivo se espera hasta que deja de cambiar antes de analizarlo, y no se
    ///     reanaliza si no cambio desde la ultima vez.
    /// </summary>
    public sealed class VigilanteEnTiempoReal : IDisposable
    {
        private const int MaxDeteccionesGuardadas = 200;
        private const int MaxVistos = 20000;
        private const int MaxRutasPerdidas = 100_000;
        private const int MaxCarpetasPorRevisar = 1000;

        private sealed class Pend
        {
            public DateTimeOffset Toca;
            public int Reintentos;
        }

        private readonly IMotorDeFirmas _motor;
        private readonly IReportWriter _reportes;
        private readonly OpcionesDeTiempoReal _opciones;
        private readonly FiltroDeCambios _filtro;
        private readonly Func<DateTimeOffset> _reloj;

        private readonly Dictionary<string, Pend> _pendientes = new Dictionary<string, Pend>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (long Bytes, long Ticks)> _vistos = new Dictionary<string, (long, long)>(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<string> _ordenVistos = new Queue<string>();
        private readonly List<Deteccion> _detecciones = new List<Deteccion>();
        private readonly HashSet<string> _rutasPerdidas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Carpeta -> ultima vez que se perdio o no se analizo algo en ella.
        private readonly Dictionary<string, DateTimeOffset> _porRevisar = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        private readonly object _candado = new object();
        private readonly CancellationTokenSource _parar = new CancellationTokenSource();

        private IFuenteDeCambios? _fuente;
        private Task? _bucle;
        private long _vistosN, _descartados, _analizados, _noAnalizados, _desbordesDeFuente;
        private bool _perdidasDesbordadas;           // se paso de MaxRutasPerdidas: Perdidos es un minimo
        private DateTimeOffset? _revisarTodoDesde;   // perdida sin carpeta conocida (desborde de la fuente): todo por revisar
        private int _erroresSeguidos;
        private volatile bool _motorCaido;
        private volatile string? _ultimoAviso;

        public VigilanteEnTiempoReal(
            IMotorDeFirmas motor, IReportWriter reportes, OpcionesDeTiempoReal? opciones = null, Func<DateTimeOffset>? reloj = null)
        {
            _motor = motor;
            _reportes = reportes;
            _opciones = opciones ?? new OpcionesDeTiempoReal();
            _filtro = new FiltroDeCambios(_opciones);
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        /// <summary>Se dispara por cada deteccion (para notificar). No debe lanzar ni bloquear.</summary>
        public event Action<Deteccion>? Detectado;

        public void Iniciar(IFuenteDeCambios fuente)
        {
            if (_fuente is not null) throw new InvalidOperationException("Ya iniciado.");
            _fuente = fuente;
            _bucle = Task.Run(BucleAsync);
            fuente.Iniciar(AlCambiar, AlPerder);
        }

        public EstadoDeTiempoReal Estado()
        {
            int pendientes, detecciones, porRevisar;
            long perdidos;
            bool revisarTodo, perdidasDesbordadas;
            lock (_candado)
            {
                pendientes = _pendientes.Count; detecciones = _detecciones.Count; porRevisar = _porRevisar.Count;
                perdidos = _rutasPerdidas.Count; revisarTodo = _revisarTodoDesde is not null; perdidasDesbordadas = _perdidasDesbordadas;
            }
            return new EstadoDeTiempoReal(
                Activo: _fuente is not null && !_parar.IsCancellationRequested,
                CambiosVistos: Interlocked.Read(ref _vistosN),
                Descartados: Interlocked.Read(ref _descartados),
                Analizados: Interlocked.Read(ref _analizados),
                NoAnalizados: Interlocked.Read(ref _noAnalizados),
                Perdidos: perdidos,
                Pendientes: pendientes,
                MotorCaido: _motorCaido,
                Detecciones: detecciones,
                UltimoAviso: _ultimoAviso,
                DesbordesDeFuente: Interlocked.Read(ref _desbordesDeFuente),
                CarpetasPorRevisar: porRevisar,
                RevisarTodo: revisarTodo,
                PerdidosEsMinimo: perdidasDesbordadas);
        }

        public IReadOnlyList<Deteccion> Detecciones()
        {
            lock (_candado) return _detecciones.ToList();
        }

        // ============================================================
        //  ENTRADA
        // ============================================================
        private void AlCambiar(CambioDeArchivo c)
        {
            Interlocked.Increment(ref _vistosN);

            if (_filtro.MotivoParaIgnorar(c.Ruta) is not null) { Interlocked.Increment(ref _descartados); return; }

            DateTimeOffset toca = _reloj() + _opciones.Estabilizacion;
            lock (_candado)
            {
                if (_pendientes.TryGetValue(c.Ruta, out Pend? p))
                {
                    p.Toca = toca;           // sigue cambiando: se espera de nuevo
                    p.Reintentos = 0;
                    return;
                }
                if (_pendientes.Count >= _opciones.MaxPendientes)
                {
                    // No se aparenta que se vio: el ARCHIVO queda contado como perdido (una vez, aunque emita varios
                    // eventos) y su carpeta, por revisar.
                    if (_rutasPerdidas.Count < MaxRutasPerdidas) _rutasPerdidas.Add(c.Ruta);
                    else if (!_rutasPerdidas.Contains(c.Ruta)) _perdidasDesbordadas = true;
                    AnotarPorRevisar(c.Ruta);
                    _ultimoAviso = "demasiados archivos pendientes: se descartan cambios (perdidos)";
                    return;
                }
                _pendientes[c.Ruta] = new Pend { Toca = toca };
            }
        }

        private void AlPerder(string motivo)
        {
            // No se sabe que archivos ni cuantos: se cuenta el desborde y todo queda por revisar.
            Interlocked.Increment(ref _desbordesDeFuente);
            lock (_candado) _revisarTodoDesde = _reloj();
            _ultimoAviso = "la fuente de cambios perdio eventos: " + motivo;
        }

        /// <summary>Llamar con _candado tomado.</summary>
        private void AnotarPorRevisar(string ruta)
        {
            DateTimeOffset ahora = _reloj();
            string? carpeta = Path.GetDirectoryName(ruta);
            if (string.IsNullOrEmpty(carpeta) || (_porRevisar.Count >= MaxCarpetasPorRevisar && !_porRevisar.ContainsKey(carpeta)))
            {
                _revisarTodoDesde = ahora;     // demasiadas carpetas: se pide revisarlo todo
                return;
            }
            _porRevisar[carpeta] = ahora;
        }

        /// <summary>Carpetas donde algo se perdio o no se pudo analizar. <c>Todo</c>: hubo perdidas sin carpeta conocida.</summary>
        public PorRevisar CarpetasPorRevisar()
        {
            lock (_candado)
                return new PorRevisar(_porRevisar.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList(), _revisarTodoDesde is not null);
        }

        /// <summary>
        /// Un escaneo bajo demanda COMPLETO empezado en <paramref name="inicio"/> cubrio <paramref name="raicesEscaneadas"/>.
        /// Se dan por revisadas las carpetas que quedan dentro, salvo las que el escaneo no pudo leer y las que volvieron a
        /// perder algo despues de empezar. «Todo» solo se limpia si el escaneo cubrio todas las raices vigiladas.
        /// </summary>
        public void MarcarRevisado(IReadOnlyCollection<string> raicesEscaneadas, IReadOnlyCollection<string> carpetasNoLeidas,
                                   bool cubreTodasLasRaices, DateTimeOffset inicio)
        {
            lock (_candado)
            {
                foreach (string carpeta in _porRevisar.Keys.ToList())
                {
                    if (_porRevisar[carpeta] >= inicio) continue;
                    if (!raicesEscaneadas.Any(r => Contiene(r, carpeta))) continue;
                    if (carpetasNoLeidas.Any(n => Contiene(n, carpeta) || Contiene(carpeta, n))) continue;
                    _porRevisar.Remove(carpeta);
                }
                if (_revisarTodoDesde is { } t && t < inicio && cubreTodasLasRaices && carpetasNoLeidas.Count == 0)
                    _revisarTodoDesde = null;
            }
        }

        /// <summary>True si <paramref name="ruta"/> es <paramref name="raiz"/> o esta dentro (sin confundir C: con C:b).</summary>
        public static bool Contiene(string raiz, string ruta)
        {
            string r = raiz.TrimEnd('\\', '/');
            if (string.Equals(r, ruta.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) return true;
            return ruta.Length > r.Length && ruta.StartsWith(r, StringComparison.OrdinalIgnoreCase) && (ruta[r.Length] is '\\' or '/');
        }

        // ============================================================
        //  BUCLE
        // ============================================================
        private async Task BucleAsync()
        {
            CancellationToken ct = _parar.Token;
            using var cupo = new SemaphoreSlim(Math.Max(1, _opciones.Trabajadores));
            var enCurso = new List<Task>();

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(_opciones.Sondeo, ct).ConfigureAwait(false);

                    List<string> listos;
                    DateTimeOffset ahora = _reloj();
                    lock (_candado)
                        listos = _pendientes.Where(kv => kv.Value.Toca <= ahora).Select(kv => kv.Key).ToList();

                    foreach (string ruta in listos)
                    {
                        await cupo.WaitAsync(ct).ConfigureAwait(false);

                        Pend? p;
                        lock (_candado) { _pendientes.Remove(ruta, out p); }
                        if (p is null) { cupo.Release(); continue; }

                        enCurso.RemoveAll(t => t.IsCompleted);
                        enCurso.Add(Task.Run(async () =>
                        {
                            try { await ProcesarAsync(ruta, p, ct).ConfigureAwait(false); }
                            catch (OperationCanceledException) { }
                            catch (Exception ex)
                            {
                                // Un fallo inesperado con UN archivo no tumba la vigilancia, pero tampoco se oculta.
                                NoAnalizado(ruta, "error inesperado al analizar un archivo (" + ex.GetType().Name + ")");
                            }
                            finally { cupo.Release(); }
                        }, CancellationToken.None));
                    }
                }
            }
            catch (OperationCanceledException) { }

            await Task.WhenAny(Task.WhenAll(enCurso.ToArray()), Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
        }

        private async Task ProcesarAsync(string ruta, Pend p, CancellationToken ct)
        {
            FileInfo info;
            try
            {
                info = new FileInfo(ruta);
                if (!info.Exists) { Interlocked.Increment(ref _descartados); return; }   // ya no esta: no hay nada que analizar
                if (info.Length > _opciones.MaxBytes)
                {
                    // Reescanear no lo arreglaria (el escaneo bajo demanda tiene el mismo limite): no queda por revisar.
                    NoAnalizado(ruta, "mayor que el limite del motor: " + ruta, revisable: false);
                    return;
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                NoAnalizado(ruta, "no se pudo consultar (" + ex.GetType().Name + "): " + ruta);
                return;
            }

            long ticks = info.LastWriteTimeUtc.Ticks;
            lock (_candado)
            {
                if (_vistos.TryGetValue(ruta, out var visto) && visto.Bytes == info.Length && visto.Ticks == ticks)
                {
                    Interlocked.Increment(ref _descartados);   // no cambio desde el ultimo analisis
                    return;
                }
            }

            ResultadoDeMotor veredicto;
            try
            {
                await using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                veredicto = await _motor.AnalizarAsync(fs, ct).ConfigureAwait(false);
            }
            catch (FileNotFoundException) { Interlocked.Increment(ref _descartados); return; }
            catch (DirectoryNotFoundException) { Interlocked.Increment(ref _descartados); return; }
            catch (UnauthorizedAccessException ex)
            {
                NoAnalizado(ruta, "sin permiso para leer (" + ex.GetType().Name + "): " + ruta);
                return;
            }
            catch (IOException)
            {
                // Lo mas habitual: el programa que lo escribe aun lo tiene abierto. Se reintenta mas tarde.
                if (p.Reintentos >= _opciones.MaxReintentos)
                {
                    NoAnalizado(ruta, "sigue bloqueado tras " + p.Reintentos + " reintentos: " + ruta);
                    return;
                }
                lock (_candado)
                {
                    if (!_pendientes.ContainsKey(ruta))
                        _pendientes[ruta] = new Pend
                        {
                            Reintentos = p.Reintentos + 1,
                            Toca = _reloj() + TimeSpan.FromTicks(_opciones.Estabilizacion.Ticks * (1L << Math.Min(p.Reintentos + 1, 6)))
                        };
                }
                return;
            }
            catch (MotorNoDisponibleException ex)
            {
                veredicto = ResultadoDeMotor.Fallo(ex.Message);
            }

            switch (veredicto.Veredicto)
            {
                case VeredictoDeArchivo.Limpio:
                    AlmacenarVisto(ruta, info.Length, ticks);
                    Interlocked.Increment(ref _analizados);
                    ErrorDelMotor(false);
                    return;

                case VeredictoDeArchivo.Infectado:
                    AlmacenarVisto(ruta, info.Length, ticks);
                    ErrorDelMotor(false);
                    // Primero se registra y despues se cuenta: quien ve el contador subir ya encuentra la deteccion.
                    await RegistrarDeteccionAsync(ruta, veredicto.Firma ?? "(sin nombre)", info, ct).ConfigureAwait(false);
                    Interlocked.Increment(ref _analizados);
                    return;

                default:
                    // El motor no pudo decidir: NO queda como visto (se volvera a intentar si cambia) ni como limpio.
                    NoAnalizado(ruta, "el motor no pudo analizarlo: " + veredicto.Error + " — " + ruta);
                    ErrorDelMotor(true);
                    return;
            }
        }

        private void NoAnalizado(string ruta, string aviso, bool revisable = true)
        {
            Interlocked.Increment(ref _noAnalizados);
            if (revisable) lock (_candado) AnotarPorRevisar(ruta);
            _ultimoAviso = aviso;
        }

        private void ErrorDelMotor(bool fallo)
        {
            if (!fallo)
            {
                Interlocked.Exchange(ref _erroresSeguidos, 0);
                _motorCaido = false;
                return;
            }
            if (Interlocked.Increment(ref _erroresSeguidos) >= _opciones.MaxErroresSeguidos) _motorCaido = true;
        }

        private void AlmacenarVisto(string ruta, long bytes, long ticks)
        {
            lock (_candado)
            {
                // Un cambio suyo se descarto antes, pero otro posterior si se analizo: ya no esta perdido.
                _rutasPerdidas.Remove(ruta);
                if (!_vistos.ContainsKey(ruta)) _ordenVistos.Enqueue(ruta);
                _vistos[ruta] = (bytes, ticks);
                while (_vistos.Count > MaxVistos && _ordenVistos.Count > 0) _vistos.Remove(_ordenVistos.Dequeue());
            }
        }

        private async Task RegistrarDeteccionAsync(string ruta, string firma, FileInfo info, CancellationToken ct)
        {
            string? sha = null;
            try
            {
                using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                sha = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }

            var d = new Deteccion(ruta, firma, info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), sha);
            lock (_candado)
            {
                _detecciones.RemoveAll(x => string.Equals(x.Ruta, ruta, StringComparison.OrdinalIgnoreCase));
                _detecciones.Add(d);
                while (_detecciones.Count > MaxDeteccionesGuardadas) _detecciones.RemoveAt(0);
            }

            await _reportes.EscribirAsync(Eventos.Amenazas.Detectada(
                firma, ruta, _motor.Nombre, Severidad.Alta, Accion.Registrada, sha), ct).ConfigureAwait(false);

            try { Detectado?.Invoke(d); }
            catch (Exception) { /* un suscriptor roto no debe romper la vigilancia */ }
        }

        // ============================================================
        public void Dispose()
        {
            _parar.Cancel();
            _fuente?.Dispose();
            try { _bucle?.Wait(TimeSpan.FromSeconds(3)); }
            catch (AggregateException) { }
            _parar.Dispose();
        }
    }
}
