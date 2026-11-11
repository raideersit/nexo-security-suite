using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Modules.Threats.Vulnerabilidades;

namespace Nexo.Service
{
    /// <summary>
    /// Anti-criptojacking (§2aw del traspaso): el servicio toma una muestra de procesos y conexiones cada pocos segundos y se la pasa
    /// a <see cref="VigilanteDeMineria"/>. Solo OBSERVA: no detiene ni borra nada, y no hay métodos del pipe para cambiarlo.
    ///
    /// APAGADO por omisión (Nexo:Mineria:Activo). Solo lectura: el único método es <c>mineria.estado</c>.
    /// </summary>
    public sealed class ModuloMineria : IModuloDelServicio, IAsyncDisposable
    {
        public static readonly TimeSpan IntervaloPorDefecto = TimeSpan.FromSeconds(30);
        public static readonly TimeSpan IntervaloMinimo = TimeSpan.FromSeconds(2);

        private readonly Func<MuestraDeMineria> _tomar;
        private readonly Func<CancellationToken, Task<ListaDePools>> _cargarLista;
        private readonly TimeSpan _intervalo;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _esperar;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly object _candado = new object();
        private Task? _bucle;
        private VigilanteDeMineria? _vigilante;
        private ListaDePools _lista = ListaDePools.Vacia;
        private ResultadoDeAnalisis? _ultimo;
        private DateTimeOffset? _ultimaMuestra;
        private int _muestras;
        private string? _fallo;

        public ModuloMineria(Func<MuestraDeMineria> tomar, Func<CancellationToken, Task<ListaDePools>>? cargarLista = null,
                             TimeSpan? intervalo = null, Func<DateTimeOffset>? reloj = null, Func<TimeSpan, CancellationToken, Task>? esperar = null)
        {
            _tomar = tomar;
            _cargarLista = cargarLista ?? (_ => Task.FromResult(ListaDePools.Vacia));
            TimeSpan i = intervalo ?? IntervaloPorDefecto;
            _intervalo = i < IntervaloMinimo ? IntervaloMinimo : i;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _esperar = esperar ?? ((t, ct) => Task.Delay(t, ct));
        }

        public TimeSpan Intervalo => _intervalo;

        public IReadOnlyList<string> Metodos { get; } = new[] { "mineria.estado" };

        public void Iniciar()
        {
            if (_bucle is not null) return;
            _bucle = Task.Run(() => BucleAsync(_cts.Token));
        }

        private async Task BucleAsync(CancellationToken ct)
        {
            try
            {
                // La lista (y la resolución de sus dominios) se carga aquí dentro: no retrasa el arranque del servicio.
                ListaDePools lista;
                try { lista = await _cargarLista(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    lista = ListaDePools.Vacia;
                    lock (_candado) _fallo = "no se pudo cargar la lista de servidores de minería (" + ex.GetType().Name + "): se vigila solo por CPU y puertos";
                }
                lock (_candado) { _lista = lista; _vigilante = new VigilanteDeMineria(lista); }

                while (!ct.IsCancellationRequested)
                {
                    await UnaVueltaAsync(ct).ConfigureAwait(false);
                    await _esperar(_intervalo, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
        }

        /// <summary>Una muestra y su evaluación. Interno: lo usan las pruebas (deben haber cargado un vigilante con <see cref="PrepararParaPruebas"/>).</summary>
        internal Task UnaVueltaAsync(CancellationToken ct)
        {
            try
            {
                MuestraDeMineria m = _tomar();
                VigilanteDeMineria v;
                lock (_candado) v = _vigilante ?? throw new InvalidOperationException("sin vigilante");
                ResultadoDeAnalisis r = v.Evaluar(m);
                lock (_candado) { _ultimo = r; _ultimaMuestra = _reloj(); _muestras++; _fallo = _fallo is not null && _fallo.StartsWith("no se pudo cargar", StringComparison.Ordinal) ? _fallo : null; }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Un fallo inesperado no para la vigilancia, pero tampoco se esconde: el estado lo dice.
                lock (_candado) _fallo = "la última muestra falló (" + ex.GetType().Name + ")";
            }
            return Task.CompletedTask;
        }

        internal void PrepararParaPruebas(ListaDePools lista)
        {
            lock (_candado) { _lista = lista; _vigilante = new VigilanteDeMineria(lista); }
        }

        public Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            if (metodo != "mineria.estado") throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            return Task.FromResult<object?>(Estado());
        }

        private object Estado()
        {
            ResultadoDeAnalisis? r; DateTimeOffset? cuando; int muestras; string? fallo; ListaDePools lista;
            lock (_candado) { r = _ultimo; cuando = _ultimaMuestra; muestras = _muestras; fallo = _fallo; lista = _lista; }

            // «Sin sospechas» solo si la última muestra fue completa y ya hubo muestras suficientes para ver una racha de CPU.
            bool observando = muestras < VigilanteDeMineria.MuestrasSostenidas;
            bool sinSospechas = r is not null && r.Completo && r.Hallazgos.Count == 0 && !observando && fallo is null;

            return new
            {
                activo = true,
                intervalo_segundos = (int)_intervalo.TotalSeconds,
                ultima_muestra = cuando,
                muestras,
                observando,
                muestras_necesarias = VigilanteDeMineria.MuestrasSostenidas,
                sin_sospechas = sinSospechas,
                completo = r?.Completo ?? false,
                severidad_maxima = r is null || r.Hallazgos.Count == 0 ? null : r.Maxima.ToString(),
                hallazgos = (r?.Hallazgos ?? Array.Empty<HallazgoDeSistema>()).Select(h => new
                {
                    id = h.Id, severidad = h.Severidad.ToString(), titulo = h.Titulo, detalle = h.Detalle, recomendacion = h.Recomendacion, sujeto = h.Sujeto
                }).ToList(),
                no_evaluado = r?.NoEvaluado ?? (IReadOnlyList<string>)Array.Empty<string>(),
                lista_ips = lista.Ips,
                lista_dominios = lista.Dominios,
                aviso = fallo,
                nota = "Solo observa: no detiene ningún programa. Sin una lista de servidores de minería detecta por CPU sostenida en segundo plano y por puertos habituales de minería; " +
                       "no ve mineros con proxy ni dominios que no estén en la lista, ni usa la tarjeta gráfica."
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

    /// <summary>Lo que contesta el servicio con el anti-criptojacking apagado: que la interfaz lo diga claramente.</summary>
    public sealed class ModuloMineriaApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "mineria.estado" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo == "mineria.estado"
                ? Task.FromResult<object?>(new
                {
                    activo = false,
                    sin_sospechas = false,
                    nota = "La vigilancia de criptominería está apagada. Se activa en appsettings.json (Nexo:Mineria:Activo)."
                })
                : throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
    }
}
