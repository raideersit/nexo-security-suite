using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>Un disco ya evaluado, tal como se ofrece a la interfaz.</summary>
    public sealed record DiscoEvaluado(
        string Modelo,
        string Serie,
        bool SinDatos,
        bool? PrediccionDeFallo,
        int AtributosLeidos,
        IReadOnlyList<int> AtributosClaveLeidos,
        int? TemperaturaC,
        int? DesgastePorcentaje,
        long? HorasEncendido,
        Severidad Severidad,
        IReadOnlyList<string> Alertas,
        IReadOnlyList<string> Limitaciones);

    /// <summary>
    /// Lo ultimo que se sabe de los discos. <see cref="Discos"/> es siempre la ultima lectura que SI salio bien (con su
    /// fecha en <see cref="UltimaLectura"/>); si el ultimo intento fallo, <see cref="Estado"/> es «fallido» y
    /// <see cref="Error"/> dice por que. Nunca se presentan datos viejos como si fueran de ahora.
    /// </summary>
    public sealed record EstadoDeSalud(
        string Estado,                   // nunca | listo | fallido
        bool Leyendo,
        DateTimeOffset? UltimaLectura,
        DateTimeOffset? UltimoIntento,
        DateTimeOffset? ProximaLectura,
        string? Error,
        string? AdvertenciaDeHistorial,
        IReadOnlyList<DiscoEvaluado> Discos);

    /// <summary>
    /// Mantiene la salud de los discos al dia para el servicio: lee al arrancar y cada <c>intervalo</c>, y guarda el
    /// resultado. Consultar el estado NO lee los discos (WMI tarda y cada lectura deja una nota por disco en el vault);
    /// una lectura a pedido se acepta como mucho cada <see cref="MinimoEntreLecturas"/>.
    ///
    /// Solo lee: nada de esto escribe en un disco.
    /// </summary>
    public sealed class VigiaDeSalud : IDisposable
    {
        /// <summary>Los cinco atributos que evalua <see cref="EvaluadorDeSalud"/> (Backblaze).</summary>
        public static readonly IReadOnlyList<byte> AtributosClave = new byte[] { 5, 187, 188, 197, 198 };

        public static readonly TimeSpan IntervaloPorDefecto = TimeSpan.FromHours(6);
        public static readonly TimeSpan MinimoEntreLecturas = TimeSpan.FromMinutes(5);

        private readonly MonitorDeSalud _monitor;
        private readonly TimeSpan _intervalo;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _espera;
        private readonly CancellationTokenSource _parar = new CancellationTokenSource();
        private readonly object _cerrojo = new object();

        private IReadOnlyList<DiscoEvaluado> _discos = Array.Empty<DiscoEvaluado>();
        private DateTimeOffset? _ultimaLectura;
        private DateTimeOffset? _ultimoIntento;
        private string? _error;
        private string? _advertencia;
        private bool _leyendo;
        private bool _fallido;
        private Task? _bucle;

        public VigiaDeSalud(MonitorDeSalud monitor, TimeSpan? intervalo = null, Func<DateTimeOffset>? reloj = null,
                            Func<TimeSpan, CancellationToken, Task>? espera = null)
        {
            _monitor = monitor;
            _intervalo = intervalo is TimeSpan i && i > TimeSpan.Zero ? i : IntervaloPorDefecto;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _espera = espera ?? Task.Delay;
        }

        /// <summary>Empieza a leer en segundo plano: una vez ahora y despues cada intervalo.</summary>
        public void Iniciar()
        {
            CancellationToken ct = _parar.Token;
            _bucle = Task.Run(async () =>
            {
                while (!ct.IsCancellationRequested)
                {
                    await LeerAsync(ct).ConfigureAwait(false);
                    try { await _espera(_intervalo, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }
                }
            });
        }

        public EstadoDeSalud Estado()
        {
            lock (_cerrojo)
            {
                return new EstadoDeSalud(
                    _ultimoIntento is null ? "nunca" : _fallido ? "fallido" : "listo",
                    _leyendo, _ultimaLectura, _ultimoIntento,
                    _ultimoIntento is DateTimeOffset u ? u + _intervalo : null,
                    _error, _advertencia, _discos);
            }
        }

        /// <summary>
        /// Una lectura a pedido, en segundo plano. Se niega (y dice por que) si ya hay una en curso o si la ultima empezo hace
        /// menos de <see cref="MinimoEntreLecturas"/>.
        /// </summary>
        public bool PedirLectura(out string motivo)
        {
            lock (_cerrojo)
            {
                if (_leyendo) { motivo = "ya se están leyendo los discos"; return false; }
                if (_ultimoIntento is DateTimeOffset u && _reloj() - u < MinimoEntreLecturas)
                {
                    DateTimeOffset desde = u + MinimoEntreLecturas;
                    motivo = "se leyeron hace menos de " + (int)MinimoEntreLecturas.TotalMinutes + " minutos; se puede volver a pedir desde las "
                             + desde.ToLocalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
                    return false;
                }
                // Se marca aqui, dentro del cerrojo: dos pedidos seguidos no pueden lanzar dos lecturas.
                _leyendo = true;
                _ultimoIntento = _reloj();
            }
            motivo = "lectura iniciada";
            _ = Task.Run(() => EjecutarAsync(_parar.Token));
            return true;
        }

        /// <summary>Lee y evalua todos los discos. Si ya hay una lectura en curso, no hace nada.</summary>
        public async Task LeerAsync(CancellationToken ct = default)
        {
            lock (_cerrojo)
            {
                if (_leyendo) return;
                _leyendo = true;
                _ultimoIntento = _reloj();
            }
            await EjecutarAsync(ct).ConfigureAwait(false);
        }

        /// <summary>La lectura en si. Quien llama ya marco «leyendo» y la hora del intento.</summary>
        private async Task EjecutarAsync(CancellationToken ct)
        {
            try
            {
                IReadOnlyList<(LecturaDeDisco Lectura, EvaluacionDeSalud Evaluacion)> r = await _monitor.EvaluarAsync(ct: ct).ConfigureAwait(false);
                List<DiscoEvaluado> discos = r.Select(x => Evaluado(x.Lectura, x.Evaluacion)).ToList();
                lock (_cerrojo)
                {
                    _discos = discos;
                    _ultimaLectura = _ultimoIntento;
                    _fallido = false;
                    _error = null;
                    _advertencia = _monitor.AdvertenciaDeHistorial;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                lock (_cerrojo) { _fallido = true; _error = "lectura cancelada"; }
            }
            catch (Exception ex)
            {
                // WMI puede fallar de muchas formas (servicio detenido, proveedor roto). Se dice, no se oculta: los datos
                // anteriores siguen con su fecha, y el estado pasa a «fallido».
                lock (_cerrojo) { _fallido = true; _error = "no se pudieron leer los discos (" + ex.GetType().Name + ": " + ex.Message + ")"; }
            }
            finally
            {
                lock (_cerrojo) _leyendo = false;
            }
        }

        public static DiscoEvaluado Evaluado(LecturaDeDisco l, EvaluacionDeSalud e)
            => new DiscoEvaluado(
                l.Modelo, l.SerieRedactada, !l.TieneDatos, l.PrediccionDeFallo, l.Atributos.Count,
                AtributosClave.Where(id => l.Atributo(id) is not null).Select(id => (int)id).ToList(),
                l.TemperaturaC, l.DesgastePorcentaje, l.HorasEncendido,
                e.Severidad, e.Alertas, l.Limitaciones);

        /// <summary>
        /// Lo que contesta «disco.estado» por el pipe. Esta aqui (y no en el servicio) para que las pruebas portables de la
        /// ventana lean exactamente esta forma.
        /// </summary>
        public static object ParaJson(EstadoDeSalud s)
            => new
            {
                estado = s.Estado,
                leyendo = s.Leyendo,
                ultima_lectura = s.UltimaLectura,
                ultimo_intento = s.UltimoIntento,
                proxima_lectura = s.ProximaLectura,
                error = s.Error,
                advertencia_historial = s.AdvertenciaDeHistorial,
                atributos_clave = AtributosClave.Select(x => (int)x).ToList(),
                discos = s.Discos.Select(d => new
                {
                    modelo = d.Modelo,
                    serie = d.Serie,
                    sin_datos = d.SinDatos,
                    prediccion_fallo = d.PrediccionDeFallo,
                    atributos_leidos = d.AtributosLeidos,
                    atributos_clave_leidos = d.AtributosClaveLeidos,
                    temperatura_c = d.TemperaturaC,
                    desgaste_porcentaje = d.DesgastePorcentaje,
                    horas_encendido = d.HorasEncendido,
                    severidad = d.Severidad.ToString().ToLowerInvariant(),
                    alertas = d.Alertas,
                    limitaciones = d.Limitaciones
                }).ToList()
            };

        public void Dispose()
        {
            _parar.Cancel();
            try { _bucle?.Wait(TimeSpan.FromSeconds(2)); }
            catch (AggregateException) { }
            _parar.Dispose();
        }
    }
}
