using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Ransomware;

namespace Nexo.Service
{
    /// <summary>
    /// Señuelos contra ransomware (§2am del traspaso): el servicio los pone y los revisa cada pocos segundos.
    ///
    /// Igual que el tiempo real: se ACTIVA solo en appsettings.json (Nexo:Senuelos:Activo) y no hay métodos del pipe para
    /// apagarlo ni para cambiar las carpetas. Por el pipe: ver el estado, y reponer los tocados con vista previa, token y
    /// aprobación (reponer da el aviso por visto, así que un proceso cualquiera del usuario no debe poder hacerlo a escondidas).
    /// </summary>
    public sealed class ModuloSenuelos : IModuloDelServicio, IAsyncDisposable
    {
        public const int TokenInvalido = -32011;
        public static readonly TimeSpan IntervaloPorDefecto = TimeSpan.FromSeconds(30);
        public static readonly TimeSpan IntervaloMinimo = TimeSpan.FromSeconds(5);
        /// <summary>Cada cuánto se vuelven a buscar las carpetas (un usuario que inicia sesión trae sus carpetas reales).</summary>
        public static readonly TimeSpan RebuscarCarpetasCada = TimeSpan.FromMinutes(10);

        private readonly VigilanteDeSenuelos _vigilante;
        private readonly Func<(IReadOnlyList<string> Carpetas, IReadOnlyList<CarpetaSinSenuelo> Descartadas)> _carpetas;
        private readonly TimeSpan _intervalo;
        private readonly PoliticaDeAprobacion _politica;
        private readonly PlanesPendientes<PlanDeReposicion> _planes;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _esperar;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly object _candado = new object();
        private Task? _bucle;
        private IReadOnlyList<CarpetaSinSenuelo> _descartadas = Array.Empty<CarpetaSinSenuelo>();
        private string? _fallo;

        public ModuloSenuelos(VigilanteDeSenuelos vigilante,
                              Func<(IReadOnlyList<string> Carpetas, IReadOnlyList<CarpetaSinSenuelo> Descartadas)> carpetas,
                              TimeSpan? intervalo = null, PoliticaDeAprobacion? politica = null,
                              Func<DateTimeOffset>? reloj = null, Func<TimeSpan, CancellationToken, Task>? esperar = null)
        {
            _vigilante = vigilante;
            _carpetas = carpetas;
            TimeSpan i = intervalo ?? IntervaloPorDefecto;
            _intervalo = i < IntervaloMinimo ? IntervaloMinimo : i;
            _politica = politica ?? PoliticaDeAprobacion.Ninguna;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _esperar = esperar ?? ((t, ct) => Task.Delay(t, ct));
            _planes = new PlanesPendientes<PlanDeReposicion>(TimeSpan.FromMinutes(10), reloj: _reloj);
        }

        public TimeSpan Intervalo => _intervalo;

        public IReadOnlyList<string> Metodos { get; } = new[] { "senuelos.estado", "senuelos.previsualizar", "senuelos.reponer" };

        public void Iniciar()
        {
            if (_bucle is not null) return;
            _bucle = Task.Run(() => BucleAsync(_cts.Token));
        }

        private async Task BucleAsync(CancellationToken ct)
        {
            DateTimeOffset? ultimaBusqueda = null;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await UnaVueltaAsync(ultimaBusqueda is null || _reloj() - ultimaBusqueda.Value >= RebuscarCarpetasCada, ct).ConfigureAwait(false);
                    if (ultimaBusqueda is null || _reloj() - ultimaBusqueda.Value >= RebuscarCarpetasCada) ultimaBusqueda = _reloj();
                    await _esperar(_intervalo, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
        }

        /// <summary>Una vuelta del bucle: (si toca) buscar carpetas y poner lo que falte, y revisar. Interno: lo usan las pruebas.</summary>
        internal async Task UnaVueltaAsync(bool buscarCarpetas, CancellationToken ct)
        {
            try
            {
                if (buscarCarpetas)
                {
                    (IReadOnlyList<string> carpetas, IReadOnlyList<CarpetaSinSenuelo> descartadas) = _carpetas();
                    lock (_candado) _descartadas = descartadas;
                    await _vigilante.PrepararAsync(carpetas, ct).ConfigureAwait(false);
                }
                await _vigilante.RevisarAsync(ct).ConfigureAwait(false);
                lock (_candado) _fallo = null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                // Un fallo inesperado no para la vigilancia, pero tampoco se esconde: el estado lo dice.
                lock (_candado) _fallo = "la última revisión falló (" + ex.GetType().Name + ")";
            }
        }

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "senuelos.estado":
                    return Estado();

                case "senuelos.previsualizar":
                {
                    PlanDeReposicion plan = _vigilante.PrepararReposicion();
                    string? token = null;
                    DateTimeOffset? expira = null;
                    if (plan.HayCambios) (token, expira) = _planes.Guardar(plan);
                    return new { descripcion = plan.Describir(), hay_cambios = plan.HayCambios, token, expira };
                }

                case "senuelos.reponer":
                {
                    string token = Texto(Objeto(p), "token", 64) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'token'");
                    // Aprobación antes de gastar el token: si falta, el plan sigue vigente.
                    _politica.Exigir(ContextoDeLlamada.Actual);
                    PlanDeReposicion plan = _planes.Tomar(token)
                        ?? throw new ErrorDeComando(TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");
                    ResultadoDeReposicion r = await _vigilante.ReponerAsync(plan, ct).ConfigureAwait(false);
                    return new { exito = r.Repuestos > 0 && r.Problemas.Count == 0, repuestos = r.Repuestos, problemas = r.Problemas };
                }

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        private object Estado()
        {
            EstadoDeSenuelos e = _vigilante.Estado();
            IReadOnlyList<CarpetaSinSenuelo> descartadas;
            string? fallo;
            lock (_candado) { descartadas = _descartadas; fallo = _fallo; }
            var sin = descartadas.Concat(e.SinSenuelo).ToList();

            return new
            {
                activo = true,
                intervalo_segundos = (int)_intervalo.TotalSeconds,
                ultima_revision = e.UltimaRevision,
                // «Todo en orden» solo si se revisó, hay señuelos, ninguno tocado y todos se pudieron comprobar.
                todo_en_orden = e.UltimaRevision is not null && e.Senuelos.Count > 0 && e.Tocados == 0 && e.NoComprobados.Count == 0 && fallo is null,
                tocados = e.Tocados,
                // Dos o más tocados en los últimos 10 minutos (sin contar lo enviado a la papelera): posible ransomware en marcha.
                rafaga = VigilanteDeSenuelos.Recientes(e.Senuelos, _reloj()) >= 2,
                senuelos = e.Senuelos.Select(s => new
                {
                    ruta = s.Ruta,
                    carpeta = s.Carpeta,
                    tocado = s.Tocado,
                    hallazgo = s.Hallazgo is null ? null : new
                    {
                        tipo = s.Hallazgo.Tipo.ToString().ToLowerInvariant(),
                        severidad = VigilanteDeSenuelos.SeveridadDe(s.Hallazgo).ToString(),
                        detalle = s.Hallazgo.Detalle,
                        cuando = s.Hallazgo.Cuando,
                        nueva_ruta = s.Hallazgo.NuevaRuta
                    },
                    no_comprobado = e.NoComprobados.TryGetValue(s.Ruta, out string? m) ? m : null
                }).ToList(),
                sin_senuelo = sin.Select(x => new { carpeta = x.Carpeta, motivo = x.Motivo }).ToList(),
                aviso = fallo ?? e.Aviso,
                nota = "Avisa DESPUÉS de que un señuelo cambia (hasta " + (int)_intervalo.TotalSeconds + " s más tarde); no puede impedirlo ni sabe qué programa fue."
            };
        }

        private static JsonElement Objeto(JsonElement? p)
            => p is { ValueKind: JsonValueKind.Object } o ? o : throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se esperaba un objeto de parametros");

        private static string? Texto(JsonElement o, string nombre, int max)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v) || v.ValueKind == JsonValueKind.Null) return null;
            if (v.ValueKind != JsonValueKind.String) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' debe ser texto");
            string s = v.GetString()!;
            if (s.Length > max) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' es demasiado largo");
            return s;
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

    /// <summary>Lo que contesta el servicio con los señuelos apagados: que la interfaz lo diga claramente.</summary>
    public sealed class ModuloSenuelosApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "senuelos.estado", "senuelos.previsualizar", "senuelos.reponer" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo switch
            {
                "senuelos.estado" => Task.FromResult<object?>(new
                {
                    activo = false,
                    todo_en_orden = false,
                    nota = "Los señuelos contra ransomware están apagados. Se activan en appsettings.json (Nexo:Senuelos:Activo)."
                }),
                "senuelos.previsualizar" or "senuelos.reponer"
                    => throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "los señuelos están apagados"),
                _ => throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido")
            };
    }
}
