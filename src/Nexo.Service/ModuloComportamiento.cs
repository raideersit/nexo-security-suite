using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Comportamiento;
using Nexo.Modules.Threats.Vulnerabilidades;

namespace Nexo.Service
{
    /// <summary>
    /// Análisis de comportamiento (§2bc del traspaso): el servicio abre una sesión ETW (<see cref="IFuenteDeComportamiento"/>) y el
    /// <see cref="PuntuadorDeComportamiento"/> suma señales por proceso. Solo OBSERVA: no detiene ni borra nada y no hay métodos del
    /// pipe para cambiarlo. Exige administrador (el servicio como SYSTEM lo es); si la sesión no arranca, el estado lo dice y NUNCA
    /// da «sin sospechas». APAGADO por omisión (Nexo:Comportamiento:Activo). Único método: <c>comportamiento.estado</c>.
    /// </summary>
    public sealed class ModuloComportamiento : IModuloDelServicio, IAsyncDisposable
    {
        private readonly IFuenteDeComportamiento _fuente;
        private readonly PuntuadorDeComportamiento _puntuador;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly object _candado = new();
        private string? _motivo;
        private bool _iniciado;
        private DateTimeOffset? _desde;

        public ModuloComportamiento(IFuenteDeComportamiento fuente, PuntuadorDeComportamiento puntuador, Func<DateTimeOffset>? reloj = null)
        { _fuente = fuente; _puntuador = puntuador; _reloj = reloj ?? (() => DateTimeOffset.Now); }

        public IReadOnlyList<string> Metodos { get; } = new[] { "comportamiento.estado" };

        /// <summary>Abre la sesión. Si no se puede, queda el motivo para el estado (el servicio sigue funcionando).</summary>
        public void Iniciar()
        {
            lock (_candado)
            {
                if (_iniciado) return;
                _iniciado = true;
                string? motivo;
                try { motivo = _fuente.Iniciar(); }
                catch (Exception ex) { motivo = "falló al abrir la sesión (" + ex.GetType().Name + ")"; }
                _motivo = motivo;
                if (motivo is null) _desde = _reloj();
            }
        }

        public Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            if (metodo != "comportamiento.estado") throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            return Task.FromResult<object?>(Estado());
        }

        private object Estado()
        {
            string? motivo; DateTimeOffset? desde;
            lock (_candado) { motivo = _motivo; desde = _desde; }
            bool activa = motivo is null && _fuente.Activa;
            ResultadoDeAnalisis r = _puntuador.Resumen();
            long perdidos = _fuente.Descartados;

            var noEvaluado = new List<string>(r.NoEvaluado);
            if (!activa) noEvaluado.Insert(0, "la sesión de eventos (ETW) no está en marcha: " + (motivo ?? "no se inició"));
            if (perdidos > 0) noEvaluado.Add("se perdieron " + perdidos + " eventos por exceso de actividad: pudo pasar algo sin verse");

            // «Sin sospechas» solo con la sesión viva, sin hallazgos y sin pérdidas. Firmas desconocidas no lo impiden (no suman) pero se dicen.
            bool sinSospechas = activa && r.Hallazgos.Count == 0 && perdidos == 0;

            return new
            {
                activo = true,
                sesion_activa = activa,
                desde,
                eventos_recibidos = _fuente.Recibidos,
                eventos_perdidos = perdidos,
                sin_sospechas = sinSospechas,
                completo = activa && noEvaluado.Count == 0,
                severidad_maxima = r.Hallazgos.Count == 0 ? null : r.Maxima.ToString(),
                hallazgos = r.Hallazgos.Select(h => new
                {
                    id = h.Id, severidad = h.Severidad.ToString(), titulo = h.Titulo, detalle = h.Detalle, recomendacion = h.Recomendacion, sujeto = h.Sujeto
                }).ToList(),
                no_evaluado = noEvaluado,
                aviso = activa ? null : motivo ?? "la sesión de eventos no está en marcha",
                nota = "Solo observa: no detiene ningún programa. Ve lo que pasa desde que arrancó la sesión (no el pasado) y suma señales que por separado son normales: " +
                       "un aviso es una sospecha, no una prueba."
            };
        }

        public ValueTask DisposeAsync() { try { _fuente.Dispose(); } catch { /* cierre */ } return ValueTask.CompletedTask; }
    }

    /// <summary>Lo que contesta el servicio con el análisis de comportamiento apagado.</summary>
    public sealed class ModuloComportamientoApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "comportamiento.estado" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo == "comportamiento.estado"
                ? Task.FromResult<object?>(new
                {
                    activo = false,
                    sin_sospechas = false,
                    nota = "El análisis de comportamiento está apagado. Se activa en appsettings.json (Nexo:Comportamiento:Activo) y necesita que el servicio corra como administrador."
                })
                : throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
    }
}
