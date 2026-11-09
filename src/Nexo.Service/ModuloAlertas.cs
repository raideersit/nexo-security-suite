using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// «alertas.revisar»: busca señales de intrusion en los registros de Seguridad y de Sistema (que exigen administrador: por eso aqui, en el
    /// servicio). SOLO LECTURA: no cambia la politica de auditoria ni nada mas. Deja una nota en el vault por revision. Tope de frecuencia: leer
    /// el registro de Seguridad cuesta, y un programa no debe poder ponerlo a leer sin parar.
    /// </summary>
    public sealed class ModuloAlertas : IModuloDelServicio
    {
        public static readonly TimeSpan MinimoEntreRevisiones = TimeSpan.FromSeconds(10);
        public const int DiasPorOmision = 7;
        public const int DiasMaximos = 30;

        private readonly Func<TimeSpan, DateTimeOffset, LecturaDeAlertas> _leer;
        private readonly IReportWriter _reportes;
        private readonly Func<DateTimeOffset> _reloj;
        private DateTimeOffset? _ultima;
        private readonly object _cerrojo = new();

        public ModuloAlertas(Func<TimeSpan, DateTimeOffset, LecturaDeAlertas> leer, IReportWriter reportes, Func<DateTimeOffset>? reloj = null)
        {
            _leer = leer;
            _reportes = reportes;
            _reloj = reloj ?? (() => DateTimeOffset.UtcNow);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "alertas.revisar" };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            if (metodo != "alertas.revisar") throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            int dias = DiasPorOmision;
            if (p is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty("dias", out JsonElement d))
            {
                if (d.ValueKind != JsonValueKind.Number || !d.TryGetInt32(out dias) || dias < 1 || dias > DiasMaximos)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'dias' debe ser un numero de 1 a " + DiasMaximos);
            }
            DateTimeOffset ahora = _reloj();
            lock (_cerrojo)
            {
                if (_ultima is DateTimeOffset u && ahora - u < MinimoEntreRevisiones && ahora >= u)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se acaba de revisar: espera unos segundos");
                _ultima = ahora;
            }

            LecturaDeAlertas l = await Task.Run(() => _leer(TimeSpan.FromDays(dias), ahora), ct).ConfigureAwait(false);
            ResultadoDeAnalisis r = AnalizadorDeAlertas.Analizar(l);

            try { await _reportes.EscribirAsync(Evento(r, dias), ct).ConfigureAwait(false); }
            catch (Exception) when (!ct.IsCancellationRequested) { /* el vault nunca impide ver el resultado */ }

            return new
            {
                periodo_dias = dias,
                eventos = l.Eventos.Count,
                hallazgos = r.Hallazgos.Select(h => new { id = h.Id, severidad = h.Severidad.ToString(), titulo = h.Titulo, detalle = h.Detalle, recomendacion = h.Recomendacion, sujeto = h.Sujeto }).ToList(),
                no_evaluado = r.NoEvaluado
            };
        }

        private static NexoEvent Evento(ResultadoDeAnalisis r, int dias)
        {
            int n = r.Hallazgos.Count(h => h.Severidad != Severidad.Info);
            Severidad sev = n > 0 ? r.Hallazgos.Max(h => h.Severidad) : r.Completo ? Severidad.Info : Severidad.Media;
            var sb = new StringBuilder();
            if (r.Hallazgos.Count > 0)
            {
                sb.AppendLine("| Gravedad | Hallazgo | Qué hacer |");
                sb.AppendLine("|---|---|---|");
                foreach (HallazgoDeSistema h in r.Hallazgos.Take(60))
                    sb.AppendLine("| " + h.Severidad + " | " + Celda(h.Titulo + ". " + h.Detalle) + " | " + Celda(h.Recomendacion) + " |");
                sb.AppendLine();
            }
            if (!r.Completo)
            {
                sb.AppendLine("**No se pudo revisar todo** (esto NO significa que esté bien):");
                foreach (string x in r.NoEvaluado) sb.AppendLine("- " + x);
            }
            else if (r.Hallazgos.Count == 0) sb.AppendLine("Ninguna señal de intrusión en lo que Windows registró.");
            var e = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.AlertaIdentidad,
                "Revisión de accesos y cuentas (" + dias + " días): " + (n > 0 ? n + " hallazgo(s)" : r.Completo ? "sin hallazgos" : "incompleta"))
            {
                Severidad = sev,
                Accion = Accion.Registrada,
                Cuerpo = sb.ToString()
            };
            e.Campos["hallazgos"] = n;
            e.Campos["completa"] = r.Completo;
            e.Campos["dias"] = dias;
            return e;
        }

        private static string Celda(string t) => t.Replace("|", "/").Replace("\r", " ").Replace("\n", " ");
    }
}
