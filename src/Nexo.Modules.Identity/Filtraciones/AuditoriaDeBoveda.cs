using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Identity.Filtraciones
{
    public sealed record HallazgoDeFiltracion(Guid EntradaId, long Apariciones);

    /// <summary>
    /// Resultado de revisar todas las contrasenas de una boveda. Los tres grupos son disjuntos y nada se pierde: lo que no se
    /// pudo comprobar esta en <see cref="SinComprobar"/> y NO cuenta como «limpio».
    /// </summary>
    public sealed record ResultadoDeAuditoria(
        IReadOnlyList<HallazgoDeFiltracion> Filtradas,
        IReadOnlyList<Guid> SinComprobar,
        IReadOnlyList<Guid> SinContrasena,
        int NoEncontradas)
    {
        /// <summary>true solo si TODAS las contrasenas se comprobaron y ninguna aparece. Un fallo de red nunca lo vuelve true.</summary>
        public bool TodoComprobadoYLimpio => Filtradas.Count == 0 && SinComprobar.Count == 0;
    }

    public static class AuditoriaDeBoveda
    {
        public const int ConsultasSimultaneas = 4;

        /// <summary>
        /// Revisa cada contrasena distinta una sola vez (dos entradas con la misma clave hacen una consulta), con un maximo de
        /// <see cref="ConsultasSimultaneas"/> a la vez. Las entradas sin contrasena se apartan. Publica UN evento con solo
        /// conteos: ni sitios, ni usuarios, ni contrasenas (las notas del vault son texto plano).
        /// </summary>
        public static async Task<ResultadoDeAuditoria> AuditarAsync(Boveda.Boveda boveda, ComprobadorDeContrasenas comprobador,
                                                                    IReportWriter? reportes = null, CancellationToken ct = default)
        {
            if (boveda is null) throw new ArgumentNullException(nameof(boveda));
            if (comprobador is null) throw new ArgumentNullException(nameof(comprobador));

            IReadOnlyList<EntradaDeBoveda> entradas = boveda.Entradas;
            var sinContrasena = entradas.Where(e => e.Contrasena.Length == 0).Select(e => e.Id).ToList();
            var porContrasena = entradas.Where(e => e.Contrasena.Length > 0).GroupBy(e => e.Contrasena, StringComparer.Ordinal).ToList();

            using var cupo = new SemaphoreSlim(ConsultasSimultaneas);
            var tareas = porContrasena.Select(async g =>
            {
                await cupo.WaitAsync(ct).ConfigureAwait(false);
                try { return (Grupo: g, Resultado: await comprobador.ComprobarAsync(g.Key, ct).ConfigureAwait(false)); }
                finally { cupo.Release(); }
            }).ToList();
            var hechos = await Task.WhenAll(tareas).ConfigureAwait(false);

            var filtradas = new List<HallazgoDeFiltracion>();
            var sinComprobar = new List<Guid>();
            int noEncontradas = 0;
            foreach (var h in hechos)
            {
                foreach (EntradaDeBoveda e in h.Grupo)
                {
                    switch (h.Resultado.Estado)
                    {
                        case EstadoDeComprobacion.Filtrada: filtradas.Add(new HallazgoDeFiltracion(e.Id, h.Resultado.Apariciones)); break;
                        case EstadoDeComprobacion.NoEncontrada: noEncontradas++; break;
                        default: sinComprobar.Add(e.Id); break;
                    }
                }
            }

            var resultado = new ResultadoDeAuditoria(filtradas, sinComprobar, sinContrasena, noEncontradas);
            await PublicarAsync(reportes, resultado).ConfigureAwait(false);
            return resultado;
        }

        private static async Task PublicarAsync(IReportWriter? reportes, ResultadoDeAuditoria r)
        {
            if (reportes is null) return;
            // Alta si hay filtradas; Media si no hay ninguna pero hubo que no se pudieron mirar (lo desconocido no es «bien»); Info si todo se miro y esta limpio.
            Severidad sev = r.Filtradas.Count > 0 ? Severidad.Alta : r.SinComprobar.Count > 0 ? Severidad.Media : Severidad.Info;
            var e = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.BrechaDetectada,
                r.Filtradas.Count > 0 ? "Contrasenas de la boveda en filtraciones publicas" : "Revision de contrasenas de la boveda")
            {
                Severidad = sev,
                Accion = Accion.Registrada
            };
            e.Campos["filtradas"] = r.Filtradas.Count;
            e.Campos["sin_comprobar"] = r.SinComprobar.Count;
            e.Campos["no_encontradas"] = r.NoEncontradas;
            e.Campos["sin_contrasena"] = r.SinContrasena.Count;
            try { await reportes.EscribirAsync(e).ConfigureAwait(false); }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException) { }
        }
    }
}
