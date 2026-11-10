using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        /// <summary>Como SeguridadFalsa, mas el camino para activar las carpetas protegidas (que en la realidad hace el servicio).</summary>
        private sealed class SeguridadConCfaFalsa : IServicioDeSeguridad
        {
            public readonly List<SeccionDeSeguridad> Llamadas = new();
            public readonly List<string> Previsualizaciones = new();
            public readonly List<string> Aplicados = new();
            public Func<SeccionDeSeguridad, Consulta<RevisionDeSeccion>> Responde = s => Limpia(s);
            public ResultadoDeAccion Resultado = new(true, false, "Listo.");

            public Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
            {
                Llamadas.Add(seccion);
                return Task.FromResult(Responde(seccion));
            }

            public Task<Consulta<PlanDelServicio>> PrevisualizarCarpetasProtegidasAsync(string modo, CancellationToken ct)
            {
                Previsualizaciones.Add(modo);
                return Task.FromResult(Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Cambiar de «desactivado» a «activado».", true, new string('a', 64), new[] { "aviso" })));
            }

            public Task<ResultadoDeAccion> AplicarCarpetasProtegidasAsync(string token, CancellationToken ct)
            {
                Aplicados.Add(token);
                return Task.FromResult(Resultado);
            }
        }

        private static HallazgoDeSistema Cfa(string id, Severidad s = Severidad.Media) => new(id, s, "t " + id, "d", "r");

        private static FilaDeSeccion FilaRansomware(SeguridadModelo m) => m.Secciones.Single(x => x.Seccion == SeccionDeSeguridad.Ransomware);

        private static void ProbarActivarCarpetasProtegidas()
        {
            Console.WriteLine("Pestaña Seguridad: activar las carpetas protegidas");
            var f = new SeguridadConCfaFalsa();
            var m = new SeguridadModelo(f);
            Check(!FilaRansomware(m).HayAccion, "sin revisar: no hay botón para activar (no se sabe cómo está)");

            f.Responde = s => s == SeccionDeSeguridad.Ransomware ? Rev(s, new[] { Cfa("CFA-APAGADO") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
            Check(FilaRansomware(m).HayAccion && FilaRansomware(m).Accion == SeguridadModelo.TextoDeActivar, "apagada: aparece «Activar la protección...»");
            Check(m.Secciones.Where(x => x.Seccion != SeccionDeSeguridad.Ransomware).All(x => !x.HayAccion), "en ninguna otra sección");
            Check(f.Previsualizaciones.Count == 0 && f.Aplicados.Count == 0, "revisar NO pide ningún plan ni cambia nada");

            foreach (string id in new[] { "CFA-AUDITORIA", "CFA-SOLO-DISCOS" })
            {
                f.Responde = s => Rev(s, new[] { Cfa(id) });
                Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
                Check(FilaRansomware(m).HayAccion, id + ": también se ofrece activar");
            }
            foreach (string[] ids in new[] { new[] { "CFA-ACTIVO" }, new[] { "CFA-APAGADO", "CFA-SIN-TIEMPO-REAL" }, new[] { "CFA-APAGADO", "CFA-OTRO-ANTIVIRUS" }, new[] { "CFA-BLOQUEO" } })
            {
                f.Responde = s => Rev(s, ids.Select(i => Cfa(i)).ToList());
                Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
                Check(!FilaRansomware(m).HayAccion, string.Join("+", ids) + ": NO se ofrece (ya activa, o no funcionaría)");
            }
            f.Responde = _ => Consulta<RevisionDeSeccion>.Mal("no se pudo");
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
            Check(!FilaRansomware(m).HayAccion, "revisión fallida: no se ofrece");

            // Aplicar: el resultado anterior deja de valer y se vuelve a revisar.
            f.Responde = s => Rev(s, new[] { Cfa("CFA-APAGADO") });
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
            Consulta<PlanDelServicio> plan = m.PrevisualizarActivarCarpetasAsync().GetAwaiter().GetResult();
            Check(plan.Valor is { HayCambios: true } && f.Previsualizaciones.SequenceEqual(new[] { "activar" }) && f.Aplicados.Count == 0, "la vista previa pide «activar» y no aplica nada");
            f.Llamadas.Clear();
            f.Responde = s => Rev(s, new[] { Cfa("CFA-ACTIVO", Severidad.Info) });
            ResultadoDeAccion r = m.AplicarCarpetasProtegidasAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(r.Exito && f.Aplicados.Count == 1 && f.Llamadas.SequenceEqual(new[] { SeccionDeSeguridad.Ransomware }) && !FilaRansomware(m).HayAccion && FilaRansomware(m).Estado.StartsWith("Sin problemas"),
                "al aplicar se vuelve a revisar: ahora sale activada y el botón desaparece", FilaRansomware(m).Estado);

            // Con UAC el cambio lo hace otro proceso, mas tarde: el resultado viejo NO puede quedar a la vista como si fuera el actual.
            f.Responde = s => Rev(s, new[] { Cfa("CFA-APAGADO") });
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Ransomware));
            f.Llamadas.Clear();
            f.Resultado = new ResultadoDeAccion(true, true, "Se abrio el aviso de aprobacion (UAC).");
            m.AplicarCarpetasProtegidasAsync(new string('b', 64)).GetAwaiter().GetResult();
            Check(f.Llamadas.Count == 0 && FilaRansomware(m).Estado == "Sin revisar" && !FilaRansomware(m).HayAccion, "con UAC: la sección queda «Sin revisar» (el resultado viejo ya no vale), sin botón");

            // El servicio por omision (sin pipe) no puede cambiar Defender, y lo dice.
            IServicioDeSeguridad sinServicio = new ServicioDeSeguridadNoDisponible("x");
            Check(sinServicio.PrevisualizarCarpetasProtegidasAsync("activar", CancellationToken.None).GetAwaiter().GetResult().Error!.Contains("servicio de Nexo"),
                "sin servicio: no se puede, y se dice por qué");
        }
    }
}
