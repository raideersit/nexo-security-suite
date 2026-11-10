using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
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
        private sealed class SeguridadConSenuelosFalsa : IServicioDeSeguridad
        {
            public readonly List<SeccionDeSeguridad> Llamadas = new();
            public readonly List<string> Repuestos = new();
            public int Previsualizaciones;
            public Func<SeccionDeSeguridad, Consulta<RevisionDeSeccion>> Responde = s => Limpia(s);
            public ResultadoDeAccion Resultado = new(true, false, "1 señuelo repuesto.");

            public Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct) { Llamadas.Add(seccion); return Task.FromResult(Responde(seccion)); }

            public Task<Consulta<PlanDelServicio>> PrevisualizarReponerSenuelosAsync(CancellationToken ct)
            {
                Previsualizaciones++;
                return Task.FromResult(Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Se repone 1 señuelo tocado.", true, new string('c', 64), Array.Empty<string>())));
            }

            public Task<ResultadoDeAccion> ReponerSenuelosAsync(string token, CancellationToken ct) { Repuestos.Add(token); return Task.FromResult(Resultado); }
        }

        private static RespuestaCruda JsonS(string json) => new(true, null, JsonDocument.Parse(json).RootElement.Clone());

        private const string SenueloIntacto = "{\"ruta\":\"C:\\\\Users\\\\ana\\\\Documents\\\\zz-nexo-señuelo.xlsx\",\"carpeta\":\"C:\\\\Users\\\\ana\\\\Documents\",\"tocado\":false,\"hallazgo\":null,\"no_comprobado\":null}";

        private static string Tocado(string tipo, string severidad, string? noComprobado = null)
            => "{\"ruta\":\"C:\\\\Users\\\\ana\\\\Documents\\\\!nexo-señuelo.docx\",\"carpeta\":\"C:\\\\Users\\\\ana\\\\Documents\",\"tocado\":true,"
             + "\"hallazgo\":{\"tipo\":\"" + tipo + "\",\"severidad\":\"" + severidad + "\",\"detalle\":\"Su contenido cambió.\",\"cuando\":\"2026-11-09T20:00:00-03:00\",\"nueva_ruta\":null},"
             + "\"no_comprobado\":" + (noComprobado is null ? "null" : "\"" + noComprobado + "\"") + "}";

        private static string Estado(string senuelos, bool rafaga = false, string ultima = "\"2026-11-09T20:00:30-03:00\"", string aviso = "null", string sin = "[]")
            => "{\"activo\":true,\"intervalo_segundos\":30,\"ultima_revision\":" + ultima + ",\"todo_en_orden\":false,\"tocados\":0,\"rafaga\":" + (rafaga ? "true" : "false")
             + ",\"senuelos\":[" + senuelos + "],\"sin_senuelo\":" + sin + ",\"aviso\":" + aviso + ",\"nota\":\"x\"}";

        private static void ProbarSenuelosEnLaVentana()
        {
            Console.WriteLine("Pestaña Seguridad: señuelos contra ransomware (lo que dice el servicio)");

            // --- El lector ---
            Consulta<RevisionDeSenuelos> c = LectorDeSenuelosDelServicio.Leer(JsonS("{\"activo\":false,\"todo_en_orden\":false,\"nota\":\"apagados\"}"));
            Check(c.Valor is { Nota: not null, Senuelos: 0 } && c.Valor.Nota.Contains("Nexo:Senuelos:Activo") && c.Valor.Analisis.Completo, "apagados: una nota con dónde activarlos (no es un fallo)");

            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(SenueloIntacto + "," + SenueloIntacto.Replace("zz-", "otro-"),
                sin: "[{\"carpeta\":\"C:\\\\Users\\\\ana\\\\OneDrive\\\\Escritorio\",\"motivo\":\"carpeta de OneDrive: no se pone\"}]")));
            Check(c.Valor is { Senuelos: 2, Tocados: 0 } && c.Valor.Analisis.Completo && c.Valor.Analisis.Hallazgos.Single() is { Severidad: Severidad.Info, Id: "SENUELO-SIN-PONER" } h0
                  && h0.Detalle.Contains("OneDrive") && h0.Sujeto!.Contains("OneDrive"), "intactos: completa, y la carpeta sin señuelo como nota informativa con su motivo");

            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("modificado", "Alta") + "," + SenueloIntacto.Replace("\"no_comprobado\":null", "\"no_comprobado\":\"otro programa lo tiene abierto\""))));
            HallazgoDeSistema? h1 = c.Valor?.Analisis.Hallazgos.SingleOrDefault();
            Check(h1 is { Severidad: Severidad.Alta, Id: "SENUELO-MODIFICADO" } && h1.Sujeto!.EndsWith("!nexo-señuelo.docx") && h1.Titulo.Contains("cambió de contenido")
                  && h1.Detalle.Contains("no sabe qué programa") && h1.Recomendacion.Contains("desconecta") && h1.Recomendacion.Contains("Reponer señuelos"),
                "un tocado: hallazgo Alta con la ruta, qué hacer y que Nexo no sabe qué programa fue", h1?.Recomendacion);
            Check(c.Valor!.Tocados == 1 && !c.Valor.Analisis.Completo && c.Valor.Analisis.NoEvaluado.Single().Contains("no se pudo comprobar (otro programa lo tiene abierto)"),
                "un señuelo que no se pudo comprobar: «no evaluado» (la sección no puede salir en verde)");

            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("modificado", "Alta") + "," + Tocado("renombrado", "Alta"), rafaga: true)));
            Check(c.Valor!.Analisis.Hallazgos[0] is { Severidad: Severidad.Critica, Id: "SENUELOS-RAFAGA" } hr && hr.Recomendacion.Contains("Desconecta"), "ráfaga: un hallazgo Crítico el primero, con qué hacer ya");

            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("borrado", "Media"))));
            Check(c.Valor!.Analisis.Hallazgos.Single() is { Severidad: Severidad.Media } hp && hp.Recomendacion.Contains("Si fuiste tú"), "a la papelera (Media): «si fuiste tú, repónlo»");

            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(SenueloIntacto, ultima: "null", aviso: "\"la última revisión falló (IOException)\"")));
            Check(c.Valor!.Analisis.NoEvaluado.Count == 2 && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("aún no ha revisado")) && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("falló")),
                "sin revisión todavía, o con un aviso del servicio: «no evaluado»");
            c = LectorDeSenuelosDelServicio.Leer(JsonS(Estado("")));
            Check(c.Valor!.Analisis.NoEvaluado.Any(x => x.Contains("ningún señuelo")), "activos pero sin ningún señuelo puesto: no es «todo bien»");

            Check(LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("modificado", "Grave")))).Error == "respuesta del servicio no reconocida", "una gravedad desconocida invalida la respuesta entera");
            Check(LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("modificado", "Alta")).Replace(",\"rafaga\":false", ""))).Error is not null, "sin «rafaga»: no se interpreta a medias");
            Check(LectorDeSenuelosDelServicio.Leer(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("versión sin señuelos"), "un servicio antiguo (método desconocido): se dice");
            Check(LectorDeSenuelosDelServicio.Leer(new RespuestaCruda(false, "otra cosa", null)).Error == "otra cosa", "otro error del servicio: tal cual");

            // --- La sección en el modelo ---
            var f = new SeguridadConSenuelosFalsa();
            var m = new SeguridadModelo(f);
            FilaDeSeccion Fila() => m.Secciones.Single(x => x.Seccion == SeccionDeSeguridad.Senuelos);
            Check(Fila().Nombre.StartsWith("Señuelos contra ransomware") && !Fila().HayAccion, "la sección existe, sin botón antes de revisar");

            var apagado = LectorDeSenuelosDelServicio.Leer(JsonS("{\"activo\":false}")).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Senuelos ? Rev(s, apagado.Analisis.Hallazgos, apagado.Analisis.NoEvaluado, apagado.Nota, null) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Senuelos));
            Check(Fila().Estado == "No aplica" && Fila().Resumen.Contains("apagados") && !Fila().HayAccion, "apagados: «No aplica», con la explicación", Fila().Estado);

            var tocado = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(Tocado("modificado", "Alta") + "," + SenueloIntacto))).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Senuelos ? Rev(s, tocado.Analisis.Hallazgos, tocado.Analisis.NoEvaluado, null, tocado.Senuelos) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Senuelos));
            Check(Fila().Estado == "Hay hallazgos graves" && Fila().Resumen.Contains("2 señuelos vigilados") && Fila().HayAccion && Fila().Accion == SeguridadModelo.TextoDeReponer,
                "un tocado: en rojo, cuántos se vigilan, y botón «Reponer señuelos...»", Fila().Resumen);
            Check(m.Secciones.Where(x => x.Seccion != SeccionDeSeguridad.Senuelos).All(x => !x.HayAccion) && f.Previsualizaciones == 0 && f.Repuestos.Count == 0,
                "solo en esa sección, y revisar no pidió ningún plan");

            var soloNota = LectorDeSenuelosDelServicio.Leer(JsonS(Estado(SenueloIntacto, sin: "[{\"carpeta\":\"C:\\\\x\",\"motivo\":\"ocupado\"}]"))).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Senuelos ? Rev(s, soloNota.Analisis.Hallazgos, soloNota.Analisis.NoEvaluado, null, 1) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Senuelos));
            Check(!Fila().HayAccion && Fila().Estado == "Sin problemas (solo notas)", "solo una carpeta sin señuelo: sin botón (no hay nada que reponer) y sin alarma", Fila().Estado);

            // Reponer: plan -> aplicar -> se vuelve a revisar.
            f.Responde = s => s == SeccionDeSeguridad.Senuelos ? Rev(s, tocado.Analisis.Hallazgos, tocado.Analisis.NoEvaluado, null, 2) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Senuelos));
            Consulta<PlanDelServicio> plan = m.PrevisualizarReponerSenuelosAsync().GetAwaiter().GetResult();
            int antes = f.Llamadas.Count(x => x == SeccionDeSeguridad.Senuelos);
            ResultadoDeAccion r = m.ReponerSenuelosAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(f.Previsualizaciones == 1 && f.Repuestos.Single() == new string('c', 64) && r.Exito, "reponer: un plan del servicio y se aplica con su token");
            Check(f.Llamadas.Count(x => x == SeccionDeSeguridad.Senuelos) == antes + 1, "y después se vuelve a revisar la sección");

            f.Resultado = new ResultadoDeAccion(true, true, "Se abrió el aviso de aprobación (UAC).");
            antes = f.Llamadas.Count(x => x == SeccionDeSeguridad.Senuelos);
            m.ReponerSenuelosAsync(new string('c', 64)).GetAwaiter().GetResult();
            Check(Fila().Estado == "Sin revisar" && f.Llamadas.Count(x => x == SeccionDeSeguridad.Senuelos) == antes,
                "si se abrió el UAC: la sección queda «Sin revisar» (el cambio llega después), sin mostrar el estado viejo");

            // Sin servicio.
            IServicioDeSeguridad sin = new ServicioDeSeguridadNoDisponible("x");
            Check(sin.PrevisualizarReponerSenuelosAsync(CancellationToken.None).GetAwaiter().GetResult().Error == LectorDeSenuelosDelServicio.SinServicio
                  && !sin.ReponerSenuelosAsync("t", CancellationToken.None).GetAwaiter().GetResult().Exito, "sin servicio: no se puede reponer, y se dice por qué");
        }
    }
}
