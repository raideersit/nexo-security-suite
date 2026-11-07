using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Headless;
using Avalonia.Threading;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class SeguridadFalsa : IServicioDeSeguridad
        {
            public readonly List<SeccionDeSeguridad> Llamadas = new();
            public Func<SeccionDeSeguridad, Consulta<RevisionDeSeccion>> Responde = s => Limpia(s);
            public TaskCompletionSource<bool>? Puerta;

            public async Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
            {
                Llamadas.Add(seccion);
                if (Puerta is not null) await Puerta.Task;
                return Responde(seccion);
            }
        }

        private static readonly DateTimeOffset Ahora = new(2026, 11, 7, 12, 30, 0, TimeSpan.Zero);

        private static Consulta<RevisionDeSeccion> Rev(SeccionDeSeguridad s, IReadOnlyList<HallazgoDeSistema> h, IReadOnlyList<string>? no = null, string? nota = null, int? n = 3)
            => Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(s, new ResultadoDeAnalisis(h, no ?? Array.Empty<string>()), Ahora, nota, n));

        private static Consulta<RevisionDeSeccion> Limpia(SeccionDeSeguridad s) => Rev(s, Array.Empty<HallazgoDeSistema>());

        private static HallazgoDeSistema Hallazgo(Severidad sev, string titulo = "Algo", string? sujeto = null)
            => new("ID-" + titulo, sev, titulo, "Detalle de " + titulo, "Hacer algo con " + titulo, sujeto);

        private static void ProbarSeguridad()
        {
            Console.WriteLine("Pestaña Seguridad: el modelo");
            var f = new SeguridadFalsa();
            var m = new SeguridadModelo(f);

            Check(f.Llamadas.Count == 0, "al crearse NO revisa nada (la de aplicaciones usa Internet: solo cuando el usuario lo pide)");
            Check(m.Secciones.Count == 4 && m.Secciones.All(s => s.Estado == "Sin revisar") && m.Indicador == Indicador.SinDatos, "al principio: 4 secciones «Sin revisar» (3 locales y la de NVD) y el indicador sin datos");
            Check(m.Titulo == "Sin revisar todavía" && m.Explicacion.Contains("Solo se lee") && m.Explicacion.Contains("Internet"), "el titulo dice «Sin revisar todavía» y la explicacion avisa que solo lee y que una usa Internet");
            Check(m.PuedeRevisarTodo, "se puede pulsar «Revisar todo»");
            Check(m.Secciones.Select(s => s.Nombre).SequenceEqual(new[] { "Cuentas y contraseñas del sistema", "Redes Wi-Fi", "Aplicaciones desactualizadas", "Fallos de seguridad conocidos en tus aplicaciones (NVD)" }), "los nombres de las 4 secciones, en español y en orden");

            // Todo limpio y completo.
            Esperar(m.RevisarTodoAsync());
            Check(f.Llamadas.SequenceEqual(new[] { SeccionDeSeguridad.Cuentas, SeccionDeSeguridad.Wifi, SeccionDeSeguridad.Aplicaciones }), "«Revisar todo» pide las 3, en orden", string.Join(",", f.Llamadas));
            Check(m.Indicador == Indicador.Correcto && m.Titulo == "Sin problemas en lo que se pudo revisar", "las 3 limpias y completas: verde, «Sin problemas en lo que se pudo revisar»", m.Titulo);
            Check(m.Explicacion.Contains("no es una garantía"), "y aun asi dice que no es una garantia");
            Check(m.Secciones.Take(3).All(s => s.Estado == "Sin hallazgos") && m.Secciones[3].Estado == "Sin revisar" && m.Secciones[0].Resumen.Contains("3 cuentas locales") && m.Secciones[1].Resumen.Contains("3 redes guardadas"),
                  "cada seccion dice «Sin hallazgos» y cuantos elementos miro", m.Secciones[0].Resumen + " | " + m.Secciones[1].Resumen);
            Check(m.Secciones[0].Resumen.Contains("revisado a las"), "y a que hora se reviso");

            // Colores segun la gravedad.
            f.Responde = s => s == SeccionDeSeguridad.Cuentas ? Rev(s, new[] { Hallazgo(Severidad.Alta, "Grave") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Estado == "Hay hallazgos graves" && m.Indicador == Indicador.Alerta && m.Titulo == "Hay hallazgos graves", "un hallazgo Alto: la seccion y el general en alerta");
            Check(m.Secciones[0].Hallazgos.Single().Gravedad == "Alta" && m.Secciones[0].Hallazgos.Single().Detalle == "Detalle de Grave" && m.Secciones[0].HayHallazgos, "el hallazgo se ve con su gravedad y su detalle");

            f.Responde = s => s == SeccionDeSeguridad.Cuentas ? Rev(s, new[] { Hallazgo(Severidad.Media, "Medio", "ana") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Estado == "Hay cosas que revisar" && m.Indicador == Indicador.Atencion, "un hallazgo Medio: atencion (amarillo)");
            Check(m.Secciones[0].Hallazgos.Single().TieneSujeto && m.Secciones[0].Hallazgos.Single().Sujeto == "ana", "y muestra a quien se refiere");

            f.Responde = s => s == SeccionDeSeguridad.Cuentas ? Rev(s, new[] { Hallazgo(Severidad.Baja, "Bajo") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Estado == "Hay cosas que revisar", "un hallazgo Bajo tambien pide atencion");

            f.Responde = s => s == SeccionDeSeguridad.Cuentas ? Rev(s, new[] { Hallazgo(Severidad.Info, "Nota") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Estado == "Sin problemas (solo notas)" && m.Indicador == Indicador.Correcto, "solo notas informativas: sigue siendo «sin problemas», pero la nota se ve");
            Check(m.Secciones[0].Hallazgos.Single().Gravedad == "Info" && !m.Secciones[0].Hallazgos.Single().Color.Equals(Nexo.Ui.Desktop.Colores.De(Indicador.Correcto)), "y la nota no lleva color de alarma");

            f.Responde = s => s == SeccionDeSeguridad.Cuentas ? Rev(s, new[] { Hallazgo(Severidad.Critica, "Critico") }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Hallazgos.Single().Gravedad == "Crítica" && m.Indicador == Indicador.Alerta, "Critica se escribe «Crítica» y es alerta");

            // Incompleto: nunca verde.
            f.Responde = s => s == SeccionDeSeguridad.Wifi ? Rev(s, Array.Empty<HallazgoDeSistema>(), new[] { "No se pudo leer el perfil de la red «Cafe»." }) : Limpia(s);
            Esperar(m.RevisarTodoAsync());
            Check(m.Secciones[1].Estado == "Revisión incompleta" && m.Secciones[1].HayNoEvaluado && m.Secciones[1].NoEvaluado.Single().Contains("Cafe"), "sin hallazgos pero incompleta: «Revisión incompleta» y lista lo que no se pudo");
            Check(m.Indicador == Indicador.Atencion && m.Titulo == "Hay cosas que revisar", "y el general NO es verde: pide atencion", m.Titulo + " " + m.Indicador);

            f.Responde = s => s == SeccionDeSeguridad.Wifi ? Rev(s, new[] { Hallazgo(Severidad.Alta, "Wep") }, new[] { "otro" }) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Wifi));
            Check(m.Secciones[1].Estado == "Hallazgos, revisión incompleta" && m.Secciones[1].Color.Equals(m.Secciones[1].Hallazgos.Single().Color), "con hallazgo grave Y incompleta: manda lo grave en el color y el texto dice las dos cosas");

            // Una revision que falla.
            f.Responde = s => s == SeccionDeSeguridad.Aplicaciones ? Consulta<RevisionDeSeccion>.Mal("winget no responde") : Limpia(s);
            Esperar(m.RevisarTodoAsync());
            Check(m.Secciones[2].Estado == "No se pudo revisar" && m.Secciones[2].Resumen == "winget no responde." && !m.Secciones[2].HayHallazgos, "una revision que falla dice «No se pudo revisar» y por que");
            Check(m.Indicador == Indicador.SinDatos && m.Titulo == "Revisión parcial" && m.Explicacion.Contains("no significa que esté bien"), "y el general es «Revisión parcial», NUNCA verde, aunque las otras dos esten limpias", m.Titulo);

            // Una excepcion del servicio no tira la ventana.
            f.Responde = s => throw new InvalidOperationException("boom");
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m.Secciones[0].Estado == "No se pudo revisar" && m.Secciones[0].Resumen.Contains("error inesperado"), "una excepcion del servicio se muestra como «no se pudo revisar»");

            // Solo una seccion revisada y limpia: no es verde.
            var f2 = new SeguridadFalsa();
            var m2 = new SeguridadModelo(f2);
            Esperar(m2.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m2.Indicador == Indicador.SinDatos && m2.Titulo == "Revisión parcial", "con solo una de tres revisada y limpia, el general es «Revisión parcial», no verde", m2.Titulo);
            Check(m2.Secciones[1].Estado == "Sin revisar" && m2.Secciones[0].Estado == "Sin hallazgos", "las otras siguen «Sin revisar»");

            // Alerta de una manda aunque las otras no se hayan mirado.
            var f3 = new SeguridadFalsa { Responde = s => Rev(s, new[] { Hallazgo(Severidad.Alta) }) };
            var m3 = new SeguridadModelo(f3);
            Esperar(m3.RevisarAsync(SeccionDeSeguridad.Wifi));
            Check(m3.Indicador == Indicador.Alerta, "una alerta manda aunque las otras no se hayan revisado");

            // Sin adaptador Wi-Fi: un hecho, no un fallo ni un hallazgo.
            var f4 = new SeguridadFalsa { Responde = s => Rev(s, Array.Empty<HallazgoDeSistema>(), nota: s == SeccionDeSeguridad.Wifi ? "Este equipo no tiene adaptador Wi-Fi: no hay redes que revisar." : null) };
            var m4 = new SeguridadModelo(f4);
            Esperar(m4.RevisarTodoAsync());
            Check(m4.Secciones[1].Estado == "No aplica" && m4.Secciones[1].Resumen.Contains("no tiene adaptador Wi-Fi") && m4.Indicador == Indicador.Correcto, "sin adaptador Wi-Fi: «No aplica» con el motivo, y no impide el verde");

            // Lo viejo no se queda a la vista mientras se vuelve a revisar.
            var f5 = new SeguridadFalsa { Responde = s => Rev(s, new[] { Hallazgo(Severidad.Alta, "Viejo") }) };
            var m5 = new SeguridadModelo(f5);
            Esperar(m5.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(m5.Secciones[0].HayHallazgos, "control: la primera revision deja un hallazgo");
            f5.Puerta = new TaskCompletionSource<bool>();
            Task t = m5.RevisarAsync(SeccionDeSeguridad.Cuentas);
            Check(m5.Secciones[0].Estado == "Revisando..." && !m5.Secciones[0].HayHallazgos && m5.Secciones[0].Revisando && !m5.Secciones[0].PuedeRevisar,
                  "mientras se revisa de nuevo: «Revisando...», sin el hallazgo anterior y sin poder pulsar otra vez");
            Check(!m5.PuedeRevisarTodo, "y «Revisar todo» queda deshabilitado");
            int antes = f5.Llamadas.Count;
            // El segundo clic debe volver AL INSTANTE (no se espera): si la guarda faltara, esta llamada quedaria esperando la puerta y la prueba fallaria en vez de colgarse.
            Task segundo = m5.RevisarAsync(SeccionDeSeguridad.Cuentas);
            Check(segundo.IsCompleted && f5.Llamadas.Count == antes, "un segundo clic durante la revision vuelve al instante y no lanza otra");
            f5.Responde = s => Consulta<RevisionDeSeccion>.Mal("se cayo");
            f5.Puerta.SetResult(true);
            Esperar(t);
            Esperar(segundo);
            Check(m5.Secciones[0].Estado == "No se pudo revisar" && !m5.Secciones[0].HayHallazgos && m5.PuedeRevisarTodo, "si la nueva revision falla, NO reaparece el resultado viejo, y se puede volver a pulsar");

            // Cancelar «Revisar todo» no sigue pidiendo.
            var f6 = new SeguridadFalsa();
            var m6 = new SeguridadModelo(f6);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            Esperar(m6.RevisarTodoAsync(cts.Token));
            Check(f6.Llamadas.Count == 0, "con la cancelacion pedida no se lanza ninguna revision");

            // Colores: el peor manda, y «no se sabe» pesa mas que «bien».
            Check(ResumirSeguridad.Mas(Indicador.Correcto, Indicador.SinDatos) == Indicador.SinDatos && ResumirSeguridad.Mas(Indicador.SinDatos, Indicador.Atencion) == Indicador.Atencion
                  && ResumirSeguridad.Mas(Indicador.Atencion, Indicador.Alerta) == Indicador.Alerta && ResumirSeguridad.Mas(Indicador.Correcto, Indicador.Correcto) == Indicador.Correcto,
                  "orden de gravedad: alerta > atencion > no se sabe > correcto");

            // Fuente por omision en este destino (Linux/portable).
            IServicioDeSeguridad porDefecto = Fuentes.SeguridadPorDefecto();
            Consulta<RevisionDeSeccion> r = porDefecto.RevisarAsync(SeccionDeSeguridad.Cuentas, CancellationToken.None).GetAwaiter().GetResult();
            Check(r.Valor is null && r.Error!.Contains("Windows"), "este destino (portable) no puede revisar: la fuente por omision lo dice y no inventa una revision", r.Error);
        }

        private static void ProbarVentanaDeSeguridad(MainWindow w, SeguridadModelo sm, SeguridadFalsa f, string? captura)
        {
            // La pestaña Seguridad NO revisa sola al entrar: la de aplicaciones usa Internet.
            w.Pestanas.SelectedIndex = 7;
            Dispatcher.UIThread.RunJobs();
            Check(f.Llamadas.Count == 0, "pestaña Seguridad: entrar en la pestaña NO lanza ninguna revision");
            Check(w.TituloDeSeguridad.Text == "Sin revisar todavía" && w.ListaDeSecciones.ItemCount == 4 && w.BotonRevisarTodo.IsEnabled,
                "pestaña Seguridad: titulo «Sin revisar todavía», 4 secciones y «Revisar todo» habilitado", w.TituloDeSeguridad.Text);

            f.Responde = s => s switch
            {
                SeccionDeSeguridad.Cuentas => Rev(s, new[] { Hallazgo(Severidad.Media, "La política local no exige longitud mínima") }),
                SeccionDeSeguridad.Wifi => Limpia(s),
                _ => Rev(s, new[] { Hallazgo(Severidad.Media, "Un programa muy atacado está desactualizado", "Java 8 Update 401"), Hallazgo(Severidad.Baja, "19 aplicaciones tienen una versión más nueva") },
                         new[] { "agrego mas informacion" })
            };
            Esperar(sm.RevisarTodoAsync());
            Dispatcher.UIThread.RunJobs();
            Check(f.Llamadas.Count == 3 && w.TituloDeSeguridad.Text == "Hay cosas que revisar", "tras «Revisar todo»: 3 revisiones y el titulo enlazado", w.TituloDeSeguridad.Text);
            Check(w.ListaDeSecciones.ItemCount == 4, "las 4 secciones siguen en la lista");

            if (captura is not null)
            {
                AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                string octava = System.IO.Path.ChangeExtension(captura, null) + "-seguridad.png";
                w.CaptureRenderedFrame()?.Save(octava);
                Console.WriteLine("           captura: " + octava);
            }
        }
    }
}
