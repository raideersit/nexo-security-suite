using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class SeguridadConNvdFalsa : IServicioDeSeguridad
        {
            public readonly List<SeccionDeSeguridad> Llamadas = new();
            public readonly List<IReadOnlyList<AplicacionDesactualizada>> ConsultasNvd = new();
            public IReadOnlyList<AplicacionDesactualizada> Apps = Array.Empty<AplicacionDesactualizada>();
            public Func<Consulta<RevisionDeSeccion>> RespondeNvd = () => Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(SeccionDeSeguridad.FallosConocidos, new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), Ahora, Elementos: 1));
            public TaskCompletionSource<bool>? PuertaNvd;
            public string? AvisoDeProgreso;
            public IProgress<string>? UltimoProgreso;

            public Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
            {
                Llamadas.Add(seccion);
                return Task.FromResult(seccion == SeccionDeSeguridad.Aplicaciones
                    ? Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), Ahora, Elementos: Apps.Count, Aplicaciones: Apps))
                    : Limpia(seccion));
            }

            public async Task<Consulta<RevisionDeSeccion>> RevisarFallosConocidosAsync(IReadOnlyList<AplicacionDesactualizada> aplicaciones, IProgress<string>? progreso, CancellationToken ct)
            {
                ConsultasNvd.Add(aplicaciones);
                UltimoProgreso = progreso;
                if (AvisoDeProgreso is not null) progreso?.Report(AvisoDeProgreso);
                if (PuertaNvd is not null) await PuertaNvd.Task;
                return RespondeNvd();
            }
        }

        private static AplicacionDesactualizada AppNvd(string nombre, string id, string v) => new(nombre, id, v, "99.0", "winget");

        private static void ProbarSeguridadFallosConocidos()
        {
            Console.WriteLine("Pestaña Seguridad: fallos conocidos (NVD)");
            var apps = new[] { AppNvd("WinRAR 7.01", "RARLab.WinRAR", "7.01.0"), AppNvd("Git", "Git.Git", "2.54.0"), AppNvd("Obsidian", "Obsidian.Obsidian", "1.13.7") };
            var f = new SeguridadConNvdFalsa { Apps = apps };
            var m = new SeguridadModelo(f);

            // PRIVACIDAD: lo que envia datos a Internet solo corre con su propio boton.
            Check(m.Secciones[3].Seccion == SeccionDeSeguridad.FallosConocidos && m.Secciones[3].Boton == "Consultar NVD" && m.Secciones.Take(3).All(s => s.Boton == "Revisar"),
                "la cuarta seccion se llama «Consultar NVD»; las otras tres siguen con «Revisar»");
            Check(m.Secciones[3].Resumen.Contains("Opcional") && m.Secciones[3].Resumen.Contains("nombre y la versión") && m.Secciones[3].Resumen.Contains("antes te lo pregunta"), "antes de pulsar, la seccion explica que es opcional y que solo se envian nombre y version");
            Esperar(m.RevisarTodoAsync());
            Check(f.ConsultasNvd.Count == 0 && f.Llamadas.SequenceEqual(new[] { SeccionDeSeguridad.Cuentas, SeccionDeSeguridad.Wifi, SeccionDeSeguridad.Aplicaciones, SeccionDeSeguridad.Dispositivos }),
                "«Revisar todo» NO consulta NVD (no envia nada a Internet a espaldas del usuario)", f.ConsultasNvd.Count.ToString());
            Check(m.Secciones[3].Estado == "Sin revisar" && m.Indicador == Indicador.Correcto && m.Titulo == "Sin problemas en lo que se pudo revisar",
                "y el resultado general de las tres locales no cambia por el cruce que no se hizo", m.Titulo);
            Check(m.Explicacion.Contains("no es una garantía"), "el general sigue diciendo que no es una garantia");

            // Sin revisar las aplicaciones no hay nada que consultar.
            var fs = new SeguridadConNvdFalsa();
            var sinApps = new SeguridadModelo(fs);
            Esperar(sinApps.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(fs.ConsultasNvd.Count == 0 && sinApps.Secciones[3].Estado == "No se pudo revisar" && sinApps.Secciones[3].Resumen.Contains("primero revisa las aplicaciones"),
                "sin haber revisado las aplicaciones: no sale nada a Internet y se explica que primero hay que revisarlas", sinApps.Secciones[3].Resumen);

            // Con las aplicaciones revisadas, recibe EXACTAMENTE esas.
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(f.ConsultasNvd.Count == 1 && f.ConsultasNvd[0].SequenceEqual(apps), "el cruce recibe exactamente las aplicaciones de la ultima revision");
            Check(m.Secciones[3].Estado == "Sin hallazgos" && m.Secciones[3].Resumen.Contains("1 programa consultado") && m.Secciones[3].Resumen.Contains("revisado a las"), "resultado limpio y completo: «Sin hallazgos», con cuantos programas y a que hora");

            // Con fallos graves: alerta; y cuenta para el general.
            f.RespondeNvd = () => Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(SeccionDeSeguridad.FallosConocidos,
                new ResultadoDeAnalisis(new[] { new HallazgoDeSistema("APP-CVE", Severidad.Alta, "3 fallos de seguridad conocidos en tu versión", "WinRAR...", "Actualiza: winget upgrade --id RARLab.WinRAR", "WinRAR 7.01") }, Array.Empty<string>()), Ahora, Elementos: 2));
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(m.Secciones[3].Estado == "Hay hallazgos graves" && m.Indicador == Indicador.Alerta && m.Titulo == "Hay hallazgos graves", "un fallo conocido Alto: la seccion y el general en alerta", m.Titulo);
            Check(m.Secciones[3].Hallazgos.Single().Sujeto == "WinRAR 7.01" && m.Secciones[3].Hallazgos.Single().Recomendacion.Contains("winget upgrade --id RARLab.WinRAR"), "se ve de que programa es y la orden para actualizar");

            // Incompleto (apps sin mapa / sin red): nunca verde.
            f.RespondeNvd = () => Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(SeccionDeSeguridad.FallosConocidos,
                new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), new[] { "1 aplicación(es) no están en la lista que Nexo sabe cruzar y no se consultaron: Obsidian." }), Ahora, Elementos: 2));
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(m.Secciones[3].Estado == "Revisión incompleta" && m.Secciones[3].HayNoEvaluado && m.Indicador == Indicador.Atencion && m.Indicador != Indicador.Correcto,
                "un cruce incompleto: «Revisión incompleta» y el general NO es verde", m.Titulo);

            // Un fallo de la consulta tampoco es verde.
            f.RespondeNvd = () => Consulta<RevisionDeSeccion>.Mal("error inesperado al consultar (X)");
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(m.Secciones[3].Estado == "No se pudo revisar" && m.Indicador == Indicador.SinDatos && m.Titulo == "Revisión parcial", "si la consulta falla: «No se pudo revisar» y el general es «Revisión parcial», nunca verde", m.Titulo);

            // Volver a leer las aplicaciones invalida el cruce anterior.
            f.RespondeNvd = () => Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(SeccionDeSeguridad.FallosConocidos, new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), Ahora, Elementos: 1));
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(m.Secciones[3].Estado == "Sin hallazgos", "(preparacion) el cruce vuelve a estar limpio");
            f.Apps = new[] { AppNvd("Otra", "Git.Git", "2.55.0") };
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Check(m.Secciones[3].Estado == "Sin revisar", "al volver a revisar las aplicaciones, el cruce anterior se borra (no se muestra sobre otra lista)", m.Secciones[3].Estado);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(f.ConsultasNvd.Last()[0].VersionInstalada == "2.55.0", "y el siguiente cruce usa la lista NUEVA");

            // En marcha: progreso visible, y no se puede mezclar con una nueva lectura de aplicaciones.
            var f2 = new SeguridadConNvdFalsa { Apps = apps, PuertaNvd = new TaskCompletionSource<bool>(), AvisoDeProgreso = "Consultando 1 de 2: WinRAR 7.01" };
            var m2 = new SeguridadModelo(f2);
            Esperar(m2.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Task t = m2.RevisarAsync(SeccionDeSeguridad.FallosConocidos);
            EsperarHasta(Task.Run(() => { var sw = System.Diagnostics.Stopwatch.StartNew(); while (!m2.Secciones[3].Resumen.Contains("Consultando 1 de 2") && sw.ElapsedMilliseconds < 3000) { Thread.Sleep(5); } }));
            Dispatcher.UIThread.RunJobs();
            Check(m2.Secciones[3].Estado == "Revisando..." && m2.Secciones[3].Resumen.Contains("Consultando 1 de 2: WinRAR 7.01") && m2.Secciones[3].Resumen.Contains("7 segundos"),
                "mientras consulta: «Revisando...» con el progreso y el aviso de los 7 segundos", m2.Secciones[3].Resumen);
            Check(!m2.Secciones[3].PuedeRevisar, "y el boton no se puede pulsar otra vez");
            int antes = f2.Llamadas.Count;
            Esperar(m2.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Check(f2.Llamadas.Count == antes, "mientras se cruza, no se vuelve a leer la lista de aplicaciones (el cruce acabaria sobre otra lista)");
            f2.PuertaNvd.SetResult(true);
            Esperar(t);
            Dispatcher.UIThread.RunJobs();
            Check(m2.Secciones[3].Estado == "Sin hallazgos" && !m2.Secciones[3].Resumen.Contains("Consultando"), "al terminar, el progreso desaparece");

            // Un aviso de progreso tardio no pisa el resultado ya mostrado.
            var f3 = new SeguridadConNvdFalsa { Apps = apps };
            var m3 = new SeguridadModelo(f3);
            Esperar(m3.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Esperar(m3.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            string antesDelAviso = m3.Secciones[3].Resumen;
            f3.UltimoProgreso!.Report("Consultando 9 de 9: algo que llega tarde");
            Thread.Sleep(50);
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(50);
            Dispatcher.UIThread.RunJobs();
            Check(m3.Secciones[3].Resumen == antesDelAviso && m3.Secciones[3].Estado == "Sin hallazgos", "un aviso tardío de progreso no cambia un resultado ya mostrado");

            Check(ResumirSeguridad.Nombre(SeccionDeSeguridad.FallosConocidos).Contains("NVD") && ResumirSeguridad.Boton(SeccionDeSeguridad.Cuentas) == "Revisar", "nombre y boton de cada seccion");
            Check(MainWindow.TextoDeAvisoNvd.Contains("solo el nombre del programa y su versión") && MainWindow.TextoDeAvisoNvd.Contains("No se envía tu nombre") && MainWindow.TextoDeAvisoNvd.Contains("¿Continuar?") && MainWindow.TextoDeAvisoNvd.Contains("Nexo no instala ni cambia nada"),
                "el aviso previo dice que se envia, que no se envia y que Nexo no cambia nada");
        }

    }
}
