using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports.Model;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        public static async Task ProbarCopiaDelServicio()
        {
            Console.WriteLine("Copia versionada por el servicio: copia.estado y copia.hacer");
            var apagado = new ModuloCopiaApagado();
            var ea = await PedirSenuelos(apagado, "copia.estado", null);
            Check(ea.Ok && !ea.R!.Value.GetProperty("activo").GetBoolean(), "apagada: lo dice");
            Check(!(await PedirSenuelos(apagado, "copia.hacer", null)).Ok, "apagada: copia.hacer se niega");
            Check(!(await PedirSenuelos(apagado, "copia.restaurar", null)).Ok, "apagada: no existe copia.restaurar");
            Check(!(await PedirSenuelos(apagado, "copia.descartar", new { id = "20261112T201222Z" })).Ok, "apagada: copia.descartar se niega");

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-svc-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "docs"), destino = Path.Combine(raiz, "copia");
            Directory.CreateDirectory(docs);
            File.WriteAllText(Path.Combine(docs, "a.txt"), "uno");
            File.WriteAllText(Path.Combine(docs, "b.txt"), "dos");
            try
            {
                var w = new EscritorFalso();
                var ahora = new DateTimeOffset(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
                var ausente = new CarpetaSinSenuelo(@"C:\Users\ana\OneDrive\Escritorio", "carpeta de OneDrive");
                var m = new ModuloCopia(() => (new[] { docs, Path.Combine(raiz, "no-existe") }, new[] { ausente }), destino, 3, null, w, reloj: () => ahora);
                Check(m.Metodos.SequenceEqual(new[] { "copia.estado", "copia.hacer", "copia.descartar" }), "tres métodos: ninguno restaura, ninguno cambia destino ni carpetas");

                var e0 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(e0.GetProperty("activo").GetBoolean() && e0.GetProperty("ultima_correcta").ValueKind == JsonValueKind.Null && e0.GetProperty("sin_copia").GetArrayLength() == 1,
                      "estado inicial: activa, sin copia hecha y con la carpeta descartada a la vista");

                var h1 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h1.Ok && h1.R!.Value.GetProperty("exito").GetBoolean() && h1.R.Value.GetProperty("archivos").GetInt32() == 2 && h1.R.Value.GetProperty("nuevos").GetInt32() == 2,
                      "copia.hacer con disco real: 2 archivos nuevos (la carpeta que no existe se ignora)", h1.R?.ToString());
                var e1 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(e1.GetProperty("versiones_en_destino").GetInt32() == 1 && e1.GetProperty("destino_disponible").GetBoolean() && e1.GetProperty("ultimo").GetProperty("correcto").GetBoolean(),
                      "estado después: 1 versión en el destino");
                Check(w.Eventos.Count == 1 && w.Eventos[0].Tipo == TipoEvento.CopiaHecha && w.Eventos[0].Severidad == Severidad.Info, "evento Info «copia hecha»");

                var pronto = await PedirSenuelos(m, "copia.hacer", null);
                Check(!pronto.Ok && pronto.Codigo == ModuloCopia.DemasiadoPronto, "otra copia a los 0 s: demasiado pronto");
                ahora = ahora.AddMinutes(2);
                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno cambiado");
                var h2 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h2.Ok && h2.R!.Value.GetProperty("nuevos").GetInt32() == 1, "pasados 2 minutos, copia solo lo cambiado");
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }

            // Una a la vez, y estado «en curso» mientras dura
            {
                var puerta = new ManualResetEventSlim(false);
                int llamadas = 0;
                var w = new EscritorFalso();
                var m = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\copia", 3, null, w,
                    copiar: (c, t, ct) => { Interlocked.Increment(ref llamadas); puerta.Wait(); return new ResultadoDeCopia(true, null, new Instantanea("i", t, Array.Empty<EntradaDeCopia>(), Array.Empty<OmitidoEnCopia>(), false, null), 0, 0, 0, false, null); },
                    destinoDisponible: _ => true);
                Task<(bool, int, JsonElement?)> primera = PedirSenuelos(m, "copia.hacer", null);
                for (int i = 0; i < 200 && Volatile.Read(ref llamadas) == 0; i++) await Task.Delay(10);
                var seg = await PedirSenuelos(m, "copia.hacer", null);
                Check(!seg.Ok && seg.Codigo == ModuloCopia.CopiaEnCurso, "con una copia en marcha, otra se rechaza");
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("en_curso").GetBoolean(), "y el estado dice «en curso»");
                puerta.Set();
                Check((await primera).Item1 && llamadas == 1, "la primera termina bien y solo se copió una vez");
                Check(!(await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("en_curso").GetBoolean(), "después ya no está en curso");
            }

            // Destino ausente: no es un error, no copia, no escribe eventos
            {
                int llamadas = 0; bool hay = false;
                var w = new EscritorFalso();
                var m = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\copia", 3, null, w,
                    copiar: (c, t, ct) => { llamadas++; return new ResultadoDeCopia(true, null, new Instantanea("i", t, Array.Empty<EntradaDeCopia>(), Array.Empty<OmitidoEnCopia>(), false, null), 0, 0, 0, false, null); },
                    destinoDisponible: _ => hay);
                var h = await PedirSenuelos(m, "copia.hacer", null);
                Check(h.Ok && !h.R!.Value.GetProperty("exito").GetBoolean() && llamadas == 0 && w.Eventos.Count == 0, "destino ausente: dice que no está, no copia y no inventa un evento");
                var e = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(!e.GetProperty("destino_disponible").GetBoolean() && e.GetProperty("aviso").GetString()!.Contains("no está disponible"), "el estado lo cuenta");
                hay = true;
                Check((await PedirSenuelos(m, "copia.hacer", null)).R!.Value.GetProperty("exito").GetBoolean() && llamadas == 1, "al conectar el disco, copia");
            }

            // Fallo y copia sospechosa: eventos con su gravedad
            {
                var w = new EscritorFalso();
                var ahora = DateTimeOffset.Now;
                ResultadoDeCopia siguiente = new(false, "el disco está lleno", null, 0, 0, 0, false, null);
                var m = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, null, w,
                    copiar: (c, t, ct) => siguiente, destinoDisponible: _ => true, reloj: () => ahora);
                var h = await PedirSenuelos(m, "copia.hacer", null);
                Check(h.Ok && !h.R!.Value.GetProperty("exito").GetBoolean() && h.R.Value.GetProperty("error").GetString() == "el disco está lleno"
                      && w.Eventos.Last().Tipo == TipoEvento.CopiaFallida && w.Eventos.Last().Severidad == Severidad.Media, "una copia fallida: error a la vista y evento Media");
                ahora = ahora.AddMinutes(5);
                siguiente = new ResultadoDeCopia(true, null, new Instantanea("s", ahora, Array.Empty<EntradaDeCopia>(), Array.Empty<OmitidoEnCopia>(), true, "30 de 30 cambiaron"), 30, 0, 0, true, "no se borró");
                var h2 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h2.R!.Value.GetProperty("sospechosa").GetBoolean() && w.Eventos.Last().Tipo == TipoEvento.CopiaSospechosa && w.Eventos.Last().Severidad == Severidad.Alta
                      && w.Eventos.Last().Cuerpo.Contains("30 de 30"), "una copia sospechosa: evento Alta con el motivo");
            }

            // Copia automática: cada hora, desde el último intento, y solo con el destino conectado
            {
                int llamadas = 0; bool hay = false;
                var ahora = new DateTimeOffset(2026, 11, 10, 8, 0, 0, TimeSpan.Zero);
                var w = new EscritorFalso();
                var m = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, TimeSpan.FromHours(1), w,
                    copiar: (c, t, ct) => { llamadas++; return new ResultadoDeCopia(true, null, new Instantanea("i" + llamadas, t, Array.Empty<EntradaDeCopia>(), Array.Empty<OmitidoEnCopia>(), false, null), 0, 0, 0, false, null); },
                    destinoDisponible: _ => hay, reloj: () => ahora);
                await m.VueltaAsync(CancellationToken.None);
                Check(llamadas == 0, "automática: sin el disco conectado no intenta nada");
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("aviso").GetString()!.Contains("no está disponible"), "y lo dice en el estado");
                hay = true;
                await m.VueltaAsync(CancellationToken.None);
                Check(llamadas == 1, "en cuanto se conecta, copia");
                ahora = ahora.AddMinutes(30); await m.VueltaAsync(CancellationToken.None);
                Check(llamadas == 1, "a los 30 min todavía no toca");
                ahora = ahora.AddMinutes(31); await m.VueltaAsync(CancellationToken.None);
                Check(llamadas == 2, "a la hora, otra");
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("automatica_cada_horas").GetDouble() == 1, "el estado dice cada cuánto");
            }

            // Sin automática (cada = null) la vuelta no hace nada
            {
                int llamadas = 0;
                var m = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, null, new EscritorFalso(),
                    copiar: (c, t, ct) => { llamadas++; return new ResultadoDeCopia(true, null, null, 0, 0, 0, false, null); }, destinoDisponible: _ => true);
                await m.VueltaAsync(CancellationToken.None);
                Check(llamadas == 0, "sin «CadaHoras» solo se copia a mano");
            }

            // Sospecha de verdad, con disco real: todos los archivos cambian
            string r2 = Path.Combine(Path.GetTempPath(), "nexo-copia-svc2-" + Guid.NewGuid().ToString("N"));
            try
            {
                string d = Path.Combine(r2, "d"); Directory.CreateDirectory(d);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "x" + i);
                var w = new EscritorFalso();
                var ahora = DateTimeOffset.Now;
                var m = new ModuloCopia(() => (new[] { d }, Array.Empty<CarpetaSinSenuelo>()), Path.Combine(r2, "c"), 1, null, w, reloj: () => ahora);
                await PedirSenuelos(m, "copia.hacer", null);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "CIFRADO" + i);
                ahora = ahora.AddMinutes(5);
                var h = await PedirSenuelos(m, "copia.hacer", null);
                var e = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(h.R!.Value.GetProperty("sospechosa").GetBoolean() && e.GetProperty("versiones_en_destino").GetInt32() == 2 && w.Eventos.Last().Severidad == Severidad.Alta,
                      "con disco real: 25 archivos «cifrados» -> sospechosa, evento Alta y la versión buena sigue ahí (2 versiones aunque el tope es 1)");
                Check(e.GetProperty("sospechosas_guardadas").GetInt32() == 1, "el estado cuenta 1 copia sospechosa guardada");
                ahora = ahora.AddMinutes(5);
                await PedirSenuelos(m, "copia.hacer", null);
                var e3 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(!e3.GetProperty("ultimo").GetProperty("sospechosa").GetBoolean() && e3.GetProperty("sospechosas_guardadas").GetInt32() == 1 && e3.GetProperty("versiones_en_destino").GetInt32() == 3,
                      "una copia normal DESPUÉS no borra la sospechosa ni la buena (3 versiones, 1 sospechosa guardada): la alarma no se apaga sola");
                string idSospechosa = CopiaVersionada.Listar(Path.Combine(r2, "c"), out _).Single(v => v.Sospechosa).Id;
                Check(CopiaVersionada.DescartarSospecha(Path.Combine(r2, "c"), idSospechosa).Correcto, "la persona descarta la sospecha (como lo hace la ventana)");
                var e4 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(e4.GetProperty("sospechosas_guardadas").GetInt32() == 0, "el servicio se entera sin hacer otra copia: 0 sospechosas guardadas");
            }
            finally { try { Directory.Delete(r2, true); } catch { } }
        }

        /// <summary>El JSON REAL de ModuloCopia leído por el lector de la ventana: si cambia un nombre de un lado, esto cae.</summary>
        public static async Task ProbarCopiaContratoConLaVentana()
        {
            Console.WriteLine("Copia versionada: el JSON real del servicio lo lee la ventana");
            static Nexo.Ui.Desktop.Nucleo.RespuestaCruda Cruda(JsonElement e) => new(true, null, e);

            var ap = (await PedirSenuelos(new ModuloCopiaApagado(), "copia.estado", null)).R!.Value;
            var cap = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Estado(Cruda(ap));
            Check(cap.Valor is { Activo: false } && cap.Valor.Nota.Contains("apagada"), "apagada: la ventana lo lee como apagada, con la nota");

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-contrato-" + Guid.NewGuid().ToString("N"));
            try
            {
                string d = Path.Combine(raiz, "d"); Directory.CreateDirectory(d);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "x" + i);
                var ahora = DateTimeOffset.Now;
                var m = new ModuloCopia(() => (new[] { d }, new[] { new CarpetaSinSenuelo(@"C:\x\OneDrive\y", "carpeta de OneDrive") }), Path.Combine(raiz, "c"), 3, TimeSpan.FromHours(2), new EscritorFalso(), reloj: () => ahora);

                var antes = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Estado(Cruda((await PedirSenuelos(m, "copia.estado", null)).R!.Value));
                Check(antes.Valor is { Activo: true, DestinoDisponible: true, Ultimo: null, UltimaCorrecta: null, AutomaticaCadaHoras: 2, VersionesEnDestino: 0, VersionesAConservar: 3 }
                      && antes.Valor.SinCopia.Count == 1 && antes.Valor.Carpetas.Count == 1, "antes de copiar: se lee todo, con «último» nulo", antes.Error);

                var h = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Hacer(Cruda((await PedirSenuelos(m, "copia.hacer", null)).R!.Value));
                Check(h.Valor is { Exito: true, Archivos: 25, Nuevos: 25, Sospechosa: false }, "copia.hacer: 25 archivos nuevos", h.Error);
                var tras = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Estado(Cruda((await PedirSenuelos(m, "copia.estado", null)).R!.Value));
                Check(tras.Valor is { VersionesEnDestino: 1, UltimaCorrecta: not null, Ultimo.Correcto: true, Ultimo.Archivos: 25, EnCurso: false }, "tras copiar: estado con el último resultado", tras.Error);

                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "CIFRADO" + i);
                ahora = ahora.AddMinutes(5);
                var hs = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Hacer(Cruda((await PedirSenuelos(m, "copia.hacer", null)).R!.Value));
                Check(hs.Valor is { Exito: true, Sospechosa: true } && hs.Valor.MotivoSospecha!.Contains("25 de 25"), "sospechosa con su motivo", hs.Error);
                var es = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Estado(Cruda((await PedirSenuelos(m, "copia.estado", null)).R!.Value));
                Check(es.Valor is { Ultimo.Sospechosa: true, Ultimo.PodaSuspendida: true, VersionesEnDestino: 2 } && es.Valor.Ultimo.MotivoPoda!.Contains("No se borró"), "estado sospechoso: poda suspendida y versión buena conservada", es.Error);

                var fallo = new ModuloCopia(() => (new[] { d }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, null, new EscritorFalso(),
                    copiar: (c, t, ct) => new ResultadoDeCopia(false, "el disco está lleno", null, 0, 0, 0, false, null), destinoDisponible: _ => true);
                var hf = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Hacer(Cruda((await PedirSenuelos(fallo, "copia.hacer", null)).R!.Value));
                Check(hf.Valor is { Exito: false } && hf.Valor.Error == "el disco está lleno", "copia fallida: la ventana lee el motivo");
                var ausente = new ModuloCopia(() => (new[] { d }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, null, new EscritorFalso(), destinoDisponible: _ => false);
                var ha = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Hacer(Cruda((await PedirSenuelos(ausente, "copia.hacer", null)).R!.Value));
                Check(ha.Valor is { Exito: false } && ha.Valor.Error!.Contains("no está disponible"), "disco ausente: la ventana lo lee como «no se hizo»");
                var ea = Nexo.Ui.Desktop.Nucleo.LectorDeCopia.Estado(Cruda((await PedirSenuelos(ausente, "copia.estado", null)).R!.Value));
                Check(ea.Valor is { Activo: true, DestinoDisponible: false, VersionesEnDestino: 0 }, "estado con el disco ausente");
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }
    }
}
