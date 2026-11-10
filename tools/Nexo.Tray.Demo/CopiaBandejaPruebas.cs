using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static partial class Program
    {
        /// <summary>La copia de seguridad en la bandeja, con el JSON REAL de ModuloCopia: rojo si hay una sospechosa guardada, un globo por cada nueva.</summary>
        private static async Task ProbarCopiaEnLaBandeja()
        {
            Console.WriteLine("Copia de seguridad en la bandeja (con el JSON real del servicio)");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-tray-copia-" + Guid.NewGuid().ToString("N"));
            try
            {
                string d = Path.Combine(raiz, "d"); Directory.CreateDirectory(d);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "bueno " + i);
                var ahora = DateTimeOffset.Now;
                var modulo = new ModuloCopia(() => (new[] { d }, Array.Empty<CarpetaSinSenuelo>()), Path.Combine(raiz, "c"), 1, null, new VaultNulo(), reloj: () => ahora);
                async Task<JsonElement> Estado() => JsonSerializer.SerializeToElement(await modulo.ManejarAsync("copia.estado", null, CancellationToken.None));
                async Task Copiar() { await modulo.ManejarAsync("copia.hacer", null, CancellationToken.None); ahora = ahora.AddMinutes(5); }

                Check(ConsultorDelServicio.LeerCopia(JsonSerializer.SerializeToElement(await new ModuloCopiaApagado().ManejarAsync("copia.estado", null, CancellationToken.None))) == (0, false), "apagada: nada que vigilar");
                Check(ConsultorDelServicio.LeerCopia(await Estado()) == (0, false), "activa y sin copias todavía: (0, false)");

                var m = new ModeloDeBandeja();
                await Copiar();
                var (s0, f0) = ConsultorDelServicio.LeerCopia(await Estado());
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = s0, CopiaFallida = f0 });
                Check(s0 == 0 && !f0 && m.Estado == EstadoDeBandeja.Normal && !m.CopiaSospechosaNueva, "una copia buena: la bandeja sigue «todo en orden»");

                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "CIFRADO " + i);
                await Copiar();
                var (s1, f1) = ConsultorDelServicio.LeerCopia(await Estado());
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = s1, CopiaFallida = f1 });
                Check(s1 == 1 && m.Estado == EstadoDeBandeja.Alerta && m.Texto == "Nexo: copia de seguridad sospechosa" && m.CopiaSospechosaNueva, "copia sospechosa: ROJO y globo nuevo");
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = s1 });
                Check(!m.CopiaSospechosaNueva && m.Estado == EstadoDeBandeja.Alerta, "en la siguiente consulta no se avisa otra vez, pero sigue en rojo");

                // La copia siguiente se compara con la cifrada y sale «normal»: la alarma NO se apaga sola
                await Copiar();
                var (s2, _) = ConsultorDelServicio.LeerCopia(await Estado());
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = s2 });
                Check(s2 == 1 && m.Estado == EstadoDeBandeja.Alerta && !m.CopiaSospechosaNueva, "una copia «normal» después NO apaga la alarma (la sospechosa sigue guardada)");

                // Sin conexión: no se repite el globo al volver
                m.Actualizar(InstantaneaDelServicio.SinConexion("el servicio no está en marcha"));
                Check(m.Estado == EstadoDeBandeja.Desconectado && !m.CopiaSospechosaNueva, "sin conexión: desconectado");
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = 1 });
                Check(!m.CopiaSospechosaNueva, "y al volver no se repite el globo de la misma");
                m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = 2 });
                Check(m.CopiaSospechosaNueva && m.Texto == "Nexo: 2 copias sospechosas", "una segunda sospechosa SÍ avisa");

                // Prioridades: un señuelo tocado manda sobre la copia sospechosa; la copia sospechosa, sobre las detecciones
                var tocado = new SenueloTocadoVista(@"C:\Users\ana\Documents\!a.docx", "modificado", "cambió", "Alta", ahora);
                var m2 = new ModeloDeBandeja();
                m2.Actualizar(Sana(new[] { tocado }) with { CopiaSospechosas = 1 });
                Check(m2.Texto.Contains("señuelo"), "señuelo tocado + copia sospechosa: manda el señuelo");
                var m3 = new ModeloDeBandeja();
                m3.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaSospechosas = 1, Detecciones = new[] { new DeteccionVista(@"C:\x\malo.exe", "Eicar", 10, "aa") } });
                Check(m3.Texto == "Nexo: copia de seguridad sospechosa", "copia sospechosa + detección: manda la copia");

                // Copia fallida: amarillo, no rojo ni verde
                var m4 = new ModeloDeBandeja();
                m4.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { CopiaFallida = true });
                Check(m4.Estado == EstadoDeBandeja.Atencion && m4.Texto == "Nexo: la última copia de seguridad falló", "última copia fallida: amarillo");
                var fallo = new ModuloCopia(() => (new[] { d }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, null, new VaultNulo(),
                    copiar: (c, t, ct) => new ResultadoDeCopia(false, "disco lleno", null, 0, 0, 0, false, null), destinoDisponible: _ => true);
                await fallo.ManejarAsync("copia.hacer", null, CancellationToken.None);
                Check(ConsultorDelServicio.LeerCopia(JsonSerializer.SerializeToElement(await fallo.ManejarAsync("copia.estado", null, CancellationToken.None))) == (0, true), "el JSON real de una copia fallida se lee como fallida");

                // Formas no reconocidas: no se inventa nada
                Check(ConsultorDelServicio.LeerCopia(JsonDocument.Parse("{\"activo\":true,\"ultimo\":{\"x\":1}}").RootElement) == (0, false), "una forma que no se entiende no se toma por sospechosa");
                Check(ConsultorDelServicio.LeerCopia(JsonDocument.Parse("{\"nada\":1}").RootElement) == (0, false), "ni por nada: (0, false)");

                // Textos
                (string t1, string x1) = AccionesDelServicio.AvisoDeCopia(1);
                (string t2, string x2) = AccionesDelServicio.AvisoDeCopia(3);
                Check(t1.Contains("sospechosa") && x1.Contains("cifrado") && x2.StartsWith("3 copias"), "el globo explica y cuenta");
                string txt = AccionesDelServicio.TextoDeCopiaSospechosa(1);
                Check(txt.Contains("No borres") && txt.Contains("«Copias»") && txt.Contains("desconecta") && txt.Contains("no puede saber"), "el diálogo dice qué hacer, qué NO hacer y sus límites");
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }
    }
}
