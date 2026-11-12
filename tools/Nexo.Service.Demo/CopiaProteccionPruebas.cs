using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        /// <summary>Protección de la carpeta de copias y «copia.descartar» (la ventana ya no puede escribir en esa carpeta).</summary>
        public static async Task ProbarCopiaProteccionYDescarte()
        {
            Console.WriteLine("Copia versionada: protección de la carpeta y copia.descartar");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-svc3-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "docs"), destino = Path.Combine(raiz, "copia");
            Directory.CreateDirectory(docs);
            for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(docs, "f" + i + ".txt"), "contenido " + i);
            try
            {
                var ahora = new DateTimeOffset(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);
                var llamados = new List<string>();
                string? respuesta = null;
                var m = new ModuloCopia(() => (new[] { docs }, Array.Empty<CarpetaSinSenuelo>()), destino, 5, null, new EscritorFalso(), reloj: () => ahora,
                                        proteger: ruta => { llamados.Add(ruta); return respuesta; });

                // ---- el gancho llega a la copia y su aviso a la respuesta y al estado
                var h1 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h1.Ok && h1.R!.Value.GetProperty("exito").GetBoolean() && llamados.Count == 1 && llamados[0].EndsWith(CopiaVersionada.CarpetaDeCopias),
                      "copia.hacer protege la carpeta de Nexo del destino", string.Join("|", llamados));
                Check(h1.R!.Value.GetProperty("aviso_proteccion").ValueKind == JsonValueKind.Null, "protegida: copia.hacer no trae aviso");
                var e1 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(e1.GetProperty("aviso_proteccion").ValueKind == JsonValueKind.Null, "protegida: el estado no trae aviso");

                ahora = ahora.AddMinutes(2); respuesta = "El destino usa exFAT, que no admite permisos";
                var h2 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h2.Ok && h2.R!.Value.GetProperty("exito").GetBoolean(), "si no se puede proteger, la copia se hace igual");
                Check(h2.R!.Value.GetProperty("aviso_proteccion").GetString() == respuesta, "pero copia.hacer lleva el motivo");
                var e2 = (await PedirSenuelos(m, "copia.estado", null)).R!.Value;
                Check(e2.GetProperty("aviso_proteccion").GetString() == respuesta,
                      "y el estado lo conserva, para que la ventana lo muestre aunque no se mire al hacer la copia");
                Check(!e2.GetProperty("nota").GetString()!.Contains("no protege el destino de un ransomware que pueda escribir"), "la nota ya no dice que no hay protección alguna");

                ahora = ahora.AddMinutes(2); respuesta = null;
                await PedirSenuelos(m, "copia.hacer", null);
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("aviso_proteccion").ValueKind == JsonValueKind.Null, "cuando se arregla (p. ej. disco NTFS), el aviso desaparece");

                // ---- copia.descartar: una sospechosa de verdad (25 archivos cambian de golpe)
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(docs, "f" + i + ".txt"), "CIFRADO " + i);
                ahora = ahora.AddMinutes(2);
                var h3 = await PedirSenuelos(m, "copia.hacer", null);
                Check(h3.Ok && h3.R!.Value.GetProperty("sospechosa").GetBoolean(), "preparación: la copia con todo cambiado sale SOSPECHOSA");
                string idSosp = CopiaVersionada.Listar(destino, out _).Single(i => i.Sospechosa).Id;
                string idBuena = CopiaVersionada.Listar(destino, out _).First(i => !i.Sospechosa).Id;
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("sospechosas_guardadas").GetInt32() == 1, "el estado cuenta 1 sospechosa");

                Check(!(await PedirSenuelos(m, "copia.descartar", null)).Ok, "sin id: error de parámetros");
                Check(!(await PedirSenuelos(m, "copia.descartar", new { id = "" })).Ok, "id vacío: error de parámetros");
                Check(!(await PedirSenuelos(m, "copia.descartar", new { id = @"..\..\Windows\x" })).Ok, "un id con barras o puntos (intento de salirse de la carpeta): error de parámetros");
                Check(!(await PedirSenuelos(m, "copia.descartar", new { id = new string('a', 41) })).Ok, "un id larguísimo: error de parámetros");
                Check(!(await PedirSenuelos(m, "copia.descartar", new { id = 5 })).Ok, "un id que no es texto: error de parámetros");
                Check(!(await PedirSenuelos(m, "copia.descartar", new { id = idSosp, destino = @"C:\Windows" })).Ok == false, "un campo «destino» de más se ignora: no existe forma de apuntar el servicio a otra ruta");
                // (la línea anterior ya descartó la sospechosa de verdad: se vuelve a crear abajo para el resto de pruebas)
                Check(!CopiaVersionada.Listar(destino, out _).Any(i => i.Sospechosa), "…y ese descarte fue sobre el destino configurado, no el que mandó el cliente");

                var noExiste = await PedirSenuelos(m, "copia.descartar", new { id = "20200101T000000Z" });
                Check(noExiste.Ok && !noExiste.R!.Value.GetProperty("exito").GetBoolean() && noExiste.R.Value.GetProperty("error").GetString()!.Contains("No existe"), "un id que no existe: exito=false con el motivo");
                var noSosp = await PedirSenuelos(m, "copia.descartar", new { id = idBuena });
                Check(noSosp.Ok && !noSosp.R!.Value.GetProperty("exito").GetBoolean() && noSosp.R.Value.GetProperty("error").GetString()!.Contains("no está marcada"), "una copia que no era sospechosa: exito=false, no toca nada");

                // ---- de nuevo una sospechosa, ahora con el flujo normal
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(docs, "f" + i + ".txt"), "OTRA VEZ " + i);
                ahora = ahora.AddMinutes(2);
                await PedirSenuelos(m, "copia.hacer", null);
                string idSosp2 = CopiaVersionada.Listar(destino, out _).Single(i => i.Sospechosa).Id;
                var d = await PedirSenuelos(m, "copia.descartar", new { id = idSosp2 });
                Check(d.Ok && d.R!.Value.GetProperty("exito").GetBoolean() && d.R.Value.GetProperty("error").ValueKind == JsonValueKind.Null, "copia.descartar da por buena la sospechosa");
                Check(!CopiaVersionada.Listar(destino, out _).Any(i => i.Sospechosa) && CopiaVersionada.Verificar(destino).Correcto, "en el disco ya no está marcada y el contenido sigue intacto");
                Check((await PedirSenuelos(m, "copia.estado", null)).R!.Value.GetProperty("sospechosas_guardadas").GetInt32() == 0, "el estado ya cuenta 0 sospechosas (no espera a la próxima copia)");

                // ---- no se mete en medio de una copia en curso
                var puerta = new System.Threading.ManualResetEventSlim(false);
                var lenta = new ModuloCopia(() => (new[] { docs }, Array.Empty<CarpetaSinSenuelo>()), Path.Combine(raiz, "lenta"), 3, null, new EscritorFalso(), reloj: () => ahora,
                                            copiar: (c, t, ct) => { puerta.Wait(); return CopiaVersionada.Copiar(c, t, ct); }, proteger: _ => null);
                Task<(bool, int, JsonElement?)> primera = PedirSenuelos(lenta, "copia.hacer", null);
                await Task.Delay(300);
                var enMedio = await PedirSenuelos(lenta, "copia.descartar", new { id = "20261112T120000Z" });
                Check(!enMedio.Ok && enMedio.Codigo == ModuloCopia.CopiaEnCurso, "con una copia en curso, copia.descartar espera: error «copia en curso»");
                puerta.Set(); await primera;
                await lenta.DisposeAsync();
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }
    }
}
