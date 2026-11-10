using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Autocompletado;
using Nexo.Modules.Identity.Boveda;

namespace Nexo.Identity.Demo
{
    internal static partial class Program
    {
        private static byte[] Trama(byte[] json)
        {
            byte[] b = new byte[json.Length + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)json.Length);
            json.CopyTo(b, 4);
            return b;
        }

        private static byte[] Tramas(params object[] mensajes)
            => mensajes.SelectMany(m => Trama(JsonSerializer.SerializeToUtf8Bytes(m))).ToArray();

        private static List<JsonElement> LeerRespuestas(byte[] salida)
        {
            var l = new List<JsonElement>();
            var ms = new MemoryStream(salida);
            while (MensajeNativo.LeerAsync(ms, MensajeNativo.MaxSalida, default).GetAwaiter().GetResult() is { } m) l.Add(JsonDocument.Parse(m).RootElement.Clone());
            return l;
        }

        private static string NombreDePrueba() => "nexo-prueba-autocompletado-" + Guid.NewGuid().ToString("N")[..12];

        private static async Task ProbarCanal()
        {
            Console.WriteLine("Autocompletado: el canal host nativo ↔ ventana (pipes reales)");

            string a = CanalDeAutocompletado.NombreDePipe("PC\\ana"), b = CanalDeAutocompletado.NombreDePipe("PC\\beto");
            Check(a == CanalDeAutocompletado.NombreDePipe("pc\\ANA ") && a != b && !a.Contains('\\') && a.StartsWith("nexo-autocompletado-"),
                "el nombre del pipe es fijo por usuario, distinto entre usuarios y sin barras", a);

            // De punta a punta con el puente real: el relevo lee del «navegador» (un MemoryStream) y escribe la respuesta.
            var gh = Ent("github.com", "ana", "clave-gh");
            var emp = new EmparejadosEnMemoria();
            var puente = new PuenteDeAutocompletado(() => new[] { gh }, emp, (n, c, ct) => Task.FromResult(true));
            string nombre = NombreDePrueba();
            await using (var srv = new ServidorDeAutocompletado(nombre, puente.AtenderAsync))
            {
                srv.Iniciar();
                string k = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                var salida = new MemoryStream();
                int codigo = await new RelevoNativo(nombre).EjecutarAsync(new MemoryStream(Tramas(
                    new { tipo = "estado", navegador = "brave", clave = k },
                    new { tipo = "emparejar", navegador = "brave", clave = k },
                    new { tipo = "buscar", navegador = "brave", clave = k, url = "https://github.com/login" },
                    new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/login", id = gh.Id })), salida);
                List<JsonElement> r = LeerRespuestas(salida.ToArray());
                Check(codigo == 0 && r.Count == 4, "cuatro mensajes del navegador, cuatro respuestas, y sale con 0 al cerrar la entrada", codigo + " / " + r.Count);
                Check(r.Count == 4 && r[0].GetProperty("estado").GetString() == "ok" && !r[0].GetProperty("emparejado").GetBoolean()
                      && r[1].GetProperty("emparejado").GetBoolean() && r[2].GetProperty("entradas").GetArrayLength() == 1
                      && r[3].GetProperty("contrasena").GetString() == "clave-gh",
                    "a través del pipe: estado → emparejar → buscar → rellenar da la contraseña de github.com");
                Check(srv.Atendidas == 4, "el servidor contó las 4", srv.Atendidas.ToString());

                // Diez a la vez (más que MaxConexiones): todas contestadas, ninguna se pierde.
                var relevo = new RelevoNativo(nombre);
                byte[][] rs = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
                    relevo.ReenviarAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "estado", navegador = "edge" }))));
                Check(rs.All(x => JsonDocument.Parse(x).RootElement.GetProperty("estado").GetString() == "ok"), "diez peticiones a la vez: todas contestadas");

                // Un cliente que manda una trama mala: el servidor lo cierra y sigue atendiendo a los demás.
                using (var malo = new NamedPipeClientStream(".", nombre, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
                {
                    await malo.ConnectAsync(2000);
                    await malo.WriteAsync(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F });
                    await malo.FlushAsync();
                    int n = await malo.ReadAsync(new byte[4]).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
                    Check(n == 0, "trama con longitud enorme: el servidor cierra esa conexión sin contestar");
                }
                byte[] otra = await relevo.ReenviarAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "estado", navegador = "edge" }));
                Check(JsonDocument.Parse(otra).RootElement.GetProperty("estado").GetString() == "ok", "y el siguiente se atiende normal");

                bool dos = false;
                try { srv.Iniciar(); } catch (InvalidOperationException) { dos = true; }
                Check(dos, "iniciar dos veces: error");
            }

            // Después de cerrar el servidor (la ventana se cerró): «sin_nexo».
            byte[] tras = await new RelevoNativo(nombre, conectar: TimeSpan.FromMilliseconds(300)).ReenviarAsync(Encoding.UTF8.GetBytes("{}"));
            Check(JsonDocument.Parse(tras).RootElement.GetProperty("estado").GetString() == "sin_nexo", "ventana cerrada: el host contesta «sin_nexo» él mismo");

            // Sin servidor nunca: «sin_nexo» en el plazo de conexión, no colgado.
            var sw = Stopwatch.StartNew();
            byte[] sin = await new RelevoNativo(NombreDePrueba(), conectar: TimeSpan.FromMilliseconds(300)).ReenviarAsync(Encoding.UTF8.GetBytes("{}"));
            JsonElement sinJ = JsonDocument.Parse(sin).RootElement;
            Check(sinJ.GetProperty("estado").GetString() == "sin_nexo" && sinJ.GetProperty("motivo").GetString()!.Contains("Nexo no está abierto")
                  && sw.Elapsed < TimeSpan.FromSeconds(5), "Nexo cerrado: «sin_nexo» con un motivo en español, sin colgarse", sw.ElapsedMilliseconds + " ms");

            // Lo que manda el navegador mal formado: el relevo deja de leer (código 2) y no escribe nada.
            foreach ((string que, byte[] bytes) in new[]
            {
                ("longitud 0", new byte[] { 0, 0, 0, 0 }),
                ("longitud mayor que 64 KB", BitConverter.GetBytes(MensajeNativo.MaxEntrada + 1)),
                ("cabecera cortada", new byte[] { 5, 0 }),
                ("cuerpo cortado", new byte[] { 10, 0, 0, 0, (byte)'{' }),
            })
            {
                var o = new MemoryStream();
                int c = await new RelevoNativo(NombreDePrueba(), conectar: TimeSpan.FromMilliseconds(100)).EjecutarAsync(new MemoryStream(bytes), o);
                Check(c == 2 && o.Length == 0, "del navegador, " + que + ": el host para (2) sin escribir nada", c + " / " + o.Length);
            }
            var vacia = new MemoryStream();
            Check(await new RelevoNativo(NombreDePrueba()).EjecutarAsync(new MemoryStream(), vacia) == 0 && vacia.Length == 0, "entrada vacía (el navegador cerró): sale con 0");

            // Servidores que contestan mal.
            async Task<JsonElement> ConServidor(Func<byte[], CancellationToken, Task<byte[]>> atender, TimeSpan? porPeticion = null, TimeSpan? respuestaRelevo = null)
            {
                string n = NombreDePrueba();
                await using var s = new ServidorDeAutocompletado(n, atender, porPeticion);
                s.Iniciar();
                byte[] r = await new RelevoNativo(n, respuesta: respuestaRelevo).ReenviarAsync(Encoding.UTF8.GetBytes("{\"tipo\":\"estado\"}"));
                // Si el host dejara pasar algo que no es JSON, eso es un FALLO de la prueba, no una excepción que tumba el arnés.
                try { return JsonDocument.Parse(r).RootElement.Clone(); }
                catch (JsonException) { return JsonDocument.Parse("{\"estado\":\"llegó algo que no es JSON al navegador\"}").RootElement.Clone(); }
            }
            static string Motivo(JsonElement e) => e.GetProperty("estado").GetString() + ": " + (e.TryGetProperty("motivo", out JsonElement m) ? m.GetString() : "");

            JsonElement j = await ConServidor((p, ct) => Task.FromResult(Encoding.UTF8.GetBytes("esto no es json")));
            Check(Motivo(j) == "error: Nexo contestó algo que no se entiende", "la ventana contesta algo que no es JSON: el host no lo pasa al navegador", Motivo(j));
            j = await ConServidor((p, ct) => Task.FromResult(Encoding.UTF8.GetBytes("[1,2]")));
            Check(Motivo(j).StartsWith("error"), "un JSON que no es objeto: tampoco", Motivo(j));
            j = await ConServidor((p, ct) => Task.FromResult(new byte[MensajeNativo.MaxSalida + 10]));
            Check(Motivo(j) == "error: respuesta no válida", "la ventana intenta mandar más de 1 MB: el servidor lo cambia por un error", Motivo(j));
            j = await ConServidor(async (p, ct) => { await Task.Delay(Timeout.Infinite, ct); return Array.Empty<byte>(); }, porPeticion: TimeSpan.FromMilliseconds(300));
            Check(Motivo(j) == "error: Nexo no contestó a tiempo", "la ventana tarda más que su tope: el servidor contesta «no contestó a tiempo»", Motivo(j));
            // El servidor aguantaría 10 minutos: si el host no tuviera su propio tope, esto tardaría eso.
            var reloj = Stopwatch.StartNew();
            try
            {
                j = await ConServidor(async (p, ct) => { await Task.Delay(Timeout.Infinite, ct); return Array.Empty<byte>(); },
                                      porPeticion: TimeSpan.FromMinutes(10), respuestaRelevo: TimeSpan.FromMilliseconds(300)).WaitAsync(TimeSpan.FromSeconds(20));
            }
            catch (TimeoutException) { j = JsonDocument.Parse("{\"estado\":\"colgado\"}").RootElement.Clone(); }
            Check(Motivo(j) == "error: Nexo no contestó a tiempo" && reloj.Elapsed < TimeSpan.FromSeconds(10),
                "y si el que se cansa es el host, dice lo mismo en SU plazo (no se cuelga esperando a la ventana)", Motivo(j) + " / " + reloj.ElapsedMilliseconds + " ms");
            string grande = "{\"estado\":\"ok\",\"relleno\":\"" + new string('x', 200_000) + "\"}";
            j = await ConServidor((p, ct) => Task.FromResult(Encoding.UTF8.GetBytes(grande)));
            Check(Motivo(j) == "ok: " && j.GetProperty("relleno").GetString()!.Length == 200_000, "una respuesta de 200 KB (más que el tope de entrada, menos que 1 MB) pasa entera");
            j = await ConServidor((p, ct) => Task.FromResult(p));
            Check(j.GetProperty("tipo").GetString() == "estado", "el host reenvía el mensaje tal cual (la ventana recibe lo que mandó la extensión)");

            // Un cliente que conecta y no habla se cierra pasado el tope de inactividad.
            string ni = NombreDePrueba();
            await using (var s = new ServidorDeAutocompletado(ni, (p, ct) => Task.FromResult(p), inactivo: TimeSpan.FromMilliseconds(300)))
            {
                s.Iniciar();
                using var mudo = new NamedPipeClientStream(".", ni, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await mudo.ConnectAsync(2000);
                int n;
                try { n = await mudo.ReadAsync(new byte[4]).AsTask().WaitAsync(TimeSpan.FromSeconds(5)); } catch (TimeoutException) { n = -1; }
                Check(n == 0, "quien conecta y no manda nada: se le cierra (no ocupa un hueco para siempre)", n.ToString());
            }

            bool malNombre = false;
            try { _ = new ServidorDeAutocompletado("a\\b", (p, ct) => Task.FromResult(p)); } catch (ArgumentException) { malNombre = true; }
            Check(malNombre, "nombre de pipe con barra: rechazado");
        }

        private sealed class RegistroEnMemoria : IRegistroDeUsuario
        {
            public readonly Dictionary<string, string> Valores = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> Prohibidas = new(StringComparer.OrdinalIgnoreCase);
            public string? LeerValor(string s) => Valores.TryGetValue(s, out string? v) ? v : null;
            public void EscribirValor(string s, string v) { if (Prohibidas.Contains(s)) throw new UnauthorizedAccessException(); Valores[s] = v; }
            public bool BorrarClave(string s) => Valores.Remove(s);
        }

        private static void ProbarInstaladorDeHost(string dir)
        {
            Console.WriteLine("Autocompletado: registrar el host para Brave, Chrome y Edge");
            string id = InstaladorDeHostNativo.IdDeLaExtension;
            Check(InstaladorDeHostNativo.IdDesdeClave(InstaladorDeHostNativo.ClavePublicaDeLaExtension) == id, "el ID fijo sale de la clave pública (a–p, 32 letras)", id);
            using (RSA rsa = RSA.Create(2048))
            {
                string otraClave = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
                Check(InstaladorDeHostNativo.IdDesdeClave(otraClave) != id, "otra clave da otro ID");
            }

            string exe = Path.Combine(dir, "host", "nexo-autocompletar.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(exe)!);
            File.WriteAllText(exe, "falso");
            JsonElement m = JsonDocument.Parse(InstaladorDeHostNativo.Manifiesto(exe, new[] { id, id })).RootElement;
            Check(m.GetProperty("name").GetString() == "com.nexo.autocompletado" && m.GetProperty("type").GetString() == "stdio" && m.GetProperty("path").GetString() == exe,
                "manifiesto: nombre, tipo stdio y ruta absoluta del programa");
            Check(m.GetProperty("allowed_origins").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "chrome-extension://" + id + "/" }),
                "manifiesto: autoriza SOLO la extensión de Nexo (una vez, sin comodines)");
            foreach ((string que, Action a) in new (string, Action)[]
            {
                ("con ruta relativa", () => InstaladorDeHostNativo.Manifiesto("nexo-autocompletar.exe", new[] { id })),
                ("con ID con comodín", () => InstaladorDeHostNativo.Manifiesto(exe, new[] { "*" })),
                ("con ID con mayúsculas", () => InstaladorDeHostNativo.Manifiesto(exe, new[] { id.ToUpperInvariant() })),
                ("con ID de 31 letras", () => InstaladorDeHostNativo.Manifiesto(exe, new[] { id[..31] })),
                ("con ID con letras fuera de a–p", () => InstaladorDeHostNativo.Manifiesto(exe, new[] { new string('z', 32) })),
                ("sin IDs", () => InstaladorDeHostNativo.Manifiesto(exe, Array.Empty<string>())),
            })
            {
                bool lanzo = false;
                try { a(); } catch (ArgumentException) { lanzo = true; }
                Check(lanzo, "manifiesto " + que + ": rechazado");
            }

            Check(InstaladorDeHostNativo.EsOrigenDeExtension("chrome-extension://" + id + "/"), "origen bien formado: sí");
            Check(!InstaladorDeHostNativo.EsOrigenDeExtension("chrome-extension://" + id) && !InstaladorDeHostNativo.EsOrigenDeExtension("chrome-extension://" + id + "/x/")
                  && !InstaladorDeHostNativo.EsOrigenDeExtension("https://" + id + "/") && !InstaladorDeHostNativo.EsOrigenDeExtension(null)
                  && !InstaladorDeHostNativo.EsOrigenDeExtension("chrome-extension://" + id.ToUpperInvariant() + "/"), "origen sin barra final, con ruta, https, nulo o en mayúsculas: no");

            var reg = new RegistroEnMemoria();
            string man = Path.Combine(dir, "local", "Nexo", "autocompletado", "com.nexo.autocompletado.json");
            IReadOnlyList<string> p = InstaladorDeHostNativo.Instalar(reg, man, exe, new[] { id });
            Check(p.Count == 0 && File.Exists(man), "instalar: escribe el manifiesto, sin problemas", string.Join("; ", p));
            Check(reg.LeerValor(@"Software\Google\Chrome\NativeMessagingHosts\com.nexo.autocompletado") == man
                  && reg.LeerValor(@"Software\Microsoft\Edge\NativeMessagingHosts\com.nexo.autocompletado") == man && reg.Valores.Count == 2,
                "instalar: la clave de Chrome (la lee Brave) y la de Edge apuntan al manifiesto, y nada más");
            Check(InstaladorDeHostNativo.Revisar(reg).All(e => e.Situacion == SituacionDelHost.Listo), "revisar: los dos «listo»");
            Check(!Directory.GetFiles(Path.GetDirectoryName(man)!).Any(f => f.EndsWith(".tmp")), "no quedan temporales");

            // Revisar con dientes: cada forma de estar roto se nombra.
            SituacionDelHost Brave() => InstaladorDeHostNativo.Revisar(reg)[0].Situacion;
            Check(InstaladorDeHostNativo.Revisar(reg, new string('a', 32)).All(e => e.Situacion == SituacionDelHost.NoAutorizaLaExtension), "otro ID de extensión: «no la autoriza»");
            File.Delete(exe);
            Check(Brave() == SituacionDelHost.ProgramaNoExiste, "el programa ya no está: «el programa no existe», no «listo»");
            File.WriteAllText(exe, "falso");
            File.WriteAllText(man, "{ roto");
            Check(Brave() == SituacionDelHost.ManifiestoIlegible, "manifiesto roto: «ilegible»");
            File.WriteAllText(man, "{\"name\":\"com.otro.programa\",\"type\":\"stdio\",\"path\":\"" + exe.Replace("\\", "\\\\") + "\",\"allowed_origins\":[\"chrome-extension://" + id + "/\"]}");
            Check(Brave() == SituacionDelHost.ManifiestoIlegible, "manifiesto de otro programa: no se da por bueno");
            File.WriteAllText(man, "[]");
            Check(Brave() == SituacionDelHost.ManifiestoIlegible, "manifiesto que no es un objeto: «ilegible»");
            File.Delete(man);
            Check(Brave() == SituacionDelHost.ManifiestoNoExiste, "manifiesto borrado: «no existe»");
            Check(InstaladorDeHostNativo.Revisar(new RegistroEnMemoria()).All(e => e.Situacion == SituacionDelHost.NoRegistrado), "registro vacío: «no registrado»");

            // Desinstalar: solo lo nuestro.
            InstaladorDeHostNativo.Instalar(reg, man, exe, new[] { id });
            string ajeno = Path.Combine(dir, "otro.json");
            reg.Valores[InstaladorDeHostNativo.Navegadores[1].Subclave] = ajeno;
            IReadOnlyList<string> d = InstaladorDeHostNativo.Desinstalar(reg, man);
            Check(reg.LeerValor(InstaladorDeHostNativo.Navegadores[0].Subclave) is null && reg.LeerValor(InstaladorDeHostNativo.Navegadores[1].Subclave) == ajeno,
                "desinstalar: quita la clave que apunta a nuestro manifiesto y deja la que apunta a otro", string.Join("; ", d));
            Check(d.Any(l => l.Contains("no se toca")) && !File.Exists(man), "y lo dice, y borra nuestro manifiesto");
            reg.Valores.Clear();
            Check(InstaladorDeHostNativo.Desinstalar(reg, man).Count(l => l.Contains("no estaba registrado")) == 2, "desinstalar sin nada instalado: «no estaba registrado», sin errores");
            InstaladorDeHostNativo.Instalar(reg, man, exe, new[] { id });
            Check(InstaladorDeHostNativo.Desinstalar(reg, man.ToUpperInvariant()).Count(l => l.EndsWith("quitado")) == (OperatingSystem.IsWindows() ? 2 : 0),
                "la ruta se compara como la compara Windows (sin distinguir mayúsculas)");

            // Fallos al instalar.
            string bloqueo = Path.Combine(dir, "soy-un-archivo");
            File.WriteAllText(bloqueo, "x");
            var reg2 = new RegistroEnMemoria();
            p = InstaladorDeHostNativo.Instalar(reg2, Path.Combine(bloqueo, "m.json"), exe, new[] { id });
            Check(p.Count == 1 && p[0].Contains("manifiesto") && reg2.Valores.Count == 0, "no se puede escribir el manifiesto: se dice y NO se registra nada", string.Join("; ", p));
            var reg3 = new RegistroEnMemoria { Prohibidas = { InstaladorDeHostNativo.Navegadores[1].Subclave } };
            p = InstaladorDeHostNativo.Instalar(reg3, man, exe, new[] { id });
            Check(p.Count == 1 && p[0].StartsWith("Edge") && reg3.LeerValor(InstaladorDeHostNativo.Navegadores[0].Subclave) == man,
                "el registro de Edge falla: se dice, y Brave/Chrome queda registrado igual", string.Join("; ", p));
            bool rel = false;
            try { InstaladorDeHostNativo.Instalar(reg2, "m.json", exe, new[] { id }); } catch (ArgumentException) { rel = true; }
            Check(rel, "manifiesto en ruta relativa: rechazado");
        }
    }
}
