using System;
using System.Collections.Generic;
using System.IO;
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
        private sealed class EmparejadosEnMemoria : INavegadoresEmparejados
        {
            public readonly Dictionary<string, byte[]> Claves = new();
            public bool Autorizado(string n, byte[] c) => Claves.TryGetValue(n, out byte[]? k) && k.SequenceEqual(c);
            public string? Guardar(string n, byte[] c) { Claves[n] = c.ToArray(); return null; }
            public IReadOnlyList<string> Lista() => Claves.Keys.ToList();
            public bool Olvidar(string n) => Claves.Remove(n);
        }

        private static EntradaDeBoveda Ent(string sitio, string usuario, string clave = "secreto")
            => new(Guid.NewGuid(), sitio, usuario, clave, "", DateTimeOffset.Now, DateTimeOffset.Now);

        private static void ProbarSitiosDeEntrada()
        {
            Console.WriteLine("Autocompletado: ¿esta entrada es de esta página? (lo que frena el phishing)");
            (string sitio, string? host)[] entradas =
            {
                ("github.com", "github.com"), ("https://github.com/login", "github.com"), ("www.GitHub.com/", "github.com"),
                ("  bancoestado.cl  ", "bancoestado.cl"), ("http://intranet.empresa.cl:8443/x", "intranet.empresa.cl"), ("santander.com.ar", "santander.com.ar"),
                ("GitHub", null), ("mi banco", null), ("", null), ("localhost", null), ("com.ar", null), ("gob.cl", null), ("C:\\x\\y", null),
                ("ftp://github.com", null), ("https://bancoestado.cl@malo.top", null), ("münchen.de", "xn--mnchen-3ya.de"), ("192.168.1.1", "192.168.1.1")
            };
            foreach ((string s, string? h) in entradas)
                Check(SitioDeEntrada.HostDeEntrada(s) == h, "entrada «" + s + "» -> " + (h ?? "no reconocible (no se rellena sola)"), SitioDeEntrada.HostDeEntrada(s));

            Check(SitioDeEntrada.AnalizarPagina("https://github.com/login?x=1").Host == "github.com", "página https: válida");
            Check(SitioDeEntrada.AnalizarPagina("http://github.com/login").Motivo!.Contains("cifrada"), "página http: NO (la contraseña viajaría a la vista)");
            Check(SitioDeEntrada.AnalizarPagina("http://localhost:3000").Motivo is not null, "tampoco http://localhost");
            Check(SitioDeEntrada.AnalizarPagina("file:///C:/x.html").Motivo is not null && SitioDeEntrada.AnalizarPagina("chrome://settings").Motivo is not null
                  && SitioDeEntrada.AnalizarPagina("data:text/html,<form>").Motivo is not null, "file:, chrome:, data:: NO");
            Check(SitioDeEntrada.AnalizarPagina("https://bancoestado.cl@malo.top/").Motivo?.Contains("phishing") == true,"«https://banco@malo»: NO, y se dice que es un truco de phishing");
            Check(SitioDeEntrada.AnalizarPagina("no es url").Motivo is not null && SitioDeEntrada.AnalizarPagina(null).Motivo is not null, "basura: NO");

            string P(string url) => SitioDeEntrada.AnalizarPagina(url).Host!;
            Check(SitioDeEntrada.Coincide(P("https://github.com/"), "github.com"), "misma página: sí");
            Check(SitioDeEntrada.Coincide(P("https://gist.github.com/"), "github.com"), "subdominio del sitio guardado: sí");
            Check(!SitioDeEntrada.Coincide(P("https://github.com/"), "gist.github.com"), "al revés (entrada de un subdominio, página del dominio): NO");
            Check(!SitioDeEntrada.Coincide(P("https://bancoestado.cl.verificar.top/"), "bancoestado.cl"), "«bancoestado.cl.verificar.top»: NO");
            Check(!SitioDeEntrada.Coincide(P("https://mibancoestado.cl/"), "bancoestado.cl"), "«mibancoestado.cl» (otro nombre que termina igual): NO");
            Check(!SitioDeEntrada.Coincide(P("https://xn--pple-43d.com/"), "apple.com") && !SitioDeEntrada.Coincide(P("https://аpple.com/"), "apple.com"),
                "«аpple.com» con «а» cirílica: NO (se compara en punycode)", P("https://аpple.com/"));
            Check(SitioDeEntrada.Coincide(P("https://MÜNCHEN.de/"), SitioDeEntrada.HostDeEntrada("münchen.de")!), "un nombre con tildes coincide consigo mismo");
            Check(!SitioDeEntrada.Coincide(P("https://192.168.1.10/"), "192.168.1.1") && SitioDeEntrada.Coincide(P("https://192.168.1.1/"), "192.168.1.1"), "IP: solo la misma");
            Check(SitioDeEntrada.Coincide(P("https://github.com./"), "github.com"), "con punto final: es el mismo sitio");
        }

        private static void ProbarMensajeNativo()
        {
            Console.WriteLine("Autocompletado: el formato de native messaging");
            static byte[] Marco(uint largo, byte[] cuerpo) { var b = new byte[4 + cuerpo.Length]; BitConverter.GetBytes(largo).CopyTo(b, 0); cuerpo.CopyTo(b, 4); return b; }
            byte[] json = Encoding.UTF8.GetBytes("{\"tipo\":\"estado\",\"x\":\"ñ\"}");

            var s = new MemoryStream(Marco((uint)json.Length, json).Concat(Marco((uint)json.Length, json)).ToArray());
            Check(MensajeNativo.LeerAsync(s).GetAwaiter().GetResult()!.SequenceEqual(json) && MensajeNativo.LeerAsync(s).GetAwaiter().GetResult()!.SequenceEqual(json)
                  && MensajeNativo.LeerAsync(s).GetAwaiter().GetResult() is null, "lee dos mensajes seguidos y null al cerrarse limpio");

            foreach ((string nombre, byte[] datos) in new[]
            {
                ("cabecera cortada", new byte[] { 5, 0 }),
                ("longitud 0", Marco(0, Array.Empty<byte>())),
                ("longitud enorme (4 GB)", Marco(uint.MaxValue, json)),
                ("mayor que 64 KB", Marco(MensajeNativo.MaxEntrada + 1u, json)),
                ("cuerpo cortado", Marco(100, json))
            })
            {
                bool rechazo = false;
                string? otra = null;
                try { MensajeNativo.LeerAsync(new MemoryStream(datos)).GetAwaiter().GetResult(); }
                catch (InvalidDataException) { rechazo = true; }
                catch (Exception ex) { otra = ex.GetType().Name; }   // p. ej. intentar reservar 4 GB: eso NO es rechazarlo
                Check(rechazo, "se rechaza: " + nombre, otra);
            }

            // Un mensaje COMPLETO de 64 KB + 1: se rechaza por grande, no porque falte cuerpo.
            bool grandeEntrada = false;
            byte[] lleno = new byte[MensajeNativo.MaxEntrada + 1];
            Array.Fill(lleno, (byte)' ');
            try { MensajeNativo.LeerAsync(new MemoryStream(Marco((uint)lleno.Length, lleno))).GetAwaiter().GetResult(); } catch (InvalidDataException) { grandeEntrada = true; }
            Check(grandeEntrada, "se rechaza: un mensaje completo de 64 KB + 1 (más de lo que necesita la extensión)");

            var o = new MemoryStream();
            MensajeNativo.EscribirAsync(o, json).GetAwaiter().GetResult();
            o.Position = 0;
            Check(o.Length == json.Length + 4 && MensajeNativo.LeerAsync(o).GetAwaiter().GetResult()!.SequenceEqual(json), "escribe y se vuelve a leer igual");
            bool grande = false;
            try { MensajeNativo.EscribirAsync(new MemoryStream(), new byte[MensajeNativo.MaxSalida + 1]).GetAwaiter().GetResult(); } catch (ArgumentOutOfRangeException) { grande = true; }
            Check(grande, "no escribe más de 1 MB (el navegador lo cortaría)");
        }

        private static async Task ProbarPuente(string dir)
        {
            Console.WriteLine("Autocompletado: el puente entre la extensión y la bóveda");
            // El MISMO vector está en tools/Nexo.Autocompletado.Extension.Pruebas (nucleo.js): si uno de los dos cambia el cálculo, falla.
            Check(PuenteDeAutocompletado.CodigoDe(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()) == "915 824",
                "el código de emparejamiento de la clave 0..31 es «915 824», igual que en la extensión", PuenteDeAutocompletado.CodigoDe(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()));
            DateTimeOffset ahora = new(2026, 11, 10, 12, 0, 0, TimeSpan.FromHours(-3));
            var gh = Ent("github.com", "ana");
            var gh2 = Ent("https://github.com/login", "ana-trabajo");
            var banco = Ent("bancoestado.cl", "12345678-9", "clave-banco");
            var sinSitio = Ent("Mi correo viejo", "ana@x.cl");
            IReadOnlyList<EntradaDeBoveda>? abiertas = new[] { gh, gh2, banco, sinSitio };
            var emp = new EmparejadosEnMemoria();
            var preguntas = new List<(string, string)>();
            bool aceptar = true;
            var p = new PuenteDeAutocompletado(() => abiertas, emp, (n, c, ct) => { preguntas.Add((n, c)); return Task.FromResult(aceptar); }, () => ahora);
            var rellenados = new List<(string, string)>();
            p.Rellenado += (n, h) => rellenados.Add((n, h));

            byte[] clave = RandomNumberGenerator.GetBytes(32), otra = RandomNumberGenerator.GetBytes(32);
            string k = Convert.ToBase64String(clave);
            async Task<JsonElement> Pedir(object o) => JsonDocument.Parse(await p.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(o))).RootElement;
            static string Est(JsonElement e) => e.GetProperty("estado").GetString()!;

            // Sin emparejar.
            JsonElement r = await Pedir(new { tipo = "estado", navegador = "brave", clave = k });
            Check(Est(r) == "ok" && !r.GetProperty("emparejado").GetBoolean() && !r.GetProperty("bloqueada").GetBoolean(), "estado: abierta y sin emparejar");
            r = await Pedir(new { tipo = "buscar", navegador = "brave", clave = k, url = "https://github.com" });
            Check(Est(r) == "no_emparejado" && !r.TryGetProperty("entradas", out _), "sin emparejar: buscar no da nada");
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com", id = gh.Id });
            Check(Est(r) == "no_emparejado" && !r.ToString().Contains("secreto"), "sin emparejar: rellenar no da la contraseña");

            // Emparejar: rechazado, espera, aceptado.
            aceptar = false;
            r = await Pedir(new { tipo = "emparejar", navegador = "brave", clave = k });
            Check(Est(r) == "rechazado" && preguntas.Single() == ("brave", PuenteDeAutocompletado.CodigoDe(clave)), "emparejar pregunta en Nexo con el código; si dices que no, rechazado");
            aceptar = true;
            r = await Pedir(new { tipo = "emparejar", navegador = "brave", clave = k });
            Check(Est(r) == "rechazado" && preguntas.Count == 1, "tras un rechazo, durante 30 s ni siquiera se vuelve a preguntar");
            ahora = ahora.AddSeconds(31);
            r = await Pedir(new { tipo = "emparejar", navegador = "brave", clave = k });
            Check(Est(r) == "ok" && preguntas.Count == 2 && emp.Autorizado("brave", clave), "pasada la espera, aceptado: emparejado");
            Check(PuenteDeAutocompletado.CodigoDe(clave) is { Length: 7 } cod && cod[3] == ' ' && PuenteDeAutocompletado.CodigoDe(clave) != PuenteDeAutocompletado.CodigoDe(otra),
                "el código es «123 456» y cambia con la clave");
            r = await Pedir(new { tipo = "emparejar", navegador = "brave", clave = k });
            Check(Est(r) == "ok" && preguntas.Count == 2, "emparejar otra vez con la misma clave: no vuelve a preguntar");

            // Otra clave con el mismo nombre: no vale.
            r = await Pedir(new { tipo = "buscar", navegador = "brave", clave = Convert.ToBase64String(otra), url = "https://github.com" });
            Check(Est(r) == "no_emparejado", "el nombre «brave» con OTRA clave: no emparejado");
            r = await Pedir(new { tipo = "buscar", navegador = "edge", clave = k, url = "https://github.com" });
            Check(Est(r) == "no_emparejado", "la clave de Brave con otro nombre: no emparejado");

            // Buscar.
            r = await Pedir(new { tipo = "buscar", navegador = "brave", clave = k, url = "https://github.com/login" });
            var usuarios = r.GetProperty("entradas").EnumerateArray().Select(x => x.GetProperty("usuario").GetString()).ToList();
            Check(Est(r) == "ok" && usuarios.SequenceEqual(new[] { "ana", "ana-trabajo" }) && r.GetProperty("sitio").GetString() == "github.com", "buscar en github.com: sus dos cuentas, ordenadas");
            Check(!r.ToString().Contains("secreto") && !r.GetProperty("entradas")[0].TryGetProperty("contrasena", out _), "buscar NUNCA lleva contraseñas");
            r = await Pedir(new { tipo = "buscar", navegador = "brave", clave = k, url = "https://bancoestado.cl.verificar.top/login" });
            Check(Est(r) == "ok" && r.GetProperty("entradas").GetArrayLength() == 0, "en una página falsa del banco: ninguna cuenta");
            r = await Pedir(new { tipo = "buscar", navegador = "brave", clave = k, url = "http://github.com/login" });
            Check(Est(r) == "rechazada" && r.GetProperty("motivo").GetString()!.Contains("cifrada"), "en http: rechazada, con el motivo");

            // Rellenar.
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/login", id = gh.Id });
            Check(Est(r) == "ok" && r.GetProperty("usuario").GetString() == "ana" && r.GetProperty("contrasena").GetString() == "secreto", "rellenar: usuario y contraseña de ESA entrada");
            Check(rellenados.Single() == ("brave", "github.com"), "y Nexo se entera (para avisar)");
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://bancoestado.cl.verificar.top/", id = banco.Id });
            Check(Est(r) == "rechazada" && !r.ToString().Contains("clave-banco"), "pedir la del banco desde la página falsa (con el id correcto): rechazada");
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = sinSitio.Id });
            Check(Est(r) == "rechazada", "una entrada sin sitio reconocible no se rellena en ningún sitio");
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = Guid.NewGuid() });
            Check(Est(r) == "no_encontrada", "id que no existe: no_encontrada");

            // Bloqueada.
            abiertas = null;
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = gh.Id });
            Check(Est(r) == "bloqueada" && !r.ToString().Contains("secreto"), "bóveda bloqueada: nada");
            Check((await Pedir(new { tipo = "estado", navegador = "brave", clave = k })).GetProperty("bloqueada").GetBoolean(), "y el estado lo dice");
            abiertas = new[] { gh, gh2, banco, sinSitio };

            // Tope por minuto.
            int ok = 0, limite = 0;
            for (int i = 0; i < 30; i++)
            {
                string e = Est(await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = gh.Id }));
                if (e == "ok") ok++; else if (e == "limite") limite++;
            }
            Check(ok == PuenteDeAutocompletado.MaxRellenadosPorMinuto - 1 && limite == 30 - ok, "como mucho 20 contraseñas por minuto (una ya se dio antes)", ok + " ok, " + limite + " límite");
            ahora = ahora.AddMinutes(1);
            Check(Est(await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = gh.Id })) == "ok", "pasado el minuto, vuelve a dejar");

            // Peticiones malas.
            foreach ((string nombre, byte[] datos) in new[]
            {
                ("no es JSON", Encoding.UTF8.GetBytes("{nada")),
                ("un array", Encoding.UTF8.GetBytes("[1,2]")),
                ("sin navegador", JsonSerializer.SerializeToUtf8Bytes(new { tipo = "estado" })),
                ("navegador con mayúsculas y espacios", JsonSerializer.SerializeToUtf8Bytes(new { tipo = "estado", navegador = "Mi Brave" })),
                ("navegador larguísimo", JsonSerializer.SerializeToUtf8Bytes(new { tipo = "estado", navegador = new string('a', 40) })),
                ("tipo desconocido", JsonSerializer.SerializeToUtf8Bytes(new { tipo = "volcar", navegador = "brave", clave = k })),
                ("UTF-8 roto", new byte[] { 0x7B, 0xFF, 0xFE, 0x7D })
            })
                Check(Est(JsonDocument.Parse(await p.AtenderAsync(datos)).RootElement) == "error", "petición mala → «error»: " + nombre);
            r = await Pedir(new { tipo = "emparejar", navegador = "edge", clave = Convert.ToBase64String(new byte[16]) });
            Check(Est(r) == "error" && preguntas.Count == 2, "emparejar con una clave de 16 bytes: error y sin preguntar");
            r = await Pedir(new { tipo = "rellenar", navegador = "brave", clave = k, url = "https://github.com/", id = "no-es-guid" });
            Check(Est(r) == "error", "id que no es un GUID: error");

            // Dos emparejamientos a la vez: solo una pregunta.
            var puerta = new TaskCompletionSource<bool>();
            var p2 = new PuenteDeAutocompletado(() => abiertas, new EmparejadosEnMemoria(), (n, c, ct) => puerta.Task, () => ahora);
            Task<byte[]> a = p2.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "brave", clave = k }));
            Task<byte[]> segunda = p2.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "edge", clave = Convert.ToBase64String(otra) }));
            // Con tiempo máximo: si la segunda se quedara esperando a la primera, la prueba FALLA en vez de colgarse.
            bool contesto = await Task.WhenAny(segunda, Task.Delay(TimeSpan.FromSeconds(3))) == segunda;
            Check(contesto && Est(JsonDocument.Parse(segunda.Result).RootElement) == "ocupado", "con un emparejamiento esperando respuesta, otro contesta «ocupado» al momento (no abre otra pregunta)");
            puerta.SetResult(false);
            Check(Est(JsonDocument.Parse(await a).RootElement) == "rechazado", "y el primero sigue su curso");

            // La pregunta que lanza: es «no».
            var p3 = new PuenteDeAutocompletado(() => abiertas, new EmparejadosEnMemoria(), (n, c, ct) => throw new InvalidOperationException("ventana cerrada"), () => ahora);
            Check(Est(JsonDocument.Parse(await p3.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "brave", clave = k }))).RootElement) == "rechazado",
                "si la pregunta falla, cuenta como «no»");

            // Emparejar solo cuando se admite (la persona lo pidió en Nexo): fuera de eso, ni pregunta ni espera, y se avisa.
            bool admitir = false;
            int preguntado = 0;
            var noAdmitidos = new List<string>();
            var emparejados = new List<string>();
            var rechazos = new List<string>();
            var p4 = new PuenteDeAutocompletado(() => abiertas, new EmparejadosEnMemoria(), (n, c, ct) => { preguntado++; return Task.FromResult(true); }, () => ahora,
                                                n => admitir ? null : "pídelo primero en Nexo");
            p4.EmparejamientoNoAdmitido += noAdmitidos.Add;
            p4.Emparejado += emparejados.Add;
            p4.EmparejamientoRechazado += rechazos.Add;
            JsonElement ne = JsonDocument.Parse(await p4.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "brave", clave = k }))).RootElement;
            Check(Est(ne) == "rechazado" && ne.GetProperty("motivo").GetString() == "pídelo primero en Nexo" && preguntado == 0 && noAdmitidos.SequenceEqual(new[] { "brave" }),
                "emparejar cuando no se admite: rechazado con el motivo, SIN preguntar, y se avisa (EmparejamientoNoAdmitido)", ne.ToString());
            admitir = true;
            ne = JsonDocument.Parse(await p4.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "brave", clave = k }))).RootElement;
            Check(Est(ne) == "ok" && preguntado == 1 && emparejados.SequenceEqual(new[] { "brave" }),
                "en cuanto se admite se pregunta al momento: el «no admitido» NO activó la espera de 30 s; y avisa «Emparejado»");
            var p5 = new PuenteDeAutocompletado(() => abiertas, new EmparejadosEnMemoria(), (n, c, ct) => Task.FromResult(false), () => ahora);
            p5.EmparejamientoRechazado += rechazos.Add;
            await p5.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "edge", clave = k }));
            Check(rechazos.SequenceEqual(new[] { "edge" }), "decir «No» avisa EmparejamientoRechazado");

            // La lista en disco.
            string ruta = Path.Combine(dir, "navegadores.json");
            var j = new NavegadoresEmparejadosJson(ruta);
            Check(!j.Autorizado("brave", clave) && j.Guardar("brave", clave) is null && j.Autorizado("brave", clave) && !j.Autorizado("brave", otra), "JSON: guarda y reconoce solo esa clave");
            Check(!File.ReadAllText(ruta).Contains(k) && File.ReadAllText(ruta).Contains(Convert.ToHexString(SHA256.HashData(clave)).ToLowerInvariant()), "JSON: guarda la huella, NO la clave");
            Check(j.Guardar("edge", otra) is null && j.Lista().OrderBy(x => x).SequenceEqual(new[] { "brave", "edge" }) && j.Olvidar("brave") && !j.Autorizado("brave", clave) && j.Autorizado("edge", otra),
                "JSON: varios navegadores, y olvidar uno no toca al otro");
            File.WriteAllText(ruta, "{roto");
            Check(!j.Autorizado("edge", otra) && File.Exists(ruta + ".corrupto") && j.Problema!.Contains("dañada"), "JSON dañado: nadie autorizado, se aparta y se dice");
        }
    }
}
