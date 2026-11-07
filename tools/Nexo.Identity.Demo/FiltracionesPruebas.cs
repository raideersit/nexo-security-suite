using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;
using Nexo.Modules.Identity.Filtraciones;
using Nexo.Reports.Model;

namespace Nexo.Identity.Demo
{
    internal static partial class Program
    {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (vector publico conocido)
        private const string PrefijoPassword = "5BAA6", SufijoPassword = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        // SHA-1("123456") = 7C4A8D09CA3762AF61E59520943DC26494F8941B
        private const string PrefijoSeisDigitos = "7C4A8";

        private sealed class RangosFalsos : IConsultaDeRangos
        {
            public readonly List<string> Prefijos = new();
            public Func<string, RespuestaDeRango> Responde = _ => RespuestaDeRango.Ok("");
            public int Simultaneas, MaximoSimultaneas;
            public int RetardoMs;

            public async Task<RespuestaDeRango> ObtenerAsync(string prefijo, CancellationToken ct)
            {
                lock (Prefijos) Prefijos.Add(prefijo);
                int ahora = Interlocked.Increment(ref Simultaneas);
                lock (this) MaximoSimultaneas = Math.Max(MaximoSimultaneas, ahora);
                try
                {
                    if (RetardoMs > 0) await Task.Delay(RetardoMs, ct).ConfigureAwait(false);
                    return Responde(prefijo);
                }
                finally { Interlocked.Decrement(ref Simultaneas); }
            }
        }

        /// <summary>Un listado como el real: algunos sufijos al azar, el buscado, y relleno con cantidad 0.</summary>
        private static string Listado(string? sufijoPresente, long cantidad, bool conRelleno = true, bool minusculas = false)
        {
            var sb = new StringBuilder();
            var rnd = new Random(7);
            for (int i = 0; i < 40; i++)
                sb.Append(Convert.ToHexString(Enumerable.Range(0, 18).Select(_ => (byte)rnd.Next(256)).ToArray()).Substring(0, 35)).Append(":").Append(rnd.Next(1, 500)).Append("\r\n");
            if (conRelleno)
                for (int i = 0; i < 30; i++)
                    sb.Append(Convert.ToHexString(Enumerable.Range(0, 18).Select(_ => (byte)rnd.Next(256)).ToArray()).Substring(0, 35)).Append(":0\r\n");
            if (sufijoPresente is not null)
                sb.Append(minusculas ? sufijoPresente.ToLowerInvariant() : sufijoPresente).Append(":").Append(cantidad).Append("\r\n");
            return sb.ToString();
        }

        private static async Task ProbarFiltraciones()
        {
            Console.WriteLine("12. Comprobar contrasenas filtradas (k-anonimato)");

            var f = new RangosFalsos { Responde = _ => RespuestaDeRango.Ok(Listado(SufijoPassword, 10_000_000)) };
            var c = new ComprobadorDeContrasenas(f);

            ResultadoDeComprobacion r = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(r.Estado == EstadoDeComprobacion.Filtrada && r.Apariciones == 10_000_000, "«password» aparece, con su cantidad", r.Estado + " " + r.Apariciones);
            Check(f.Prefijos.SequenceEqual(new[] { PrefijoPassword }), "al servicio solo sale el prefijo de 5 caracteres (5BAA6, el del SHA-1 oficial)", string.Join(",", f.Prefijos));
            Check(f.Prefijos.All(p => p.Length == 5), "lo que sale mide exactamente 5 caracteres: ni la contrasena ni el hash completo (40) ni el sufijo (35)", string.Join(",", f.Prefijos.Select(p => p.Length)));

            await c.ComprobarAsync("123456").ConfigureAwait(false);
            Check(f.Prefijos.Last() == PrefijoSeisDigitos, "otro vector oficial: «123456» -> 7C4A8", f.Prefijos.Last());

            // No esta -> NoEncontrada, y solo porque el listado llego bien formado.
            f.Responde = _ => RespuestaDeRango.Ok(Listado(null, 0));
            ResultadoDeComprobacion no = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(no.Estado == EstadoDeComprobacion.NoEncontrada, "con un listado valido que no la incluye: NoEncontrada", no.Estado.ToString());

            // El relleno (cantidad 0) NO cuenta: si el sufijo buscado viene con 0, no esta filtrada.
            f.Responde = _ => RespuestaDeRango.Ok(Listado(SufijoPassword, 0));
            ResultadoDeComprobacion relleno = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(relleno.Estado == EstadoDeComprobacion.NoEncontrada, "un sufijo con cantidad 0 es relleno y no cuenta como aparicion", relleno.Estado.ToString());

            f.Responde = _ => RespuestaDeRango.Ok(Listado(SufijoPassword, 42, minusculas: true));
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.Filtrada, "el sufijo en minusculas tambien coincide");

            // Casi igual (un caracter distinto) no coincide.
            string casi = SufijoPassword.Substring(0, 34) + (SufijoPassword[34] == '0' ? '1' : '0');
            f.Responde = _ => RespuestaDeRango.Ok(Listado(casi, 99));
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoEncontrada, "un sufijo que difiere en 1 caracter NO coincide");

            // Lo que no se pudo comprobar jamas es NoEncontrada.
            f.Responde = _ => RespuestaDeRango.Fallo("sin red");
            ResultadoDeComprobacion sinRed = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(sinRed.Estado == EstadoDeComprobacion.NoSePudoComprobar && sinRed.Motivo == "sin red", "un fallo de red es NoSePudoComprobar (con el motivo), jamas NoEncontrada");

            f.Responde = _ => throw new InvalidOperationException("boom");
            ResultadoDeComprobacion lanza = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(lanza.Estado == EstadoDeComprobacion.NoSePudoComprobar, "si la consulta lanza una excepcion, tambien es NoSePudoComprobar", lanza.Estado.ToString());

            f.Responde = _ => RespuestaDeRango.Ok("<html><body>Inicia sesion en el Wi-Fi del hotel</body></html>");
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoSePudoComprobar, "un portal cautivo (HTML) es NoSePudoComprobar, no «no filtrada»");

            f.Responde = _ => RespuestaDeRango.Ok("");
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoSePudoComprobar, "una respuesta vacia es NoSePudoComprobar");

            f.Responde = _ => RespuestaDeRango.Ok(Listado(null, 0) + "esto no es una linea valida\r\n");
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoSePudoComprobar, "un listado con una linea basura sin la contrasena adentro no se da por bueno");

            f.Responde = _ => RespuestaDeRango.Ok(Listado(SufijoPassword, 77) + "basura\r\n");
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.Filtrada, "pero si la contrasena SI esta, un hallazgo no se descarta por una linea basura posterior");

            f.Responde = _ => RespuestaDeRango.Ok(Listado(null, 0) + SufijoPassword + ":99999999999999999999\r\n");
            Check((await c.ComprobarAsync("password").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoSePudoComprobar, "una cantidad de 20 digitos (desborde) es una linea invalida");

            Check((await c.ComprobarAsync("").ConfigureAwait(false)).Estado == EstadoDeComprobacion.NoSePudoComprobar, "una contrasena vacia no se comprueba");

            var cts = new CancellationTokenSource(); cts.Cancel();
            bool cancelo = false;
            f.Responde = _ => RespuestaDeRango.Ok(Listado(null, 0));
            f.RetardoMs = 500;
            try { await c.ComprobarAsync("password", cts.Token).ConfigureAwait(false); } catch (OperationCanceledException) { cancelo = true; }
            Check(cancelo, "cancelar propaga la cancelacion (no se disfraza de «no filtrada»)");
        }

        private sealed class ManejadorFalso : HttpMessageHandler
        {
            public HttpRequestMessage? Ultima;
            public Func<HttpResponseMessage> Responde = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Listado(null, 0)) };
            public Func<CancellationToken, Task>? Antes;
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Ultima = request;
                if (Antes is not null) await Antes(cancellationToken).ConfigureAwait(false);
                return Responde();
            }
        }

        private static async Task ProbarHttp()
        {
            Console.WriteLine("13. El cliente HTTP");
            var m = new ManejadorFalso();
            using var http = new ConsultaDeRangosHttp(m);

            RespuestaDeRango ok = await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false);
            Check(ok.Exito && m.Ultima!.RequestUri!.ToString() == "https://api.pwnedpasswords.com/range/5BAA6", "pide exactamente https://api.pwnedpasswords.com/range/5BAA6", m.Ultima?.RequestUri?.ToString());
            Check(m.Ultima!.Headers.TryGetValues("Add-Padding", out var v) && v.Contains("true"), "pide relleno (Add-Padding: true) para ocultar cuantos resultados hay");
            Check(m.Ultima.Method == HttpMethod.Get && m.Ultima.Content is null, "es un GET sin cuerpo (no sube nada)");
            Check(m.Ultima.RequestUri!.Scheme == "https", "solo HTTPS");

            foreach (string malo in new[] { "5baa6", "5BAA", "5BAA61", "5BAA/", "../..", "", "5BAA6?x=1" })
            {
                bool lanzo = false;
                try { await http.ObtenerAsync(malo, CancellationToken.None).ConfigureAwait(false); } catch (ArgumentException) { lanzo = true; }
                if (!lanzo) { Check(false, "el prefijo «" + malo + "» deberia rechazarse"); }
            }
            Check(true, "prefijos invalidos (minusculas, largos, con barras o parametros) se rechazan");

            m.Responde = () => new HttpResponseMessage(HttpStatusCode.InternalServerError);
            RespuestaDeRango e500 = await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false);
            Check(!e500.Exito && e500.Motivo!.Contains("500"), "HTTP 500 es un fallo con su codigo");

            m.Responde = () => new HttpResponseMessage(HttpStatusCode.Redirect) { Headers = { Location = new Uri("http://malo.example/") } };
            Check(!(await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false)).Exito, "una redireccion NO es exito (y el cliente real no las sigue)");

            m.Responde = () => new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            Check(!(await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false)).Exito, "HTTP 429 es un fallo");

            m.Responde = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('A', 2 * 1024 * 1024)) };
            RespuestaDeRango grande = await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false);
            Check(!grande.Exito && grande.Motivo!.Contains("grande"), "una respuesta de 2 MiB se rechaza por demasiado grande");

            m.Responde = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new FlujoInfinito()) };
            var sw = System.Diagnostics.Stopwatch.StartNew();
            RespuestaDeRango infinita = await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false);
            Check(!infinita.Exito && sw.ElapsedMilliseconds < 5000, "un flujo que nunca termina se corta al pasar el limite, sin llenar la memoria", infinita.Motivo + " " + sw.ElapsedMilliseconds + " ms");

            m.Responde = () => throw new HttpRequestException("sin red");
            Check(!(await http.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false)).Exito, "un error de conexion es un fallo, no una excepcion");

            using var lento = new ConsultaDeRangosHttp(new ManejadorFalso { Antes = ct => Task.Delay(10_000, ct) }, TimeSpan.FromMilliseconds(300));
            var sw2 = System.Diagnostics.Stopwatch.StartNew();
            RespuestaDeRango tarde = await lento.ObtenerAsync("5BAA6", CancellationToken.None).ConfigureAwait(false);
            Check(!tarde.Exito && tarde.Motivo!.Contains("tiempo") && sw2.ElapsedMilliseconds < 3000, "si no contesta a tiempo, falla con «tiempo de espera» sin colgarse", tarde.Motivo + " " + sw2.ElapsedMilliseconds + " ms");

            using var cancel = new CancellationTokenSource(); cancel.Cancel();
            bool cancelo = false;
            try { await http.ObtenerAsync("5BAA6", cancel.Token).ConfigureAwait(false); } catch (OperationCanceledException) { cancelo = true; }
            Check(cancelo, "la cancelacion del usuario se propaga");

            // De punta a punta: comprobador + cliente HTTP con un servicio falso que devuelve el listado.
            m.Responde = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Listado(SufijoPassword, 5)) };
            var c = new ComprobadorDeContrasenas(http);
            ResultadoDeComprobacion r = await c.ComprobarAsync("password").ConfigureAwait(false);
            Check(r.Estado == EstadoDeComprobacion.Filtrada && r.Apariciones == 5 && m.Ultima!.RequestUri!.AbsolutePath == "/range/5BAA6", "comprobador + cliente HTTP juntos: encuentra «password» pidiendo solo /range/5BAA6");
        }

        private sealed class FlujoInfinito : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) { Array.Fill(buffer, (byte)'A', offset, count); return count; }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private static async Task ProbarAuditoria(string dir)
        {
            Console.WriteLine("14. Auditar la boveda");
            var w = new EscritorFalso();
            using Boveda b = await Boveda.CrearAsync(Path.Combine(dir, "auditoria.nxv"), Maestra, null, Rapidos, true).ConfigureAwait(false);
            EntradaDeBoveda a = await b.AgregarAsync("sitio-privado-uno.example", "usuario-privado", "password", "").ConfigureAwait(false);
            EntradaDeBoveda a2 = await b.AgregarAsync("sitio-privado-dos.example", "otro", "password", "").ConfigureAwait(false); // misma clave
            EntradaDeBoveda ok = await b.AgregarAsync("sitio-privado-tres.example", "u", "una-clave-larga-y-unica-9X!", "").ConfigureAwait(false);
            EntradaDeBoveda vacia = await b.AgregarAsync("sitio-sin-clave.example", "u", "", "").ConfigureAwait(false);

            string sufOk = ComprobadorDeContrasenasSufijo("una-clave-larga-y-unica-9X!");
            var f = new RangosFalsos
            {
                Responde = p => p == PrefijoPassword ? RespuestaDeRango.Ok(Listado(SufijoPassword, 123)) : RespuestaDeRango.Ok(Listado(null, 0))
            };
            var c = new ComprobadorDeContrasenas(f);
            ResultadoDeAuditoria r = await AuditoriaDeBoveda.AuditarAsync(b, c, w).ConfigureAwait(false);

            Check(r.Filtradas.Count == 2 && r.Filtradas.All(h => h.Apariciones == 123) && r.Filtradas.Select(h => h.EntradaId).OrderBy(x => x).SequenceEqual(new[] { a.Id, a2.Id }.OrderBy(x => x)),
                  "las dos entradas con «password» salen como filtradas, con su cantidad");
            Check(r.NoEncontradas == 1 && r.SinComprobar.Count == 0 && r.SinContrasena.SequenceEqual(new[] { vacia.Id }), "la unica buena es NoEncontrada; la sin clave se aparta; nada sin comprobar");
            Check(f.Prefijos.Count == 2, "dos entradas con la misma clave hacen UNA sola consulta (2 consultas en total, no 3)", string.Join(",", f.Prefijos));
            Check(!r.TodoComprobadoYLimpio, "con filtradas, TodoComprobadoYLimpio es false");

            string todo = string.Join("\n", w.Eventos.Select(e => e.Titulo + "|" + e.Cuerpo + "|" + string.Join(",", e.Campos.Select(k => k.Key + "=" + k.Value))));
            Check(w.Eventos.Count == 1 && w.Eventos[0].Tipo == TipoEvento.BrechaDetectada && w.Eventos[0].Severidad == Severidad.Alta, "se publica un evento de brecha con severidad alta");
            Check(!new[] { "sitio-privado", "usuario-privado", "password", "una-clave-larga", "otro", "sitio-sin-clave" }.Any(s => todo.Contains(s, StringComparison.OrdinalIgnoreCase)),
                  "el evento solo lleva conteos: ni sitios, ni usuarios, ni contrasenas", todo);
            Check(todo.Contains("filtradas=2") && todo.Contains("no_encontradas=1") && todo.Contains("sin_contrasena=1"), "y los conteos son los correctos (2 filtradas, 1 no encontrada, 1 sin contrasena)", todo);

            // Si la red falla, NADA queda como «limpio».
            var caida = new RangosFalsos { Responde = _ => RespuestaDeRango.Fallo("sin red") };
            var w2 = new EscritorFalso();
            ResultadoDeAuditoria sinRed = await AuditoriaDeBoveda.AuditarAsync(b, new ComprobadorDeContrasenas(caida), w2).ConfigureAwait(false);
            Check(sinRed.Filtradas.Count == 0 && sinRed.SinComprobar.Count == 3 && sinRed.NoEncontradas == 0, "sin red: las 3 contrasenas quedan SinComprobar, ninguna «no encontrada»", sinRed.SinComprobar.Count + " / " + sinRed.NoEncontradas);
            Check(!sinRed.TodoComprobadoYLimpio, "y TodoComprobadoYLimpio es false: no comprobar no es estar bien");
            Check(w2.Eventos[0].Severidad == Severidad.Media, "el evento es de severidad media, no informativo");

            // Todo limpio y todo comprobado: aqui si.
            var buena = new RangosFalsos { Responde = _ => RespuestaDeRango.Ok(Listado(null, 0)) };
            var w3 = new EscritorFalso();
            ResultadoDeAuditoria limpia = await AuditoriaDeBoveda.AuditarAsync(b, new ComprobadorDeContrasenas(buena), w3).ConfigureAwait(false);
            Check(limpia.TodoComprobadoYLimpio && w3.Eventos[0].Severidad == Severidad.Info, "con todo comprobado y nada filtrado: TodoComprobadoYLimpio y severidad informativa");

            // Concurrencia acotada.
            using Boveda grande = await Boveda.CrearAsync(Path.Combine(dir, "auditoria2.nxv"), Maestra, null, Rapidos, true).ConfigureAwait(false);
            for (int i = 0; i < 20; i++) await grande.AgregarAsync("s" + i, "u", "clave-numero-" + i + "-xyz", "").ConfigureAwait(false);
            var lenta = new RangosFalsos { RetardoMs = 40, Responde = _ => RespuestaDeRango.Ok(Listado(null, 0)) };
            await AuditoriaDeBoveda.AuditarAsync(grande, new ComprobadorDeContrasenas(lenta)).ConfigureAwait(false);
            Check(lenta.Prefijos.Count == 20 && lenta.MaximoSimultaneas <= AuditoriaDeBoveda.ConsultasSimultaneas && lenta.MaximoSimultaneas > 1,
                  "20 contrasenas: nunca mas de " + AuditoriaDeBoveda.ConsultasSimultaneas + " consultas a la vez (y si van en paralelo)", "maximo simultaneo: " + lenta.MaximoSimultaneas);

            // Bloqueada: no se puede auditar.
            b.Bloquear();
            bool bloq = false;
            try { await AuditoriaDeBoveda.AuditarAsync(b, c).ConfigureAwait(false); } catch (InvalidOperationException) { bloq = true; }
            Check(bloq, "una boveda bloqueada no se puede auditar");
            _ = ok; _ = sufOk;
        }

        private static string ComprobadorDeContrasenasSufijo(string pass)
        {
            string h = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(Encoding.UTF8.GetBytes(pass)));
            return h.Substring(5);
        }

        private static async Task ProbarServicioReal()
        {
            Console.WriteLine("15. El servicio real de Pwned Passwords (Internet; solo sale el prefijo 5BAA6)");
            using var http = new ConsultaDeRangosHttp();
            var c = new ComprobadorDeContrasenas(http);
            ResultadoDeComprobacion r = await c.ComprobarAsync("password").ConfigureAwait(false);
            Console.WriteLine("      INFO: «password» -> " + r.Estado + ", apariciones: " + r.Apariciones + (r.Motivo is null ? "" : " (" + r.Motivo + ")"));
            Check(r.Estado == EstadoDeComprobacion.Filtrada && r.Apariciones > 1_000_000, "«password» aparece millones de veces en el servicio real", r.Estado + " " + r.Apariciones + " " + r.Motivo);

            string improbable = "Nx-" + Guid.NewGuid().ToString("N") + "-prueba";
            ResultadoDeComprobacion n = await c.ComprobarAsync(improbable).ConfigureAwait(false);
            Check(n.Estado == EstadoDeComprobacion.NoEncontrada, "una cadena aleatoria nueva NO esta (listado real bien formado, con relleno)", n.Estado + " " + n.Motivo);
        }
    }
}
