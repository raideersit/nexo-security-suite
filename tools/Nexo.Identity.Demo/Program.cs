using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;
using Nexo.Modules.Identity.Boveda;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Identity.Demo
{
    internal static partial class Program
    {
        private static int _fallos;

        // Parametros de pruebas: lo minimo que Argon2 admite, para que cientos de aperturas no tarden minutos.
        private static readonly ParametrosDeClave Rapidos = new(1024, 1, 1);
        private const string Maestra = "una-contrasena-maestra-larga";

        private sealed class EscritorFalso : IReportWriter
        {
            public readonly List<NexoEvent> Eventos = new();
            public bool Lanzar;
            public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
            {
                if (Lanzar) throw new IOException("disco lleno");
                Eventos.Add(evento);
                return Task.FromResult<NoteRef>(null!);
            }
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            string dir = Path.Combine(Path.GetTempPath(), "nexo-identity-demo-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                ProbarArgon2ContraVectorOficial();
                await ProbarCiclo(dir).ConfigureAwait(false);
                await ProbarContenidoCifrado(dir).ConfigureAwait(false);
                await ProbarManipulacion(dir).ConfigureAwait(false);
                await ProbarParametrosHostiles(dir).ConfigureAwait(false);
                await ProbarGuardado(dir).ConfigureAwait(false);
                await ProbarContrasenaMaestra(dir).ConfigureAwait(false);
                await ProbarBloqueo(dir).ConfigureAwait(false);
                await ProbarEventos(dir).ConfigureAwait(false);
                ProbarGenerador();
                await ProbarCostoReal(dir).ConfigureAwait(false);
                await ProbarCopias(dir).ConfigureAwait(false);
                await ProbarFiltraciones().ConfigureAwait(false);
                await ProbarHttp().ConfigureAwait(false);
                await ProbarAuditoria(dir).ConfigureAwait(false);
                // Solo con --real: habla con Internet (envia unicamente el prefijo de 5 caracteres de una contrasena de prueba publica).
                if (args.Contains("--real")) await ProbarServicioReal().ConfigureAwait(false);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static string Ruta(string dir, string nombre) => Path.Combine(dir, nombre + ".nxv");

        private static async Task<Boveda> NuevaAsync(string dir, string nombre, IReportWriter? w = null, string maestra = Maestra)
            => await Boveda.CrearAsync(Ruta(dir, nombre), maestra, w, Rapidos, permitirParametrosDebiles: true).ConfigureAwait(false);

        // ------------------------------------------------------------------------------------------------

        private static void ProbarArgon2ContraVectorOficial()
        {
            Console.WriteLine("1. Argon2id contra el vector oficial (RFC 9106, seccion 5.3)");
            byte[] pwd = Enumerable.Repeat((byte)0x01, 32).ToArray();
            using var a = new Argon2id(pwd)
            {
                Salt = Enumerable.Repeat((byte)0x02, 16).ToArray(),
                KnownSecret = Enumerable.Repeat((byte)0x03, 8).ToArray(),
                AssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray(),
                MemorySize = 32, Iterations = 3, DegreeOfParallelism = 4
            };
            string tag = Convert.ToHexString(a.GetBytes(32)).ToLowerInvariant();
            Check(tag == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", "la libreria produce el valor del RFC 9106 para Argon2id", tag);
        }

        private static async Task ProbarCiclo(string dir)
        {
            Console.WriteLine("2. Crear, guardar, abrir");
            using Boveda b = await NuevaAsync(dir, "ciclo").ConfigureAwait(false);
            EntradaDeBoveda e1 = await b.AgregarAsync("banco.ejemplo.cl", "ana", "S3creto!clave", "nota uno").ConfigureAwait(false);
            await b.AgregarAsync("correo.ejemplo.com", "ana@ejemplo.com", "otra-clave-larga", "").ConfigureAwait(false);
            await b.ActualizarAsync(e1.Id, "banco.ejemplo.cl", "ana", "S3creto!NUEVA", "nota dos").ConfigureAwait(false);

            ResultadoDeApertura r = await Boveda.AbrirAsync(Ruta(dir, "ciclo"), Maestra).ConfigureAwait(false);
            Check(r.Abierta && r.Boveda is not null, "se abre con la contrasena correcta", r.Estado.ToString());
            using Boveda? c = r.Boveda;
            Check(c!.Entradas.Count == 2, "las 2 entradas estan", c.Entradas.Count.ToString());
            EntradaDeBoveda leida = c.Entradas.First(x => x.Id == e1.Id);
            Check(leida.Contrasena == "S3creto!NUEVA" && leida.Notas == "nota dos" && leida.Usuario == "ana", "la actualizacion se guardo");

            ResultadoDeApertura mala = await Boveda.AbrirAsync(Ruta(dir, "ciclo"), "esta-no-es-la-clave").ConfigureAwait(false);
            Check(mala.Estado == EstadoDeApertura.ContrasenaIncorrectaOArchivoAlterado && mala.Boveda is null, "con otra contrasena NO abre", mala.Estado.ToString());

            ResultadoDeApertura nada = await Boveda.AbrirAsync(Ruta(dir, "no-existe"), Maestra).ConfigureAwait(false);
            Check(nada.Estado == EstadoDeApertura.NoExiste, "una ruta sin archivo dice NoExiste, no «contrasena incorrecta»");

            bool lanzo = false;
            try { await Boveda.CrearAsync(Ruta(dir, "ciclo"), Maestra, null, Rapidos, true).ConfigureAwait(false); } catch (IOException) { lanzo = true; }
            Check(lanzo, "crear sobre una boveda existente se rechaza (no la sobrescribe)");

            bool corta = false;
            try { await Boveda.CrearAsync(Ruta(dir, "corta"), "corta", null, Rapidos, true).ConfigureAwait(false); } catch (ArgumentException) { corta = true; }
            Check(corta, "una contrasena maestra corta se rechaza");

            bool debil = false;
            try { await Boveda.CrearAsync(Ruta(dir, "debil"), Maestra, null, Rapidos, permitirParametrosDebiles: false).ConfigureAwait(false); } catch (ArgumentException) { debil = true; }
            Check(debil && !File.Exists(Ruta(dir, "debil")), "parametros de Argon2 debiles se rechazan salvo que se pida expresamente, y no se crea nada");
            Check(ParametrosDeClave.Seguros.EsSeguro && !Rapidos.EsSeguro && Rapidos.EsLegible, "los parametros por omision son seguros y los de prueba no");

            // La misma contrasena en otra forma Unicode (NFC vs NFD) abre igual.
            string nfc = "contraseña-ÁÉ-larga1";
            string nfd = nfc.Normalize(System.Text.NormalizationForm.FormD);
            using (await NuevaAsync(dir, "unicode", null, nfc).ConfigureAwait(false)) { }
            ResultadoDeApertura u = await Boveda.AbrirAsync(Ruta(dir, "unicode"), nfd).ConfigureAwait(false);
            Check(u.Abierta, "la misma contrasena en NFC y NFD abre la misma boveda", u.Estado.ToString());
            u.Boveda?.Dispose();
        }

        private static async Task ProbarContenidoCifrado(string dir)
        {
            Console.WriteLine("3. Lo que hay en el disco esta cifrado");
            using Boveda b = await NuevaAsync(dir, "cifrada").ConfigureAwait(false);
            await b.AgregarAsync("sitio-secreto-xyz.example", "usuario-secreto-abc", "clave-ultra-secreta-123", "nota-secreta-nnn").ConfigureAwait(false);
            byte[] archivo = File.ReadAllBytes(Ruta(dir, "cifrada"));

            string[] secretos = { "sitio-secreto-xyz", "usuario-secreto-abc", "clave-ultra-secreta-123", "nota-secreta-nnn" };
            bool aparece(byte[] datos, string s) =>
                datos.AsSpan().IndexOf(Encoding.UTF8.GetBytes(s)) >= 0 || datos.AsSpan().IndexOf(Encoding.Unicode.GetBytes(s)) >= 0;

            // Control: el mismo contenido SIN cifrar si se encuentra. Sin esto, «no aparece» no probaria nada.
            byte[] sinCifrar = Encoding.UTF8.GetBytes("{\"Sitio\":\"sitio-secreto-xyz.example\",\"Usuario\":\"usuario-secreto-abc\",\"Contrasena\":\"clave-ultra-secreta-123\",\"Notas\":\"nota-secreta-nnn\"}");
            Check(secretos.All(s => aparece(sinCifrar, s)), "control: el texto sin cifrar SI contiene los secretos (la busqueda funciona)");
            Check(secretos.All(s => !aparece(archivo, s)), "ninguno aparece en el archivo, ni en UTF-8 ni en UTF-16");
            Check(!aparece(archivo, Maestra), "la contrasena maestra tampoco");
            Check(archivo.AsSpan(0, 4).SequenceEqual("NXV1"u8), "el archivo empieza con la marca NXV1");

            // Dos boveda con el mismo contenido y la misma contrasena no producen el mismo archivo (sal y nonce aleatorios).
            using Boveda b2 = await NuevaAsync(dir, "cifrada2").ConfigureAwait(false);
            await b2.AgregarAsync("sitio-secreto-xyz.example", "usuario-secreto-abc", "clave-ultra-secreta-123", "nota-secreta-nnn").ConfigureAwait(false);
            byte[] otro = File.ReadAllBytes(Ruta(dir, "cifrada2"));
            Check(!archivo.AsSpan(FormatoLongitudCabeceraSal(), 16).SequenceEqual(otro.AsSpan(FormatoLongitudCabeceraSal(), 16)), "la sal es distinta en cada boveda");
        }

        private static int FormatoLongitudCabeceraSal() => 18;

        private static async Task ProbarManipulacion(string dir)
        {
            Console.WriteLine("4. Un archivo alterado nunca se abre");
            using (Boveda b = await NuevaAsync(dir, "base").ConfigureAwait(false))
                await b.AgregarAsync("sitio.example", "ana", "clave-de-ana", "n").ConfigureAwait(false);
            string rutaBase = Ruta(dir, "base");
            byte[] original = File.ReadAllBytes(rutaBase);

            string rutaMuta = Ruta(dir, "muta");
            int abrieron = 0, lanzaron = 0, total = 0;
            for (int i = 0; i < original.Length; i++)
            {
                foreach (byte mascara in new byte[] { 0x01, 0x80 })
                {
                    // Los campos de costo (offsets 6..17): solo el bit bajo, para no pedir cientos de MiB a cada vuelta.
                    if (i is >= 6 and <= 17 && mascara == 0x80) continue;
                    byte[] copia = (byte[])original.Clone();
                    copia[i] ^= mascara;
                    File.WriteAllBytes(rutaMuta, copia);
                    total++;
                    try
                    {
                        ResultadoDeApertura r = await Boveda.AbrirAsync(rutaMuta, Maestra).ConfigureAwait(false);
                        if (r.Abierta) { abrieron++; r.Boveda?.Dispose(); }
                    }
                    catch (Exception) { lanzaron++; }
                }
            }
            Check(abrieron == 0, "cambiar CUALQUIER bit de cualquier byte (" + total + " variantes) impide abrir: cabecera, sal, nonce, cifrado y etiqueta", abrieron + " abrieron");
            Check(lanzaron == 0, "y ninguna variante lanza una excepcion: todas dan un estado claro", lanzaron + " lanzaron");

            int truncadosOk = 0;
            for (int n = 0; n < original.Length; n++)
            {
                File.WriteAllBytes(rutaMuta, original.AsSpan(0, n).ToArray());
                try { ResultadoDeApertura r = await Boveda.AbrirAsync(rutaMuta, Maestra).ConfigureAwait(false); if (!r.Abierta) truncadosOk++; }
                catch (Exception) { }
            }
            Check(truncadosOk == original.Length, "truncado a cualquier longitud (0 a " + (original.Length - 1) + " bytes): nunca abre y nunca lanza", truncadosOk + "/" + original.Length);

            File.WriteAllBytes(rutaMuta, original.Concat(new byte[] { 0 }).ToArray());
            ResultadoDeApertura extra = await Boveda.AbrirAsync(rutaMuta, Maestra).ConfigureAwait(false);
            Check(extra.Estado == EstadoDeApertura.ArchivoIlegible, "un byte de mas al final tambien se rechaza", extra.Estado.ToString());

            File.WriteAllBytes(rutaMuta, new byte[2000]);
            Check((await Boveda.AbrirAsync(rutaMuta, Maestra).ConfigureAwait(false)).Estado == EstadoDeApertura.ArchivoIlegible, "un archivo que no es una boveda es ArchivoIlegible");

            byte[] version = (byte[])original.Clone(); version[4] = 2;
            File.WriteAllBytes(rutaMuta, version);
            Check((await Boveda.AbrirAsync(rutaMuta, Maestra).ConfigureAwait(false)).Estado == EstadoDeApertura.VersionNoSoportada, "una version futura dice VersionNoSoportada");
        }

        private static async Task ProbarParametrosHostiles(string dir)
        {
            Console.WriteLine("5. Un archivo hecho para agotar la memoria no lo consigue");
            string ruta = Ruta(dir, "hostil");
            using (Boveda b = await NuevaAsync(dir, "hostil").ConfigureAwait(false)) { }
            byte[] original = File.ReadAllBytes(ruta);

            async Task<(EstadoDeApertura, long)> Con(Action<byte[]> cambio)
            {
                byte[] c = (byte[])original.Clone();
                cambio(c);
                File.WriteAllBytes(ruta, c);
                var sw = Stopwatch.StartNew();
                ResultadoDeApertura r = await Boveda.AbrirAsync(ruta, Maestra).ConfigureAwait(false);
                return (r.Estado, sw.ElapsedMilliseconds);
            }

            var (e1, t1) = await Con(c => BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(c, 6)).ConfigureAwait(false);
            Check(e1 == EstadoDeApertura.ParametrosFueraDeRango && t1 < 2000, "memoria = 4 GiB: rechazado sin intentar reservarla", e1 + " en " + t1 + " ms");
            var (e2, t2) = await Con(c => BitConverter.GetBytes(0x7FFFFFFFu).CopyTo(c, 10)).ConfigureAwait(false);
            Check(e2 == EstadoDeApertura.ParametrosFueraDeRango && t2 < 2000, "2 mil millones de iteraciones: rechazado sin calcularlas", e2 + " en " + t2 + " ms");
            var (e3, _) = await Con(c => BitConverter.GetBytes(0u).CopyTo(c, 14)).ConfigureAwait(false);
            Check(e3 == EstadoDeApertura.ParametrosFueraDeRango, "paralelismo 0: rechazado");
            var (e4, _) = await Con(c => BitConverter.GetBytes(10_000u).CopyTo(c, 14)).ConfigureAwait(false);
            Check(e4 == EstadoDeApertura.ParametrosFueraDeRango, "paralelismo 10 000: rechazado");
            var (e5, _) = await Con(c => BitConverter.GetBytes(0u).CopyTo(c, 6)).ConfigureAwait(false);
            Check(e5 == EstadoDeApertura.ParametrosFueraDeRango, "memoria 0: rechazado");
            var (e6, t6) = await Con(c => BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(c, 18 + 16 + 12)).ConfigureAwait(false);
            Check(e6 == EstadoDeApertura.ArchivoIlegible && t6 < 2000, "longitud declarada de 4 GiB: ArchivoIlegible sin reservar memoria", e6 + " en " + t6 + " ms");
            var (e7, _) = await Con(c => BitConverter.GetBytes(0x80000000u).CopyTo(c, 6)).ConfigureAwait(false);
            Check(e7 == EstadoDeApertura.ParametrosFueraDeRango, "un valor que daria negativo al pasar a int no se cuela");
        }

        private static async Task ProbarGuardado(string dir)
        {
            Console.WriteLine("6. Guardado");
            string ruta = Ruta(dir, "guardado");
            using Boveda b = await NuevaAsync(dir, "guardado").ConfigureAwait(false);
            var nonces = new HashSet<string>();
            for (int i = 0; i < 20; i++)
            {
                await b.AgregarAsync("sitio" + i, "u", "p", "").ConfigureAwait(false);
                byte[] a = File.ReadAllBytes(ruta);
                nonces.Add(Convert.ToHexString(a.AsSpan(18 + 16, 12)));
            }
            Check(nonces.Count == 20, "20 guardados seguidos usan 20 nonces distintos (jamas se repite uno con la misma clave)", nonces.Count + " distintos");

            string[] sobrantes = Directory.GetFiles(dir, "guardado.nxv*").Where(f => !f.EndsWith("guardado.nxv")).ToArray();
            Check(sobrantes.Length == 0, "tras guardar no quedan temporales ni .bak", string.Join(", ", sobrantes.Select(Path.GetFileName)));

            // Borrar de verdad: lo eliminado no puede quedar en ningun archivo.
            using Boveda d = await NuevaAsync(dir, "borrado").ConfigureAwait(false);
            EntradaDeBoveda a1 = await d.AgregarAsync("para-borrar.example", "u", "p", "").ConfigureAwait(false);
            await d.AgregarAsync("se-queda.example", "u", "p", "").ConfigureAwait(false);
            bool borrada = await d.EliminarAsync(a1.Id).ConfigureAwait(false);
            Check(borrada && !await d.EliminarAsync(a1.Id).ConfigureAwait(false), "eliminar una entrada la quita; eliminarla otra vez devuelve false");
            ResultadoDeApertura reab = await Boveda.AbrirAsync(Ruta(dir, "borrado"), Maestra).ConfigureAwait(false);
            Check(reab.Abierta && reab.Boveda!.Entradas.Count == 1 && reab.Boveda.Entradas[0].Sitio == "se-queda.example", "al reabrir, la eliminada no esta");
            reab.Boveda?.Dispose();
            Check(Directory.GetFiles(dir, "borrado.nxv*").Length == 1, "y no hay copia vieja con la entrada eliminada (solo un archivo)", string.Join(", ", Directory.GetFiles(dir, "borrado.nxv*").Select(Path.GetFileName)));

            // Varias escrituras simultaneas no corrompen el archivo.
            using Boveda c = await NuevaAsync(dir, "concurrente").ConfigureAwait(false);
            await Task.WhenAll(Enumerable.Range(0, 20).Select(i => c.AgregarAsync("s" + i, "u", "p", ""))).ConfigureAwait(false);
            ResultadoDeApertura rc = await Boveda.AbrirAsync(Ruta(dir, "concurrente"), Maestra).ConfigureAwait(false);
            Check(rc.Abierta && rc.Boveda!.Entradas.Count == 20, "20 altas simultaneas: el archivo abre y tiene las 20", rc.Estado + " " + rc.Boveda?.Entradas.Count);
            rc.Boveda?.Dispose();

            // Entradas invalidas.
            bool v1 = false, v2 = false;
            try { await c.AgregarAsync("  ", "u", "p").ConfigureAwait(false); } catch (ArgumentException) { v1 = true; }
            try { await c.AgregarAsync("x", "u", new string('a', 5000)).ConfigureAwait(false); } catch (ArgumentException) { v2 = true; }
            Check(v1 && v2, "un sitio vacio o una contrasena de 5000 caracteres se rechazan");
            bool noEncontrada = false;
            try { await c.ActualizarAsync(Guid.NewGuid(), "x", "u", "p", "").ConfigureAwait(false); } catch (KeyNotFoundException) { noEncontrada = true; }
            Check(noEncontrada, "actualizar una entrada que no existe lanza KeyNotFound");
        }

        private static async Task ProbarContrasenaMaestra(string dir)
        {
            Console.WriteLine("7. Cambiar la contrasena maestra");
            string ruta = Ruta(dir, "cambio");
            using Boveda b = await NuevaAsync(dir, "cambio").ConfigureAwait(false);
            await b.AgregarAsync("sitio.example", "ana", "clave", "").ConfigureAwait(false);
            byte[] antes = File.ReadAllBytes(ruta);

            bool rechazada = false;
            try { await b.CambiarContrasenaMaestraAsync("no-es-la-actual", "otra-maestra-nueva-1").ConfigureAwait(false); } catch (UnauthorizedAccessException) { rechazada = true; }
            Check(rechazada, "con la contrasena actual equivocada NO cambia");
            Check(File.ReadAllBytes(ruta).AsSpan().SequenceEqual(antes), "y el archivo queda intacto");

            await b.CambiarContrasenaMaestraAsync(Maestra, "otra-maestra-nueva-1").ConfigureAwait(false);
            byte[] despues = File.ReadAllBytes(ruta);
            Check(!despues.AsSpan(18, 16).SequenceEqual(antes.AsSpan(18, 16)), "la sal cambia");
            Check((await Boveda.AbrirAsync(ruta, Maestra).ConfigureAwait(false)).Estado == EstadoDeApertura.ContrasenaIncorrectaOArchivoAlterado, "la contrasena vieja ya no abre");
            ResultadoDeApertura nueva = await Boveda.AbrirAsync(ruta, "otra-maestra-nueva-1").ConfigureAwait(false);
            Check(nueva.Abierta && nueva.Boveda!.Entradas.Count == 1, "la nueva abre y conserva las entradas");
            nueva.Boveda?.Dispose();
            Check(Directory.GetFiles(dir, "cambio.nxv*").Length == 1, "no queda una copia con la clave vieja");

            bool corta = false;
            try { await b.CambiarContrasenaMaestraAsync("otra-maestra-nueva-1", "corta").ConfigureAwait(false); } catch (ArgumentException) { corta = true; }
            Check(corta, "una contrasena nueva corta se rechaza");
        }

        private static async Task ProbarBloqueo(string dir)
        {
            Console.WriteLine("8. Bloquear");
            Boveda b = await NuevaAsync(dir, "bloqueo").ConfigureAwait(false);
            await b.AgregarAsync("sitio.example", "ana", "clave", "").ConfigureAwait(false);

            FieldInfo campo = typeof(Boveda).GetField("_clave", BindingFlags.Instance | BindingFlags.NonPublic)!;
            byte[] clave = (byte[])campo.GetValue(b)!;
            Check(clave.Any(x => x != 0), "control: con la boveda abierta la clave no es todo ceros");
            b.Bloquear();
            Check(clave.All(x => x == 0), "bloquear sobrescribe con ceros el mismo arreglo que tenia la clave");
            Check(b.Bloqueada, "queda bloqueada");

            bool a = false, c = false, d = false;
            try { _ = b.Entradas; } catch (InvalidOperationException) { a = true; }
            try { await b.AgregarAsync("x", "u", "p").ConfigureAwait(false); } catch (InvalidOperationException) { c = true; }
            try { await b.EliminarAsync(Guid.NewGuid()).ConfigureAwait(false); } catch (InvalidOperationException) { d = true; }
            Check(a && c && d, "bloqueada, leer o cambiar entradas lanza InvalidOperation");
            b.Bloquear();
            b.Dispose();
            Check(true, "bloquear dos veces y Dispose no fallan");
        }

        private static async Task ProbarEventos(string dir)
        {
            Console.WriteLine("9. Eventos: sin secretos");
            var w = new EscritorFalso();
            using (Boveda b = await NuevaAsync(dir, "eventos", w).ConfigureAwait(false))
                await b.AgregarAsync("sitio-privado.example", "usuario-privado", "clave-privada-xyz", "nota-privada").ConfigureAwait(false);
            await Boveda.AbrirAsync(Ruta(dir, "eventos"), "contrasena-equivocada-1", w).ConfigureAwait(false);
            ResultadoDeApertura ok = await Boveda.AbrirAsync(Ruta(dir, "eventos"), Maestra, w).ConfigureAwait(false);
            ok.Boveda?.Dispose();

            Check(w.Eventos.Select(e => e.Tipo).SequenceEqual(new[] { TipoEvento.BovedaCreada, TipoEvento.BovedaFalloDeDesbloqueo, TipoEvento.BovedaDesbloqueada }),
                  "se publican creada, fallo de desbloqueo y desbloqueada, en ese orden", string.Join(",", w.Eventos.Select(e => e.Tipo)));

            string todo = string.Join("\n", w.Eventos.Select(e => e.Titulo + "|" + e.Cuerpo + "|" + string.Join(",", e.Campos.Select(k => k.Key + "=" + k.Value))
                                                                + "|" + string.Join(",", e.Entidades.Select(x => x.ToString()))));
            string[] secretos = { "sitio-privado", "usuario-privado", "clave-privada-xyz", "nota-privada", Maestra, "contrasena-equivocada-1", dir };
            Check(secretos.All(s => !todo.Contains(s, StringComparison.OrdinalIgnoreCase)), "ningun evento contiene sitio, usuario, contrasena, notas, la maestra ni la ruta", todo);
            Check(w.Eventos.All(e => e.Modulo == ModuloOrigen.Identidad), "todos son del modulo Identidad");
            Check(w.Eventos.First(e => e.Tipo == TipoEvento.BovedaFalloDeDesbloqueo).Severidad >= Severidad.Media, "el intento fallido tiene severidad media o mas");

            var roto = new EscritorFalso { Lanzar = true };
            ResultadoDeApertura r = await Boveda.AbrirAsync(Ruta(dir, "eventos"), Maestra, roto).ConfigureAwait(false);
            Check(r.Abierta, "si no se puede escribir el reporte, la boveda abre igual");
            r.Boveda?.Dispose();
        }

        private static void ProbarGenerador()
        {
            Console.WriteLine("10. Generador de contrasenas");
            string p = GeneradorDeContrasenas.Generar();
            Check(p.Length == 20 && p.Any(char.IsLower) && p.Any(char.IsUpper) && p.Any(char.IsDigit) && p.Any(c => !char.IsLetterOrDigit(c)), "por omision: 20 caracteres con minuscula, mayuscula, digito y simbolo", p);

            bool todas = true;
            for (int i = 0; i < 2000; i++)
            {
                string x = GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Longitud: 8));
                if (!(x.Any(char.IsLower) && x.Any(char.IsUpper) && x.Any(char.IsDigit) && x.Any(c => !char.IsLetterOrDigit(c)))) todas = false;
            }
            Check(todas, "2000 contrasenas de 8: TODAS tienen una de cada clase");

            Check(Enumerable.Range(0, 2000).Select(_ => GeneradorDeContrasenas.Generar()).Distinct().Count() == 2000, "2000 contrasenas seguidas son todas distintas");

            string sinAmb = string.Concat(Enumerable.Range(0, 300).Select(_ => GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Longitud: 64))));
            Check(sinAmb.All(c => "O0oIl1|".IndexOf(c) < 0), "evitando ambiguos, nunca salen O 0 o I l 1 |");
            string conAmb = string.Concat(Enumerable.Range(0, 300).Select(_ => GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Longitud: 64, EvitarAmbiguos: false))));
            Check(conAmb.Any(c => "O0oIl1|".IndexOf(c) >= 0), "control: sin ese filtro si salen (el filtro hace algo)");

            // Sin sesgo: solo digitos sin ambiguos = 8 simbolos; cada uno debe salir ~1/8 de las veces.
            var o = new OpcionesDeGenerador(Longitud: 128, Minusculas: false, Mayusculas: false, Digitos: true, Simbolos: false);
            var cuenta = new int[10];
            int total = 0;
            for (int i = 0; i < 2000; i++) foreach (char c in GeneradorDeContrasenas.Generar(o)) { cuenta[c - '0']++; total++; }
            double esperado = total / 8.0;
            Check(new[] { 2, 3, 4, 5, 6, 7, 8, 9 }.All(d => Math.Abs(cuenta[d] - esperado) / esperado < 0.03) && cuenta[0] == 0 && cuenta[1] == 0,
                  "distribucion uniforme entre los 8 digitos (cada uno a menos de 3 % de lo esperado)", string.Join(",", cuenta));

            bool a = false, b = false, c2 = false;
            try { GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Longitud: 4)); } catch (ArgumentOutOfRangeException) { a = true; }
            try { GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Longitud: 999)); } catch (ArgumentOutOfRangeException) { b = true; }
            try { GeneradorDeContrasenas.Generar(new OpcionesDeGenerador(Minusculas: false, Mayusculas: false, Digitos: false, Simbolos: false)); } catch (ArgumentException) { c2 = true; }
            Check(a && b && c2, "longitud fuera de 8..128 y ninguna clase se rechazan");
        }

        private static async Task ProbarCostoReal(string dir)
        {
            Console.WriteLine("11. Costo real de los parametros por omision");
            var sw = Stopwatch.StartNew();
            using (Boveda b = await Boveda.CrearAsync(Ruta(dir, "real"), Maestra).ConfigureAwait(false)) { }
            long crear = sw.ElapsedMilliseconds;
            sw.Restart();
            ResultadoDeApertura r = await Boveda.AbrirAsync(Ruta(dir, "real"), Maestra).ConfigureAwait(false);
            long abrir = sw.ElapsedMilliseconds;
            r.Boveda?.Dispose();
            Console.WriteLine("      INFO: Argon2id 64 MiB, 3 iteraciones, 2 hilos: crear " + crear + " ms, abrir " + abrir + " ms");
            Check(r.Abierta, "una boveda con los parametros por omision abre");
            Check(abrir >= 30, "abrir no es instantaneo (el costo de Argon2 existe: si fuera ~0 los parametros no se estarian aplicando)", abrir + " ms");
            Check(abrir < 10_000, "y tampoco es insoportable");
        }
    }
}
