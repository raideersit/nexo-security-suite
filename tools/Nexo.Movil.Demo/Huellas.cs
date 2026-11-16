using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        /// <summary>APK falsos en memoria: cuenta cuantas veces se abre cada uno, y puede fallar a pedido.</summary>
        private sealed class OrigenFalso : IOrigenDeApks
        {
            public readonly Dictionary<string, byte[]> Archivos = new();
            public readonly HashSet<string> Ilegibles = new();
            public int Aperturas;
            public long? Tamano(string ruta) => Archivos.TryGetValue(ruta, out var b) ? b.Length : null;
            public Stream Abrir(string ruta)
            {
                Aperturas++;
                if (Ilegibles.Contains(ruta)) throw new UnauthorizedAccessException("sin permiso");
                return new MemoryStream(Archivos[ruta]);
            }
        }

        private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

        private static ModeloDeApp ConApks(string paquete, long version, long fecha, params string[] rutas) =>
            new() { Paquete = paquete, Nombre = paquete, VersionCode = version, UltimaActualizacionMs = fecha, Apks = rutas };

        private static void ProbarHuellas()
        {
            Titulo("Huella SHA-256 de un APK");
            var o = new OrigenFalso();
            o.Archivos["/a/base.apk"] = Encoding.ASCII.GetBytes("abc");
            o.Archivos["/b/base.apk"] = Array.Empty<byte>();
            var calc = new CalculadorDeHuellas(o, new CacheDeHuellas());
            var r = calc.Calcular(new[] { ConApks("com.a", 1, 10, "/a/base.apk"), ConApks("com.b", 1, 10, "/b/base.apk") });
            Check(r.Huellas["com.a"].Archivos[0].Sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 de «abc» = vector de prueba oficial");
            Check(r.Huellas["com.b"].Archivos[0].Sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 de un archivo vacio = vector oficial");
            Check(r.Huellas["com.a"].Archivos[0].Archivo == "base.apk" && r.Huellas["com.a"].Archivos[0].Tamano == 3, "guarda nombre y tamano");

            var grande = new byte[1_000_000]; new Random(7).NextBytes(grande);
            o.Archivos["/g/base.apk"] = grande;
            var rg = new CalculadorDeHuellas(o, new CacheDeHuellas()).Calcular(new[] { ConApks("com.g", 1, 1, "/g/base.apk") });
            Check(rg.Huellas["com.g"].Archivos[0].Sha256 == Sha(grande), "un APK que ocupa varios bloques de lectura da la misma huella que el calculo directo");

            Titulo("APK dividido («split»)");
            o.Archivos["/s/base.apk"] = new byte[] { 1, 2, 3 };
            o.Archivos["/s/split_config.arm64_v8a.apk"] = new byte[] { 4, 5 };
            var rs = new CalculadorDeHuellas(o, new CacheDeHuellas()).Calcular(new[] { ConApks("com.s", 1, 1, "/s/base.apk", "/s/split_config.arm64_v8a.apk") });
            Check(rs.Huellas["com.s"].Archivos.Count == 2 && rs.Huellas["com.s"].Archivos[1].Archivo == "split_config.arm64_v8a.apk", "se hashean el base y cada split");
            Check(rs.Resumen.BytesLeidos == 5, "cuenta los bytes leidos");
        }

        private static void ProbarCache()
        {
            Titulo("Cache: solo se rehashea lo nuevo o cambiado");
            var o = new OrigenFalso();
            foreach (var p in new[] { "a", "b", "c" }) o.Archivos[$"/{p}/base.apk"] = Encoding.ASCII.GetBytes("contenido " + p);
            var cache = new CacheDeHuellas();
            var apps = new[] { ConApks("com.a", 1, 100, "/a/base.apk"), ConApks("com.b", 1, 100, "/b/base.apk"), ConApks("com.c", 1, 100, "/c/base.apk") };
            var calc = new CalculadorDeHuellas(o, cache);
            var r1 = calc.Calcular(apps);
            Check(r1.Resumen.Calculadas == 3 && r1.Resumen.DeCache == 0 && o.Aperturas == 3, "primera pasada: calcula las 3", $"{r1.Resumen.Calculadas}/{r1.Resumen.DeCache}, aperturas={o.Aperturas}");
            o.Aperturas = 0;
            var r2 = calc.Calcular(apps);
            Check(r2.Resumen.Calculadas == 0 && r2.Resumen.DeCache == 3 && o.Aperturas == 0, "segunda pasada: todo de cache y NO se abre ningun archivo", $"aperturas={o.Aperturas}");
            Check(r2.Huellas["com.b"].Archivos[0].Sha256 == r1.Huellas["com.b"].Archivos[0].Sha256, "la huella de la cache es la misma");

            o.Aperturas = 0;
            var actualizada = new[] { apps[0], ConApks("com.b", 2, 100, "/b/base.apk"), apps[2] };
            var r3 = calc.Calcular(actualizada);
            Check(r3.Resumen.Calculadas == 1 && o.Aperturas == 1, "subir el versionCode de una app: solo esa se recalcula", $"{r3.Resumen.Calculadas}");
            o.Aperturas = 0;
            var r4 = calc.Calcular(new[] { apps[0], ConApks("com.b", 2, 999, "/b/base.apk"), apps[2] });
            Check(r4.Resumen.Calculadas == 1, "cambiar lastUpdateTime tambien la recalcula");
            o.Archivos["/c/base.apk"] = Encoding.ASCII.GetBytes("contenido c MODIFICADO");
            o.Aperturas = 0;
            var r5 = calc.Calcular(new[] { apps[0], ConApks("com.b", 2, 999, "/b/base.apk"), apps[2] });
            Check(r5.Resumen.Calculadas == 1 && r5.Huellas["com.c"].Archivos[0].Sha256 == Sha(o.Archivos["/c/base.apk"]), "un APK que cambia de tamano sin cambiar de version se detecta y se recalcula");

            Titulo("Cache: apps desinstaladas y apps del sistema");
            var r6 = calc.Calcular(new[] { apps[0] });
            Check(r6.Resumen.Podadas == 2 && cache.Cantidad == 1, "lo desinstalado se borra de la cache", $"podadas={r6.Resumen.Podadas}");
            o.Aperturas = 0;
            var sistema = new ModeloDeApp { Paquete = "com.android.sys", EsDeSistema = true, Apks = new[] { "/a/base.apk" } };
            var r7 = new CalculadorDeHuellas(o, new CacheDeHuellas()).Calcular(new[] { sistema });
            Check(r7.Huellas.Count == 0 && o.Aperturas == 0, "las apps del sistema no se hashean");
            var sinApk = new CalculadorDeHuellas(o, new CacheDeHuellas()).Calcular(new[] { ConApks("com.nada", 1, 1) });
            Check(sinApk.Huellas.Count == 0 && sinApk.Resumen.Fallidas == 0, "una app sin rutas de APK se ignora sin error");
        }

        private static void ProbarCacheFallosYCancelacion()
        {
            Titulo("Fallos y cancelacion");
            var o = new OrigenFalso();
            o.Archivos["/ok/base.apk"] = new byte[] { 1 };
            o.Archivos["/mal/base.apk"] = new byte[] { 2 };
            o.Ilegibles.Add("/mal/base.apk");
            var cache = new CacheDeHuellas();
            var calc = new CalculadorDeHuellas(o, cache);
            var apps = new[] { ConApks("com.mal", 1, 1, "/mal/base.apk"), ConApks("com.ok", 1, 1, "/ok/base.apk") };
            var r = calc.Calcular(apps);
            Check(r.Resumen.Fallidas == 1 && r.Resumen.Calculadas == 1 && r.Huellas.ContainsKey("com.ok"), "una app ilegible no frena a las demas", $"fallidas={r.Resumen.Fallidas}");
            Check(r.Resumen.Errores.Count == 1 && r.Resumen.Errores[0].StartsWith("com.mal"), "el error nombra la app");
            Check(!r.Huellas.ContainsKey("com.mal") && cache.Cantidad == 1, "lo que fallo NO se guarda en la cache como si fuera bueno");

            using var cts = new CancellationTokenSource();
            var o2 = new OrigenFalso();
            var muchas = Enumerable.Range(0, 20).Select(i => { o2.Archivos[$"/{i}/base.apk"] = new[] { (byte)i }; return ConApks("com.p" + i, 1, 1, $"/{i}/base.apk"); }).ToArray();
            var cache2 = new CacheDeHuellas();
            var progreso = new Progreso(h => { if (h == 5) cts.Cancel(); });
            bool cancelo = false;
            try { new CalculadorDeHuellas(o2, cache2).Calcular(muchas, progreso, cts.Token); } catch (OperationCanceledException) { cancelo = true; }
            Check(cancelo, "se puede cancelar");
            Check(cache2.Cantidad == 5, "lo calculado antes de cancelar queda en la cache (la proxima vez sigue donde se quedo)", $"{cache2.Cantidad}");
            o2.Aperturas = 0;
            var r2 = new CalculadorDeHuellas(o2, cache2).Calcular(muchas);
            Check(r2.Resumen.DeCache == 5 && r2.Resumen.Calculadas == 15, "al reanudar solo se calcula lo que faltaba", $"{r2.Resumen.DeCache}/{r2.Resumen.Calculadas}");
            var ps = new List<int>();
            new CalculadorDeHuellas(o2, new CacheDeHuellas()).Calcular(muchas, new Progreso(h => ps.Add(h)));
            Check(ps.Count == 20 && ps[^1] == 20 && ps.SequenceEqual(ps.OrderBy(x => x)), "informa el progreso de 1 a N");
        }

        private sealed class Progreso : IProgress<(int Hechas, int Total)>
        {
            private readonly Action<int> _f;
            public Progreso(Action<int> f) => _f = f;
            public void Report((int Hechas, int Total) v) => _f(v.Hechas);
        }

        private static void ProbarPersistenciaDeCache()
        {
            Titulo("Cache en disco");
            var dir = Path.Combine(Path.GetTempPath(), "nexo-movil-demo-" + Guid.NewGuid().ToString("N"));
            try
            {
                var ruta = Path.Combine(dir, "huellas.json");
                var o = new OrigenFalso(); o.Archivos["/a/base.apk"] = new byte[] { 9, 9, 9 };
                var c = new CacheDeHuellas();
                new CalculadorDeHuellas(o, c).Calcular(new[] { ConApks("com.a", 3, 33, "/a/base.apk") });
                c.Guardar(ruta);
                Check(File.Exists(ruta) && !File.Exists(ruta + ".tmp"), "guarda el archivo y no deja el temporal");
                var c2 = CacheDeHuellas.Cargar(ruta, out var aviso);
                Check(aviso == null && c2.Cantidad == 1, "recarga lo guardado sin avisos");
                o.Aperturas = 0;
                var r = new CalculadorDeHuellas(o, c2).Calcular(new[] { ConApks("com.a", 3, 33, "/a/base.apk") });
                Check(r.Resumen.DeCache == 1 && o.Aperturas == 0, "la cache recargada de disco evita recalcular");

                Check(CacheDeHuellas.Cargar(Path.Combine(dir, "no-existe.json"), out var a0).Cantidad == 0 && a0 == null, "sin archivo: cache vacia, sin aviso");
                File.WriteAllText(ruta, "{esto no es json");
                var danada = CacheDeHuellas.Cargar(ruta, out var a1);
                Check(danada.Cantidad == 0 && a1 != null, "un JSON roto no se usa y se avisa", a1);
                File.WriteAllText(ruta, "{\"Version\":1,\"Apps\":[{\"Paquete\":\"com.x\",\"VersionCode\":1,\"UltimaActualizacionMs\":1,\"Archivos\":[{\"Archivo\":\"base.apk\",\"Tamano\":1,\"Sha256\":\"zzzz\"}]}]}");
                var invalida = CacheDeHuellas.Cargar(ruta, out var a2);
                Check(invalida.Cantidad == 0 && a2 != null, "una huella que no es SHA-256 invalida toda la cache (no se confia a medias)");
                File.WriteAllText(ruta, "{\"Version\":99,\"Apps\":[]}");
                Check(CacheDeHuellas.Cargar(ruta, out var a3).Cantidad == 0 && a3 != null, "una version desconocida se descarta con aviso");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }

        private static void ProbarListasYCoincidencias()
        {
            Titulo("Lista de huellas conocidas");
            var h1 = new string('a', 64); var h2 = new string('B', 64); var h3 = new string('c', 64);
            var plana = ListaDeHuellas.Desde("plana.txt", new StringReader($"# comentario\n\n{h1}\n  {h2}  \nesto no es una huella\n{h1}\n"));
            Check(plana.Cantidad == 2, "texto plano: ignora comentarios, vacias y repetidas", plana.Cantidad.ToString());
            Check(plana.LineasInvalidas == 1, "cuenta las lineas invalidas");
            Check(plana.Contiene(h2.ToLowerInvariant()) && plana.Contiene(h2), "las mayusculas se normalizan");
            Check(!plana.Contiene(h1[..63]), "una huella a medias no coincide");

            // Formato de ejemplo INVENTADO con la forma de un CSV de varias columnas: el real de MalwareBazaar no se pudo verificar.
            var csv = $"# CSV de ejemplo inventado\n\"2026-11-16 10:00:00\",\"{h3}\",\"md5\",\"sha1\",\"reportero\",\"a.apk\",\"apk\",\"application/vnd.android.package-archive\",\"Familia\"\n\"2026-11-16 10:01:00\",\"{new string('d', 64)}\",\"md5\",\"sha1\",\"reportero\",\"b.exe\",\"exe\",\"application/x-dosexec\",\"Otra\"\n";
            var l2 = ListaDeHuellas.Desde("ejemplo.csv", new StringReader(csv));
            Check(l2.Cantidad == 1 && l2.Contiene(h3) && l2.FilasQueNoSonApk == 1, "CSV de varias columnas: solo filas de APK", $"{l2.Cantidad}, noApk={l2.FilasQueNoSonApk}");
            Check(Lanza(() => ListaDeHuellas.Desde("vacia", new StringReader("# nada\n\nbasura"))), "una lista sin ninguna huella valida es un error, no «cero amenazas»");
            Check(Lanza(() => ListaDeHuellas.Desde("solo-exe", new StringReader($"x,{new string('e', 64)},exe"))), "una lista donde todo es no-APK tambien es un error");

            Titulo("Coincidencias");
            var apps = new[]
            {
                new HuellaDeApp("com.limpia", 1, 1, new[] { new HuellaDeArchivo("base.apk", 1, new string('1', 64)) }),
                new HuellaDeApp("com.mala", 1, 1, new[] { new HuellaDeArchivo("base.apk", 1, new string('2', 64)), new HuellaDeArchivo("split.apk", 1, h1) }),
            };
            var m = BuscadorDeCoincidencias.Buscar(apps, new[] { plana, l2 });
            Check(m.Count == 1 && m[0].Paquete == "com.mala" && m[0].Archivo == "split.apk" && m[0].Lista == "plana.txt", "encuentra la app cuyo split esta en la lista y dice en cual", string.Join(";", m.Select(x => x.Paquete + "/" + x.Archivo)));
            Check(BuscadorDeCoincidencias.Buscar(apps, Array.Empty<ListaDeHuellas>()).Count == 0, "sin listas no hay coincidencias");
            Check(BuscadorDeCoincidencias.Buscar(Array.Empty<HuellaDeApp>(), new[] { plana }).Count == 0, "sin apps no hay coincidencias");
        }

        private static bool Lanza(Action a)
        {
            try { a(); return false; } catch (InvalidDataException) { return true; }
        }
    }
}
