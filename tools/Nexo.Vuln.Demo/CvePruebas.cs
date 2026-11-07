using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private static string Recurso(string nombre)
        {
            using Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(nombre)!;
            return new StreamReader(s, Encoding.UTF8).ReadToEnd().TrimStart('﻿');
        }

        private static string NvdReal() => Recurso("nvd-winrar-7.01.json");
        private static string NvdNodo() => Recurso("nvd-nodejs-24.15.0.json");

        private static readonly ProductoCpe PWinRar = new("rarlab", "winrar", true), PNodo = new("nodejs", "node.js");

        // Piezas para armar respuestas de NVD con la forma real (configurations > nodes > cpeMatch).
        private static string Coincide(string criteria, bool vulnerable = true, string extra = "")
            => "{\"vulnerable\":" + (vulnerable ? "true" : "false") + ",\"criteria\":\"" + criteria + "\"" + extra + "}";
        private static string Config(params string[] coincidencias)
            => "\"configurations\":[{\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + string.Join(",", coincidencias) + "]}]}]";
        private static string CveJson(string id, string config, string extra = "") => "{\"id\":\"" + id + "\"," + config + extra + "}";
        private static string Respuesta(int total, int porPagina, params string[] cves)
            => "{\"resultsPerPage\":" + porPagina + ",\"startIndex\":0,\"totalResults\":" + total + ",\"vulnerabilities\":[" + string.Join(",", cves.Select(c => "{\"cve\":" + c + "}")) + "]}";
        private const string WrCriterio = "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*";

        private const string NvdVacio = "{\"resultsPerPage\":0,\"startIndex\":0,\"totalResults\":0,\"format\":\"NVD_CVE\",\"version\":\"2.0\",\"vulnerabilities\":[]}";

        private sealed class NvdFalso : IConsultaNvd
        {
            private readonly Func<string, RespuestaHttp> _responder;
            public List<string> Consultas { get; } = new();
            public NvdFalso(Func<string, RespuestaHttp> responder) => _responder = responder;
            public Task<RespuestaHttp> ConsultarCvesAsync(string cpe, CancellationToken ct) { Consultas.Add(cpe); return Task.FromResult(_responder(cpe)); }
        }

        private sealed class ManejadorFalso : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _f;
            public List<HttpRequestMessage> Peticiones { get; } = new();
            public ManejadorFalso(Func<HttpRequestMessage, HttpResponseMessage> f) => _f = f;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) { Peticiones.Add(request); return Task.FromResult(_f(request)); }
        }

        private sealed class ManejadorQueFalla : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => throw new HttpRequestException("sin red", new System.Net.Sockets.SocketException());
        }

        private static AplicacionDesactualizada App(string nombre, string id, string version) => new(nombre, id, version, "99.0", "winget");

        private static ResumenDeCruce Cruzar(IReadOnlyList<AplicacionDesactualizada> apps, NvdFalso nvd, List<TimeSpan>? esperas = null, DateTimeOffset? inicio = null)
        {
            DateTimeOffset ahora = inicio ?? new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
            return CruceConCve.CruzarAsync(apps, nvd,
                (t, _) => { esperas?.Add(t); ahora += t; return Task.CompletedTask; },
                () => ahora).GetAwaiter().GetResult();
        }

        public static void ProbarCveParser()
        {
            Console.WriteLine("16. Cruce con CVE: lectura de la respuesta de NVD");
            RespuestaDeNvdLeida l = ParserDeNvd.Parsear(NvdReal(), PWinRar, "7.01");
            Check(l.Reconocida && l.Cves.Count == 3, "la respuesta REAL de NVD para WinRAR 7.01 se lee entera: 3 fallos", l.Motivo + " / " + l.Cves.Count);
            Check(l.Cves.Select(c => c.Id).OrderBy(x => x).SequenceEqual(new[] { "CVE-2025-31334", "CVE-2025-6218", "CVE-2025-8088" }), "son CVE-2025-31334, CVE-2025-6218 y CVE-2025-8088", string.Join(",", l.Cves.Select(c => c.Id)));
            CveEncontrado c88 = l.Cves.Single(c => c.Id == "CVE-2025-8088");
            Check(c88.Puntaje == 8.8, "CVE-2025-8088 toma el puntaje PRIMARIO de NVD (8.8, CVSS 3.1), no el secundario 8.4 de CVSS 4.0", c88.Puntaje?.ToString());
            Check(c88.Gravedad == Severidad.Alta, "8.8 es gravedad Alta");
            Check(l.Cves.Single(c => c.Id == "CVE-2025-31334").Puntaje == 6.8 && l.Cves.Single(c => c.Id == "CVE-2025-31334").Gravedad == Severidad.Media, "CVE-2025-31334 vale 6.8: Media");
            Check(l.Cves.Single(c => c.Id == "CVE-2025-8088").Explotada && l.Cves.Single(c => c.Id == "CVE-2025-6218").Explotada && !l.Cves.Single(c => c.Id == "CVE-2025-31334").Explotada,
                "se marcan los explotados (lista CISA): 8088 y 6218 si, 31334 no");

            Check(ParserDeNvd.Parsear(NvdVacio, PWinRar, "7.01") is { Reconocida: true, Cves.Count: 0 }, "una respuesta valida con 0 fallos se reconoce como «cero»");
            string[] malas =
            {
                "", "   ", "no es json", "[]", "{}", "{\"totalResults\":0}", "{\"vulnerabilities\":[]}",
                "{\"totalResults\":\"0\",\"vulnerabilities\":[]}",
                "{\"totalResults\":-1,\"vulnerabilities\":[]}",
                "{\"totalResults\":2,\"vulnerabilities\":[]}", // dice 2, trae 0: cortada o paginada
                "{\"totalResults\":0,\"vulnerabilities\":{}}",
                "{\"totalResults\":1,\"vulnerabilities\":[{}]}",
                "{\"totalResults\":1,\"vulnerabilities\":[{\"cve\":{}}]}",
                "{\"totalResults\":1,\"vulnerabilities\":[{\"cve\":{\"id\":\"no-es-un-id\"}}]}",
                "{\"totalResults\":1,\"vulnerabilities\":[{\"cve\":{\"id\":5}}]}",
                "{\"totalResults\":5,\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2025-0001\"}}]}"
            };
            foreach (string m in malas)
                Check(!ParserDeNvd.Parsear(m, PWinRar, "7.01").Reconocida, "no se reconoce (nunca es «sin fallos»): " + Recorte(m));
            Check(!ParserDeNvd.Parsear(new string('x', ParserDeNvd.MaximoDeCaracteres + 1), PWinRar, "7.01").Reconocida, "una respuesta enorme se rechaza");
            Check(!ParserDeNvd.Parsear(new string('[', 100) + new string(']', 100), PWinRar, "7.01").Reconocida, "un JSON anidado de forma absurda se rechaza sin colgarse");

            string rechazado = Respuesta(2, 2, CveJson("CVE-2020-0001", Config(Coincide(WrCriterio)), ",\"vulnStatus\":\"Rejected\""), CveJson("CVE-2020-0002", Config(Coincide(WrCriterio)), ",\"vulnStatus\":\"Analyzed\""));
            RespuestaDeNvdLeida r = ParserDeNvd.Parsear(rechazado, PWinRar, "7.01");
            Check(r.Reconocida && r.Cves.Count == 1 && r.Cves[0].Id == "CVE-2020-0002", "un CVE «Rejected» (retirado) no cuenta, y el recuento total sigue cuadrando");
            string sinPuntaje = Respuesta(1, 1, CveJson("CVE-2026-0001", Config(Coincide(WrCriterio)), ",\"metrics\":{}"));
            CveEncontrado sp = ParserDeNvd.Parsear(sinPuntaje, PWinRar, "7.01").Cves.Single();
            Check(sp.Puntaje is null && sp.Gravedad == Severidad.Media, "un fallo sin puntaje todavia NO se esconde: cuenta como Media");
            string puntajeAbsurdo = Respuesta(1, 1, CveJson("CVE-2026-0002", Config(Coincide(WrCriterio)), ",\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":99}}]}"));
            Check(ParserDeNvd.Parsear(puntajeAbsurdo, PWinRar, "7.01").Cves.Single().Puntaje is null, "un puntaje fuera de 0 a 10 se descarta (queda «sin puntaje»)");
        }

        public static void ProbarCveFiltroPorProducto()
        {
            Console.WriteLine("16b. Cruce con CVE: solo cuentan los fallos que afectan DE VERDAD a este producto y version");
            RespuestaDeNvdLeida n = ParserDeNvd.Parsear(NvdNodo(), PNodo, "24.15.0");
            string[] ids = n.Cves.Select(c => c.Id).OrderBy(x => x, StringComparer.Ordinal).ToArray();
            Check(n.Reconocida && n.Cves.Count == 6 && n.Descartados == 2, "Node.js 24.15.0 (respuesta REAL): NVD devuelve 8, pero solo 6 afectan a Node.js; 2 se descartan", n.Cves.Count + " / " + n.Descartados);
            Check(!ids.Contains("CVE-2021-43803") && !ids.Contains("CVE-2022-36046"), "los dos descartados son los de Next.js (Node.js solo figura como plataforma donde corre, vulnerable=false)", string.Join(",", ids));
            Check(ids.SequenceEqual(new[] { "CVE-2026-111497", "CVE-2026-48617", "CVE-2026-48937", "CVE-2026-56847", "CVE-2026-56850", "CVE-2026-58043" }), "y los 6 que quedan son los fallos reales de Node.js", string.Join(",", ids));
            Check(n.Cves.Single(c => c.Id == "CVE-2026-111497").Explotada && n.Cves.Count(c => c.Explotada) == 1, "solo el de Brotli figura en la lista de explotados de CISA");

            // Los limites de los rangos, con los datos reales de Node.js.
            int Cuenta(string v) => ParserDeNvd.Parsear(NvdNodo(), PNodo, v).Cves.Count;
            Check(Cuenta("24.16.0") == 6, "24.16.0 sigue dentro de «hasta 24.16.0 incluido» (CVE-2026-48617)");
            Check(ParserDeNvd.Parsear(NvdNodo(), PNodo, "24.16.1").Cves.All(c => c.Id != "CVE-2026-48617"), "24.16.1 ya queda FUERA de «hasta 24.16.0 incluido»");
            Check(ParserDeNvd.Parsear(NvdNodo(), PNodo, "24.17.0").Cves.All(c => c.Id != "CVE-2026-48937") && Cuenta("24.17.0") == 4, "24.17.0 queda FUERA de «hasta 24.17.0 excluido»: quedan 4", Cuenta("24.17.0").ToString());
            Check(Cuenta("24.99.0") == 0 && ParserDeNvd.Parsear(NvdNodo(), PNodo, "24.99.0").Descartados == 8, "una version posterior a todos los rangos: 0 fallos y los 8 descartados");

            // Comparador de versiones.
            Check(ParserDeNvd.Comparar("7.01", "7.1") == 0 && ParserDeNvd.Comparar("24.0", "24.0.0") == 0, "«7.01» = «7.1» y «24.0» = «24.0.0»");
            Check(ParserDeNvd.Comparar("7.01", "7.10") < 0 && ParserDeNvd.Comparar("2.54.0", "2.9") > 0 && ParserDeNvd.Comparar("1.9", "1.10") < 0, "se compara numericamente por partes, no como texto («2.54» > «2.9», «1.9» < «1.10»)");
            Check(ParserDeNvd.Comparar("1.0-beta", "1.0") is null && ParserDeNvd.Comparar("1.0", "abc") is null && ParserDeNvd.Comparar("", "1") is null, "una version no numerica no se compara (null)");

            string Uno(string coincidencias, string version = "7.01") => ParserDeNvd.Parsear(Respuesta(1, 1, CveJson("CVE-2026-0001", Config(coincidencias))), PWinRar, version).Cves.Count.ToString();
            Check(Uno(Coincide(WrCriterio)) == "1", "vulnerable=true del producto, sin limites: afecta a todas las versiones");
            Check(Uno(Coincide(WrCriterio, vulnerable: false)) == "0", "vulnerable=false (solo plataforma): NO cuenta");
            Check(Uno(Coincide("cpe:2.3:a:otro:programa:*:*:*:*:*:*:*:*")) == "0", "vulnerable=true pero de OTRO producto: NO cuenta");
            Check(Uno(Coincide("cpe:2.3:a:rarlab:winrar_extra:*:*:*:*:*:*:*:*")) == "0", "un producto de nombre parecido («winrar_extra») NO cuenta");
            Check(Uno(Coincide("cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*")) == "1" && Uno(Coincide("cpe:2.3:a:rarlab:winrar:6.0:*:*:*:*:*:*:*")) == "0", "una version exacta en el criterio: cuenta solo si es la nuestra");
            Check(Uno(Coincide("cpe:2.3:a:rarlab:winrar:-:*:*:*:*:*:*:*")) == "0", "version «no aplica» (-): no nombra una version concreta, NO cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionStartIncluding\":\"7.0\",\"versionEndExcluding\":\"7.02\"")) == "1", "dentro de [7.0, 7.02): cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionStartIncluding\":\"7.02\"")) == "0", "antes del inicio del rango: NO cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionStartExcluding\":\"7.01\"")) == "0", "justo en un inicio EXCLUIDO: NO cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionEndIncluding\":\"7.01\"")) == "1", "justo en un final INCLUIDO: cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionEndExcluding\":\"7.01\"")) == "0", "justo en un final EXCLUIDO: NO cuenta");
            Check(Uno(Coincide(WrCriterio, true, ",\"versionEndExcluding\":\"7.01-rc\"")) == "1", "un limite que no se puede comparar cuenta (NVD ya lo emparejo con nuestra version): no se esconde un fallo por una rareza");
            Check(Uno("{\"vulnerable\":\"true\",\"criteria\":\"" + WrCriterio + "\"}") == "0", "vulnerable como TEXTO «true» (no booleano): NO cuenta");
            Check(Uno("{\"criteria\":\"" + WrCriterio + "\"}") == "0", "sin el campo vulnerable: NO cuenta");
            Check(Uno(Coincide(WrCriterio.ToUpperInvariant())) == "1", "el criterio se compara sin distinguir mayusculas");
            Check(ParserDeNvd.Parsear(Respuesta(1, 1, "{\"id\":\"CVE-2026-0001\"}"), PWinRar, "7.01").Cves.Count == 0, "un CVE sin configurations: no se puede afirmar nada, NO cuenta");
            string varios = Respuesta(2, 2, CveJson("CVE-2026-0001", Config(Coincide(WrCriterio, false), Coincide(WrCriterio, true, ",\"versionStartIncluding\":\"9.0\""))), CveJson("CVE-2026-0002", Config(Coincide(WrCriterio, false), Coincide(WrCriterio))));
            RespuestaDeNvdLeida rv = ParserDeNvd.Parsear(varios, PWinRar, "7.01");
            Check(rv.Cves.Count == 1 && rv.Cves[0].Id == "CVE-2026-0002" && rv.Descartados == 1, "con varias coincidencias basta UNA vulnerable que cubra la version; el de rango ajeno se descarta");

            // Respuestas paginadas (productos muy atacados con una version vieja).
            RespuestaDeNvdLeida pg = ParserDeNvd.Parsear(Respuesta(5000, 2, CveJson("CVE-2020-0001", Config(Coincide(WrCriterio))), CveJson("CVE-2020-0002", Config(Coincide(WrCriterio)))), PWinRar, "7.01");
            Check(pg.Reconocida && pg.Parcial && pg.Cves.Count == 2, "una pagina llena con mas resultados detras se acepta como PARCIAL (no se confunde con una respuesta cortada)");
            Check(!ParserDeNvd.Parsear(Respuesta(5000, 3, CveJson("CVE-2020-0001", Config(Coincide(WrCriterio))), CveJson("CVE-2020-0002", Config(Coincide(WrCriterio)))), PWinRar, "7.01").Reconocida, "si la pagina NO esta llena (dice 3 por pagina y trae 2): respuesta cortada, no se reconoce");
            string saltada = Respuesta(5000, 2, CveJson("CVE-2020-0001", Config(Coincide(WrCriterio))), CveJson("CVE-2020-0002", Config(Coincide(WrCriterio)))).Replace("\"startIndex\":0", "\"startIndex\":2");
            Check(!ParserDeNvd.Parsear(saltada, PWinRar, "7.01").Reconocida, "una pagina que no es la primera (startIndex distinto de 0) no se acepta");
            Check(!ParserDeNvd.Parsear(Respuesta(5000, 0), PWinRar, "7.01").Reconocida, "total 5000 con 0 elementos: no se reconoce");
        }

        private static string Recorte(string s) => s.Length > 45 ? s.Substring(0, 45) + "…" : (s.Length == 0 ? "(vacío)" : s);

        public static void ProbarCveMapaYVersiones()
        {
            Console.WriteLine("17. Cruce con CVE: mapa curado y traduccion de versiones");
            Check(MapaDeProductos.Buscar("RARLab.WinRAR") == new ProductoCpe("rarlab", "winrar", true), "RARLab.WinRAR -> rarlab:winrar");
            Check(MapaDeProductos.Buscar("rarlab.winrar")?.Producto == "winrar", "el id no distingue mayusculas");
            Check(MapaDeProductos.Buscar("Mozilla.Firefox.es-ES")?.Producto == "firefox", "Mozilla.Firefox.es-ES (con variante de idioma) entra");
            Check(MapaDeProductos.Buscar("OpenJS.NodeJS.LTS")?.Producto == "node.js", "OpenJS.NodeJS.LTS entra");
            Check(MapaDeProductos.Buscar("Git.Git")?.Producto == "git", "Git.Git entra");
            foreach (string no in new[] { "Git.GitHubDesktop", "GitHub.cli", "Oracle.JavaRuntimeEnvironment", "Python.PythonInstallManager", "Obsidian.Obsidian", "", "   ", "7zip.7zipExtra", "Google.ChromeRemoteDesktopHost" })
                Check(MapaDeProductos.Buscar(no) is null, "no se cruza (no esta en el mapa curado): «" + no + "»");

            ProductoCpe wr = MapaDeProductos.Buscar("RARLab.WinRAR")!, git = MapaDeProductos.Buscar("Git.Git")!;
            Check(MapaDeProductos.NormalizarVersion(wr, "7.01.0") == "7.01", "WinRAR «7.01.0» de winget -> «7.01» de NVD");
            Check(MapaDeProductos.NormalizarVersion(wr, "7.0.0") == "7.0", "WinRAR «7.0.0» -> «7.0» (nunca queda con una sola parte)");
            Check(MapaDeProductos.NormalizarVersion(wr, "6.22") == "6.22", "WinRAR «6.22» se queda igual");
            Check(MapaDeProductos.NormalizarVersion(git, "2.54.0") == "2.54.0", "Git «2.54.0» NO pierde su cero final (en Git el cero es parte de la version)");
            foreach (string mala in new[] { "< 175.1.0.13416", "Unknown", "1.0-beta", "", "  ", "7", "7.", ".7.1", "7.01.0.0.0", "abc", "7,01", "7.01 ", "１２.３", "8.0.4010.10x" })
                if (mala.Trim() != "7.01") Check(MapaDeProductos.NormalizarVersion(git, mala) is null, "version no fiable, no se adivina: «" + mala + "»");
            Check(MapaDeProductos.NormalizarVersion(git, null) is null, "version nula: no se adivina");
            Check(MapaDeProductos.Cpe(wr, "7.01") == "cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*", "el CPE se arma exactamente como lo espera NVD");

            // La lista de riesgo y el mapa no deben contradecirse en un id con otra forma.
            Check(MapaDeProductos.Todas.Select(e => e.Prefijo).Distinct(StringComparer.OrdinalIgnoreCase).Count() == MapaDeProductos.Todas.Count, "el mapa no repite ids");
            Check(MapaDeProductos.Todas.All(e => Regex.IsMatch(MapaDeProductos.Cpe(e.Cpe, "1.0"), @"^cpe:2\.3:a:[a-z0-9_.\-]+:[a-z0-9_.\-]+:1\.0(:\*){7}$")), "todos los CPE del mapa tienen la forma que acepta la consulta HTTP");
        }

        public static void ProbarCveCruce()
        {
            Console.WriteLine("18. Cruce con CVE: estados honestos, limite de tasa y fallos");
            var apps = new[] { App("WinRAR 7.01", "RARLab.WinRAR", "7.01.0"), App("Git", "Git.Git", "2.54.0"), App("Obsidian", "Obsidian.Obsidian", "1.13.7") };

            // Respuesta por producto.
            var nvd = new NvdFalso(cpe => cpe.Contains(":winrar:") ? new RespuestaHttp(200, NvdReal()) : new RespuestaHttp(200, NvdVacio));
            var esperas = new List<TimeSpan>();
            ResumenDeCruce c = Cruzar(apps, nvd, esperas);
            Check(c.Resultados.Single(r => r.App.Id == "RARLab.WinRAR") is { Estado: EstadoDeCruce.ConFallos } w && w.Cves.Count == 3, "WinRAR 7.01 -> con fallos (3)");
            Check(c.Resultados.Single(r => r.App.Id == "Git.Git").Estado == EstadoDeCruce.SinFallosConocidos, "Git con respuesta valida y vacia -> sin fallos conocidos");
            Check(c.SinMapa.Count == 1 && c.SinMapa[0].Id == "Obsidian.Obsidian", "Obsidian no esta en el mapa: queda como «sin mapa», no como «limpio»");
            Check(!nvd.Consultas.Any(q => q.Contains("obsidian")) && nvd.Consultas.Count == 2, "lo que no esta en el mapa NO se consulta (solo salen 2 consultas)", string.Join(" | ", nvd.Consultas));
            Check(nvd.Consultas.Contains("cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*"), "se consulto con la version traducida («7.01», no «7.01.0»)");
            Check(nvd.Consultas.All(q => Regex.IsMatch(q, @"^cpe:2\.3:a:[a-z0-9_.\-]+:[a-z0-9_.\-]+:[\d.]+(:\*){7}$")), "lo unico que se envia son producto y version en un CPE");

            // Limite de tasa: sin clave, 5 por 30 s -> 7 s entre consultas.
            Check(esperas.Count == 1 && esperas[0] == TimeSpan.FromSeconds(7), "entre dos consultas se espera 7 s; antes de la primera no se espera nada", string.Join(",", esperas));
            var tres = new[] { App("A", "RARLab.WinRAR", "7.01.0"), App("B", "Git.Git", "2.54.0"), App("C", "7zip.7zip", "24.08") };
            var esp3 = new List<TimeSpan>();
            Cruzar(tres, new NvdFalso(_ => new RespuestaHttp(200, NvdVacio)), esp3);
            Check(esp3.Count == 2 && esp3.All(e => e == TimeSpan.FromSeconds(7)), "tres consultas: dos esperas de 7 s", string.Join(",", esp3));
            var ahora = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
            var nvdLento = new NvdFalso(_ => { ahora += TimeSpan.FromSeconds(20); return new RespuestaHttp(200, NvdVacio); });
            var esp4 = new List<TimeSpan>();
            CruceConCve.CruzarAsync(tres, nvdLento, (t, _) => { esp4.Add(t); ahora += t; return Task.CompletedTask; }, () => ahora).GetAwaiter().GetResult();
            Check(esp4.Count == 2 && esp4.All(e => e == TimeSpan.FromSeconds(7)), "la espera se cuenta desde que TERMINA la consulta anterior");
            var ahora2 = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
            var nvdReloj = new NvdFalso(_ => new RespuestaHttp(200, NvdVacio));
            var esp5 = new List<TimeSpan>();
            CruceConCve.CruzarAsync(tres, nvdReloj, (t, _) => { esp5.Add(t); ahora2 += t; return Task.CompletedTask; }, () => { ahora2 += TimeSpan.FromSeconds(10); return ahora2; }).GetAwaiter().GetResult();
            Check(esp5.Count == 0, "si ya pasaron mas de 7 s entre consultas, no se espera de mas", string.Join(",", esp5));

            // El mismo CPE se consulta una sola vez.
            var dos = new[] { App("Firefox", "Mozilla.Firefox", "130.0"), App("Firefox ES", "Mozilla.Firefox.es-ES", "130.0") };
            var nvdDos = new NvdFalso(_ => new RespuestaHttp(200, NvdVacio));
            ResumenDeCruce cd = Cruzar(dos, nvdDos);
            Check(nvdDos.Consultas.Count == 1 && cd.Resultados.Count == 2 && cd.Resultados.All(r => r.Estado == EstadoDeCruce.SinFallosConocidos), "dos aplicaciones con el mismo CPE y version: una sola consulta, dos resultados");
            Check(cd.Resultados.Select(r => r.App.Id).SequenceEqual(new[] { "Mozilla.Firefox", "Mozilla.Firefox.es-ES" }), "y cada resultado conserva SU aplicacion");

            // Fallos: ninguno puede leerse como «sin fallos».
            void NoComprobable(string etiqueta, RespuestaHttp r)
            {
                ResumenDeCruce x = Cruzar(new[] { App("WinRAR", "RARLab.WinRAR", "7.01.0") }, new NvdFalso(_ => r));
                ResultadoDeCruce y = x.Resultados.Single();
                Check(y.Estado == EstadoDeCruce.NoSePudoComprobar && !string.IsNullOrWhiteSpace(y.Motivo) && y.Cves.Count == 0, "«" + etiqueta + "» -> no se pudo comprobar, con motivo", y.Estado + " / " + y.Motivo);
                ResultadoDeAnalisis an = CruceConCve.Analizar(x);
                Check(!an.Completo && !an.Hallazgos.Any(h => h.Id == "APP-CVE-NINGUNO"), "«" + etiqueta + "» -> el analisis queda incompleto y NUNCA dice «sin fallos»");
            }
            NoComprobable("sin red", new RespuestaHttp(null, "", "SocketException"));
            NoComprobable("HTTP 404", new RespuestaHttp(404, ""));
            NoComprobable("HTTP 500", new RespuestaHttp(500, ""));
            NoComprobable("HTTP 301", new RespuestaHttp(301, ""));
            // Un error con un cuerpo que PARECE valido (cero fallos) no puede leerse como «sin fallos»: el codigo HTTP manda, no el texto.
            NoComprobable("HTTP 500 con un cuerpo de «cero fallos»", new RespuestaHttp(500, NvdVacio));
            NoComprobable("HTTP 404 con un cuerpo de «cero fallos»", new RespuestaHttp(404, NvdVacio));
            NoComprobable("HTTP 204 con un cuerpo de «cero fallos»", new RespuestaHttp(204, NvdVacio));
            NoComprobable("HTTP 200 vacio", new RespuestaHttp(200, ""));
            NoComprobable("HTTP 200 con {}", new RespuestaHttp(200, "{}"));
            NoComprobable("HTTP 200 con HTML", new RespuestaHttp(200, "<html>Mantenimiento</html>"));
            NoComprobable("HTTP 200 cortada", new RespuestaHttp(200, NvdReal().Substring(0, 3000)));
            NoComprobable("HTTP 403", new RespuestaHttp(403, ""));
            NoComprobable("HTTP 429", new RespuestaHttp(429, ""));

            ResumenDeCruce lanza = CruceConCve.CruzarAsync(new[] { App("WinRAR", "RARLab.WinRAR", "7.01.0") }, new NvdQueLanza(), (_, _) => Task.CompletedTask, () => DateTimeOffset.UnixEpoch).GetAwaiter().GetResult();
            Check(lanza.Resultados.Single().Estado == EstadoDeCruce.NoSePudoComprobar, "si la consulta lanza una excepcion, no se pudo comprobar (y no se cae)");

            // Ante 403/429 se PARA.
            var cuatro = new[] { App("A", "RARLab.WinRAR", "7.01.0"), App("B", "Git.Git", "2.54.0"), App("C", "7zip.7zip", "24.08"), App("D", "VideoLAN.VLC", "3.0.20") };
            int llamadas = 0;
            var nvd429 = new NvdFalso(_ => ++llamadas == 2 ? new RespuestaHttp(429, "") : new RespuestaHttp(200, NvdVacio));
            ResumenDeCruce c429 = Cruzar(cuatro, nvd429);
            Check(nvd429.Consultas.Count == 2, "tras un 429 Nexo deja de preguntar (2 consultas de 4, no insiste)", nvd429.Consultas.Count.ToString());
            Check(c429.Resultados[0].Estado == EstadoDeCruce.SinFallosConocidos && c429.Resultados.Skip(1).All(r => r.Estado == EstadoDeCruce.NoSePudoComprobar), "la primera salio bien; la del 429 y las que quedaron sin preguntar: «no se pudo comprobar»");
            Check(c429.Resultados.Count == 4, "ninguna aplicacion desaparece del resultado");

            // Version no traducible: ni se consulta.
            var nvdV = new NvdFalso(_ => new RespuestaHttp(200, NvdVacio));
            ResumenDeCruce cv = Cruzar(new[] { App("Firefox", "Mozilla.Firefox", "< 130.0"), App("Git", "Git.Git", "Unknown") }, nvdV);
            Check(nvdV.Consultas.Count == 0 && cv.Resultados.All(r => r.Estado == EstadoDeCruce.NoSePudoComprobar), "una version que no se puede traducir con certeza ni se consulta: no se pudo comprobar");

            // Cancelacion.
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            bool cancelo = false;
            try { CruceConCve.CruzarAsync(apps, new NvdFalso(_ => new RespuestaHttp(200, NvdVacio)), (_, _) => Task.CompletedTask, () => DateTimeOffset.UnixEpoch, ct: cts.Token).GetAwaiter().GetResult(); }
            catch (OperationCanceledException) { cancelo = true; }
            Check(cancelo, "cancelar detiene el cruce (no devuelve un resultado a medias)");

            // Progreso.
            var avisos = new List<string>();
            CruceConCve.CruzarAsync(apps, new NvdFalso(_ => new RespuestaHttp(200, NvdVacio)), (_, _) => Task.CompletedTask, () => DateTimeOffset.UnixEpoch, new ListaDeProgreso(avisos)).GetAwaiter().GetResult();
            Check(avisos.Count == 2 && avisos[0].StartsWith("Consultando 1 de 2") && avisos[1].StartsWith("Consultando 2 de 2"), "el progreso cuenta solo lo que se consulta (2, no 3)", string.Join(" | ", avisos));
        }

        private sealed class NvdQueLanza : IConsultaNvd
        {
            public Task<RespuestaHttp> ConsultarCvesAsync(string cpe, CancellationToken ct) => throw new InvalidOperationException("boom");
        }

        private sealed class ListaDeProgreso : IProgress<string>
        {
            private readonly List<string> _l;
            public ListaDeProgreso(List<string> l) => _l = l;
            public void Report(string value) => _l.Add(value);
        }

        public static void ProbarCveAnalisis()
        {
            Console.WriteLine("19. Cruce con CVE: hallazgos");
            ResumenDeCruce ConUno(ResultadoDeCruce r) => new(new[] { r }, Array.Empty<AplicacionDesactualizada>());
            AplicacionDesactualizada wr = App("WinRAR 7.01", "RARLab.WinRAR", "7.01.0");

            ResultadoDeAnalisis real = CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, ParserDeNvd.Parsear(NvdReal(), PWinRar, "7.01").Cves)));
            HallazgoDeSistema h = real.Hallazgos.Single();
            Check(h.Id == "APP-CVE" && h.Severidad == Severidad.Alta && h.Sujeto == "WinRAR 7.01", "WinRAR real: un hallazgo Alta", h.Severidad + " " + h.Sujeto);
            Check(h.Titulo.StartsWith("3 fallos de seguridad conocidos") && h.Detalle.Contains("CVE-2025-8088") && h.Detalle.Contains("CVE-2025-6218") && h.Detalle.Contains("CVE-2025-31334"), "el titulo cuenta 3 y el detalle nombra los CVE", h.Titulo);
            Check(h.Detalle.Contains("ya se usa en ataques reales") && h.Detalle.Contains("(explotado)"), "avisa de los explotados");
            Check(h.Detalle.Contains("no prueba que te hayan atacado") && h.Recomendacion == "Actualiza: winget upgrade --id RARLab.WinRAR", "dice que existir el fallo no prueba un ataque y da la orden exacta para actualizar");
            Check(real.Completo, "con todo comprobado, el analisis es completo");

            // Un explotado de gravedad baja sube a Alta; sin explotar se queda en su gravedad.
            var baja = new[] { new CveEncontrado("CVE-2020-0001", 3.1, Explotada: true) };
            Check(CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, baja))).Hallazgos.Single().Severidad == Severidad.Alta, "un fallo de puntaje 3.1 pero EXPLOTADO sube a Alta");
            var baja2 = new[] { new CveEncontrado("CVE-2020-0001", 3.1, Explotada: false) };
            Check(CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, baja2))).Hallazgos.Single().Severidad == Severidad.Baja, "el mismo fallo sin explotar se queda en Baja");
            var critica = new[] { new CveEncontrado("CVE-2020-0002", 9.8, false), new CveEncontrado("CVE-2020-0003", 5.0, false) };
            Check(CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, critica))).Hallazgos.Single().Severidad == Severidad.Critica, "manda el peor: 9.8 es Critica");
            var muchos = Enumerable.Range(1, 9).Select(i => new CveEncontrado("CVE-2020-" + (1000 + i), 5.0, false)).ToList();
            HallazgoDeSistema hm = CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, muchos))).Hallazgos.Single();
            Check(hm.Titulo.StartsWith("9 fallos") && hm.Detalle.Contains("y 3 más"), "con muchos CVE el detalle muestra 6 y «y 3 más»", hm.Detalle);
            Check(CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, new[] { new CveEncontrado("CVE-2020-0001", 5, false) }))).Hallazgos.Single().Titulo.StartsWith("1 fallo de seguridad conocido en"), "con uno solo, singular");

            ResultadoDeAnalisis limpio = CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.SinFallosConocidos, Array.Empty<CveEncontrado>())));
            Check(limpio.Hallazgos.Single().Severidad == Severidad.Info && limpio.Completo && limpio.Hallazgos.Single().Titulo.Contains("Sin fallos conocidos en NVD") && limpio.Hallazgos.Single().Detalle.Contains("no es una garantía"), "sin fallos: Info, y el texto dice «no es una garantía»");
            Check(!limpio.Hallazgos.Single().Titulo.Contains("seguro", StringComparison.OrdinalIgnoreCase) && !limpio.Hallazgos.Single().Detalle.Contains("seguro ", StringComparison.OrdinalIgnoreCase), "nunca dice «seguro»");

            ResultadoDeAnalisis sinMapa = CruceConCve.Analizar(new ResumenDeCruce(Array.Empty<ResultadoDeCruce>(), Enumerable.Range(1, 10).Select(i => App("Programa " + i, "X.Y" + i, "1.0")).ToList()));
            Check(!sinMapa.Completo && sinMapa.NoEvaluado.Single().Contains("10 aplicación(es) no están en la lista") && sinMapa.NoEvaluado.Single().Contains("y 2 más"), "lo que no esta en el mapa se declara y el analisis queda incompleto");
            Check(!CruceConCve.Analizar(new ResumenDeCruce(Array.Empty<ResultadoDeCruce>(), Array.Empty<AplicacionDesactualizada>())).Completo, "sin nada que cruzar tampoco es «completo»");

            // Parcial: «al menos», con la explicacion.
            ResultadoDeAnalisis parcial = CruceConCve.Analizar(ConUno(new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, ParserDeNvd.Parsear(NvdReal(), PWinRar, "7.01").Cves, Parcial: true)));
            Check(parcial.Hallazgos.Single().Titulo.StartsWith("Al menos 3 fallos") && parcial.Hallazgos.Single().Detalle.Contains("Hay muchos más") && parcial.Hallazgos.Single().Detalle.Contains("2000"), "un resultado parcial dice «Al menos N» y que hay muchos mas", parcial.Hallazgos.Single().Titulo);

            // Orden: el peor primero.
            ResultadoDeAnalisis orden = CruceConCve.Analizar(new ResumenDeCruce(new[]
            {
                new ResultadoDeCruce(App("Git", "Git.Git", "2.54.0"), EstadoDeCruce.SinFallosConocidos, Array.Empty<CveEncontrado>()),
                new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, ParserDeNvd.Parsear(NvdReal(), PWinRar, "7.01").Cves)
            }, Array.Empty<AplicacionDesactualizada>()));
            Check(orden.Hallazgos[0].Id == "APP-CVE" && orden.Hallazgos[1].Id == "APP-CVE-NINGUNO", "los fallos van antes que las notas");
        }

        public static void ProbarCveHttp()
        {
            Console.WriteLine("20. Cruce con CVE: consulta HTTP");
            const string cpe = "cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*";
            var m = new ManejadorFalso(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(NvdVacio, Encoding.UTF8, "application/json") });
            using var http = new ConsultaNvdHttp(m);
            RespuestaHttp r = http.ConsultarCvesAsync(cpe, CancellationToken.None).GetAwaiter().GetResult();
            Check(r.Estado == 200 && r.Texto == NvdVacio, "un 200 devuelve el texto tal cual");
            HttpRequestMessage p = m.Peticiones.Single();
            Check(p.RequestUri!.Host == "services.nvd.nist.gov" && p.RequestUri.Scheme == "https" && p.RequestUri.AbsolutePath == "/rest/json/cves/2.0", "va al servidor fijo de NVD, por HTTPS, a la ruta de CVE", p.RequestUri.ToString());
            Check(p.RequestUri.Query.Contains("virtualMatchString=cpe%3A2.3%3Aa%3Ararlab%3Awinrar%3A7.01") && p.RequestUri.Query.Contains("resultsPerPage=2000"), "lleva el CPE escapado y pide hasta 2000 resultados", p.RequestUri.Query);
            Check(p.Method == HttpMethod.Get && p.Content is null, "es un GET sin cuerpo");
            Check(p.Headers.UserAgent.ToString() == "Nexo-Security-Suite" && p.Headers.Authorization is null && !p.Headers.Contains("apiKey") && !p.Headers.Contains("Cookie"), "se presenta con un nombre generico, sin cuenta, clave ni cookies (nada del usuario)", p.Headers.UserAgent.ToString());

            foreach (string mal in new[]
            {
                "", "cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*&apiKey=x", "cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*:*#", "cpe:2.3:a:rarlab:winrar:7.01\n:*:*:*:*:*:*:*",
                "cpe:2.3:a:rar lab:winrar:7.01:*:*:*:*:*:*:*", "cpe:2.3:h:rarlab:winrar:7.01:*:*:*:*:*:*:*", "cpe:2.3:a:rarlab:winrar:7.01:*:*:*:*:*:*", "https://evil.example/", "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:rarlab:winrar:7.01:a:*:*:*:*:*:*"
            })
            {
                bool lanzo = false;
                try { http.ConsultarCvesAsync(mal, CancellationToken.None).GetAwaiter().GetResult(); } catch (ArgumentException) { lanzo = true; }
                Check(lanzo, "un CPE que no tiene la forma esperada se rechaza ANTES de salir: " + Recorte(mal.Replace("\n", "\\n")));
            }
            Check(m.Peticiones.Count == 1, "los CPE rechazados no hicieron ninguna peticion");

            RespuestaHttp Con(Func<HttpRequestMessage, HttpResponseMessage> f)
            {
                using var h = new ConsultaNvdHttp(new ManejadorFalso(f));
                return h.ConsultarCvesAsync(cpe, CancellationToken.None).GetAwaiter().GetResult();
            }
            Check(Con(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests)).Estado == 429, "un 429 se devuelve como 429");
            Check(Con(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)).Estado == 403, "un 403 se devuelve como 403");
            Check(Con(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)).Estado == 503, "un 503 se devuelve como 503");
            RespuestaHttp redir = Con(_ => { var x = new HttpResponseMessage(HttpStatusCode.MovedPermanently); x.Headers.Location = new Uri("https://evil.example/"); return x; });
            Check(redir.Estado == 301 && redir.Texto == "", "una redireccion NO se sigue ni se lee: queda como 301 sin texto");
            RespuestaHttp grande = Con(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('x', ParserDeNvd.MaximoDeCaracteres + 10)) });
            Check(grande.Estado is null && grande.Error!.Contains("demasiado grande"), "una respuesta mayor que el tope se corta y se declara fallo", grande.Estado + " / " + grande.Error);
            using (var sinRed = new ConsultaNvdHttp(new ManejadorQueFalla()))
            {
                RespuestaHttp f = sinRed.ConsultarCvesAsync(cpe, CancellationToken.None).GetAwaiter().GetResult();
                Check(f.Estado is null && !string.IsNullOrWhiteSpace(f.Error), "sin red: estado nulo y motivo", f.Error);
            }
            using (var lento = new ConsultaNvdHttp(new ManejadorLento(), TimeSpan.FromMilliseconds(150)))
            {
                RespuestaHttp f = lento.ConsultarCvesAsync(cpe, CancellationToken.None).GetAwaiter().GetResult();
                Check(f.Estado is null && f.Error!.Contains("tiempo"), "un servidor que no contesta se corta por tiempo", f.Error);
            }
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            bool cancelo = false;
            try { new ConsultaNvdHttp(new ManejadorLento()).ConsultarCvesAsync(cpe, cts.Token).GetAwaiter().GetResult(); } catch (OperationCanceledException) { cancelo = true; }
            Check(cancelo, "si el usuario cancela, se propaga la cancelacion (no se confunde con «tiempo agotado»)");
        }

        private sealed class ManejadorLento : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
        }

        public static void ProbarCveTextos()
        {
            Console.WriteLine("21. Cruce con CVE: textos con tildes");
            var textos = new List<string>();
            AplicacionDesactualizada wr = App("WinRAR 7.01", "RARLab.WinRAR", "7.01.0");
            var todos = new ResumenDeCruce(new[]
            {
                new ResultadoDeCruce(wr, EstadoDeCruce.ConFallos, ParserDeNvd.Parsear(NvdReal(), PWinRar, "7.01").Cves),
                new ResultadoDeCruce(App("Git", "Git.Git", "2.54.0"), EstadoDeCruce.SinFallosConocidos, Array.Empty<CveEncontrado>()),
                new ResultadoDeCruce(App("A", "RARLab.WinRAR", "1.0"), EstadoDeCruce.NoSePudoComprobar, Array.Empty<CveEncontrado>(), "no hubo conexión con NVD"),
                new ResultadoDeCruce(App("B", "RARLab.WinRAR", "1.0"), EstadoDeCruce.NoSePudoComprobar, Array.Empty<CveEncontrado>(), "NVD limitó las consultas (código 429): Nexo dejó de preguntar; vuelve a intentarlo en unos minutos")
            }, Enumerable.Range(1, 10).Select(i => App("P" + i, "X.Y" + i, "1.0")).ToList());
            textos.AddRange(TextosDe(CruceConCve.Analizar(todos)));
            textos.AddRange(TextosDe(CruceConCve.Analizar(new ResumenDeCruce(Array.Empty<ResultadoDeCruce>(), Array.Empty<AplicacionDesactualizada>()))));

            // Los motivos que fabrica el propio cruce (no los que se pasan a mano arriba).
            foreach (RespuestaHttp r in new[] { new RespuestaHttp(null, "", "SocketException"), new RespuestaHttp(403, ""), new RespuestaHttp(429, ""), new RespuestaHttp(500, ""), new RespuestaHttp(200, "{}"), new RespuestaHttp(200, NvdReal().Substring(0, 3000)) })
                textos.AddRange(TextosDe(CruceConCve.Analizar(Cruzar(new[] { wr }, new NvdFalso(_ => r)))));
            textos.AddRange(TextosDe(CruceConCve.Analizar(Cruzar(new[] { App("Git", "Git.Git", "Unknown") }, new NvdFalso(_ => new RespuestaHttp(200, NvdVacio))))));

            Check(textos.Count > 15, "se recorrieron los textos del cruce en todos sus casos (" + textos.Count + " textos)", textos.Count.ToString());
            var malos = new SortedSet<string>(StringComparer.Ordinal);
            foreach (string t in textos)
                foreach (Match m in Palabra.Matches(t))
                    if (Array.IndexOf(SinTilde, m.Value.ToLowerInvariant()) >= 0 && !(m.Value.Length > 1 && m.Value == m.Value.ToUpperInvariant()))
                        malos.Add(m.Value + "  →  «" + Resumen(t, m.Index) + "»");
            Check(malos.Count == 0, "ningún texto del cruce contiene una palabra sin su tilde", string.Join(" | ", malos.Take(8)));
            Check(!textos.Any(t => Regex.IsMatch(t, @"\b(the|and|error|failed|rate limit)\b", RegexOptions.IgnoreCase)), "ningún texto del cruce tiene palabras en inglés sueltas");
        }
    }
}
