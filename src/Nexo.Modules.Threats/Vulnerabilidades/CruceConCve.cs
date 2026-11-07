using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    /// <summary>Un producto tal como lo nombra la base de CPE de NVD. <see cref="QuitarCerosFinales"/>: winget da «7.01.0» y NVD «7.01».</summary>
    public sealed record ProductoCpe(string Proveedor, string Producto, bool QuitarCerosFinales = false);

    /// <summary>
    /// Mapa CURADO de ids de winget a productos CPE. Solo entran programas cuyo CPE se comprobo contra NVD con una version vieja
    /// conocida (debe devolver CVE): un CPE mal escrito devolveria «cero fallos» y eso se leeria como «limpio». Lo que no esta aqui
    /// NO se cruza y se declara «no comprobado». Java no esta (winget da «8.0.4010.10», NVD «1.8.0:update_401»: la traduccion no es fiable).
    /// </summary>
    public static class MapaDeProductos
    {
        private static readonly (string Prefijo, ProductoCpe Cpe)[] Entradas =
        {
            ("RARLab.WinRAR", new ProductoCpe("rarlab", "winrar", QuitarCerosFinales: true)),
            ("7zip.7zip", new ProductoCpe("7-zip", "7-zip")),
            ("Google.Chrome", new ProductoCpe("google", "chrome")),
            ("Mozilla.Firefox", new ProductoCpe("mozilla", "firefox")),
            ("Microsoft.Edge", new ProductoCpe("microsoft", "edge_chromium")),
            ("VideoLAN.VLC", new ProductoCpe("videolan", "vlc_media_player")),
            ("Git.Git", new ProductoCpe("git-scm", "git")),
            ("OpenJS.NodeJS", new ProductoCpe("nodejs", "node.js"))
        };

        /// <summary>Entradas para las pruebas y la comprobacion real.</summary>
        public static IReadOnlyList<(string Prefijo, ProductoCpe Cpe)> Todas => Entradas;

        public static ProductoCpe? Buscar(string idWinget)
        {
            if (string.IsNullOrWhiteSpace(idWinget)) return null;
            foreach ((string prefijo, ProductoCpe cpe) in Entradas)
            {
                // Prefijo exacto o seguido de punto (Mozilla.Firefox.es-ES, OpenJS.NodeJS.LTS); nunca «Git.GitHub...» por empezar igual.
                if (idWinget.Equals(prefijo, StringComparison.OrdinalIgnoreCase)
                    || (idWinget.Length > prefijo.Length && idWinget.StartsWith(prefijo, StringComparison.OrdinalIgnoreCase) && idWinget[prefijo.Length] == '.'))
                    return cpe;
            }
            return null;
        }

        /// <summary>
        /// La version de winget en el formato de NVD, o null si no es fiable. Solo se aceptan versiones puramente numericas de 2 a 4
        /// partes: «&lt; 175.1», «Unknown», «1.0-beta» o «8.0.4010.10» de Java NO se adivinan.
        /// </summary>
        public static string? NormalizarVersion(ProductoCpe p, string? versionWinget)
        {
            string v = (versionWinget ?? "").Trim();
            if (!Regex.IsMatch(v, @"^[0-9]{1,6}(\.[0-9]{1,6}){1,3}\z", RegexOptions.CultureInvariant)) return null;
            if (p.QuitarCerosFinales)
            {
                var partes = v.Split('.').ToList();
                while (partes.Count > 2 && partes[^1] == "0") partes.RemoveAt(partes.Count - 1);
                v = string.Join('.', partes);
            }
            return v;
        }

        public static string Cpe(ProductoCpe p, string version)
            => "cpe:2.3:a:" + p.Proveedor + ":" + p.Producto + ":" + version + ":*:*:*:*:*:*:*";
    }

    /// <summary>Un fallo conocido (CVE). <see cref="Puntaje"/> null = NVD no lo ha puntuado todavia.</summary>
    public sealed record CveEncontrado(string Id, double? Puntaje, bool Explotada)
    {
        /// <summary>Gravedad segun el puntaje CVSS; sin puntaje se trata como Media (no se esconde).</summary>
        public Severidad Gravedad => Puntaje switch
        {
            null => Severidad.Media,
            >= 9.0 => Severidad.Critica,
            >= 7.0 => Severidad.Alta,
            >= 4.0 => Severidad.Media,
            > 0 => Severidad.Baja,
            _ => Severidad.Info
        };
    }

    /// <summary>
    /// <see cref="Parcial"/>: NVD tiene mas coincidencias de las que cupieron en la pagina pedida (productos muy atacados, version vieja):
    /// <see cref="Cves"/> son solo las de esa pagina. <see cref="Descartados"/>: CVE que NVD devolvio pero NO afectan a este producto y
    /// version (p. ej. un fallo de Next.js que solo lista Node.js como plataforma donde corre).
    /// </summary>
    public sealed record RespuestaDeNvdLeida(bool Reconocida, string? Motivo, IReadOnlyList<CveEncontrado> Cves, bool Parcial = false, int Descartados = 0);

    /// <summary>
    /// Lee la respuesta JSON de <c>/rest/json/cves/2.0</c> de NVD. Estricto: si falta algo esperado, el recuento no cuadra con
    /// <c>totalResults</c> (respuesta paginada o cortada) o un CVE no tiene un id valido, la respuesta NO se reconoce, y una respuesta
    /// no reconocida nunca equivale a «sin fallos». Los CVE «Rejected» (retirados) no cuentan.
    /// NVD devuelve tambien CVE que solo MENCIONAN al producto como plataforma (<c>vulnerable: false</c>): un CVE solo cuenta si algun
    /// <c>cpeMatch</c> con <c>vulnerable: true</c> es de ESTE producto y su rango de versiones incluye la instalada.
    /// </summary>
    public static class ParserDeNvd
    {
        public const int MaximoDeCaracteres = 8 * 1024 * 1024;
        private static readonly Regex IdCve = new Regex(@"^CVE-[0-9]{4}-[0-9]{4,}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static RespuestaDeNvdLeida Parsear(string? json, ProductoCpe producto, string version)
        {
            if (string.IsNullOrWhiteSpace(json)) return No("la respuesta de NVD llegó vacía");
            if (json.Length > MaximoDeCaracteres) return No("la respuesta de NVD es demasiado grande");
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
                JsonElement raiz = doc.RootElement;
                if (raiz.ValueKind != JsonValueKind.Object) return No("la respuesta de NVD no tiene la forma esperada");
                if (!raiz.TryGetProperty("totalResults", out JsonElement total) || total.ValueKind != JsonValueKind.Number || !total.TryGetInt32(out int esperados) || esperados < 0)
                    return No("a la respuesta de NVD le falta el recuento total");
                if (!raiz.TryGetProperty("vulnerabilities", out JsonElement lista) || lista.ValueKind != JsonValueKind.Array)
                    return No("a la respuesta de NVD le falta la lista de fallos");
                int recibidos = lista.GetArrayLength();
                bool parcial = false;
                if (recibidos != esperados)
                {
                    // Solo es una pagina legitima si NVD declara una pagina inicial llena; cualquier otro desajuste es una respuesta cortada.
                    bool paginaLlena = esperados > recibidos && recibidos > 0
                        && raiz.TryGetProperty("startIndex", out JsonElement ini) && ini.ValueKind == JsonValueKind.Number && ini.TryGetInt32(out int i0) && i0 == 0
                        && raiz.TryGetProperty("resultsPerPage", out JsonElement rpp) && rpp.ValueKind == JsonValueKind.Number && rpp.TryGetInt32(out int n) && n == recibidos;
                    if (!paginaLlena)
                        return No("NVD dice " + esperados + " fallo(s) pero la respuesta trae " + recibidos + " (respuesta cortada)");
                    parcial = true;
                }

                var cves = new List<CveEncontrado>();
                int descartados = 0;
                foreach (JsonElement item in lista.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("cve", out JsonElement c) || c.ValueKind != JsonValueKind.Object
                        || !c.TryGetProperty("id", out JsonElement id) || id.ValueKind != JsonValueKind.String || !IdCve.IsMatch(id.GetString() ?? ""))
                        return No("un fallo de la respuesta de NVD no tiene un identificador válido");
                    if (c.TryGetProperty("vulnStatus", out JsonElement st) && st.ValueKind == JsonValueKind.String
                        && string.Equals(st.GetString(), "Rejected", StringComparison.OrdinalIgnoreCase)) continue;

                    if (!Afecta(c, producto, version)) { descartados++; continue; }

                    bool explotada = c.TryGetProperty("cisaExploitAdd", out JsonElement kev) && kev.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(kev.GetString());
                    cves.Add(new CveEncontrado(id.GetString()!, Puntaje(c), explotada));
                }
                return new RespuestaDeNvdLeida(true, null, cves, parcial, descartados);
            }
            catch (JsonException) { return No("la respuesta de NVD no es JSON válido"); }
        }

        /// <summary>
        /// ¿Algun <c>cpeMatch</c> vulnerable de este CVE es del producto y cubre la version? Sin <c>configurations</c> no se puede
        /// afirmar nada: no cuenta. Un rango que no se puede comparar (version rara) cuenta (NVD ya lo emparejo con la nuestra).
        /// </summary>
        private static bool Afecta(JsonElement cve, ProductoCpe p, string version)
        {
            if (!cve.TryGetProperty("configurations", out JsonElement configs) || configs.ValueKind != JsonValueKind.Array) return false;
            string prefijo = "cpe:2.3:a:" + p.Proveedor + ":" + p.Producto + ":";
            foreach (JsonElement cfg in configs.EnumerateArray())
            {
                if (cfg.ValueKind != JsonValueKind.Object || !cfg.TryGetProperty("nodes", out JsonElement nodos) || nodos.ValueKind != JsonValueKind.Array) continue;
                foreach (JsonElement nodo in nodos.EnumerateArray())
                {
                    if (nodo.ValueKind != JsonValueKind.Object || !nodo.TryGetProperty("cpeMatch", out JsonElement matches) || matches.ValueKind != JsonValueKind.Array) continue;
                    foreach (JsonElement m in matches.EnumerateArray())
                    {
                        if (m.ValueKind != JsonValueKind.Object) continue;
                        if (!m.TryGetProperty("vulnerable", out JsonElement vul) || vul.ValueKind != JsonValueKind.True) continue;
                        if (!m.TryGetProperty("criteria", out JsonElement cr) || cr.ValueKind != JsonValueKind.String) continue;
                        string criterio = (cr.GetString() ?? "").ToLowerInvariant();
                        if (!criterio.StartsWith(prefijo, StringComparison.Ordinal)) continue;
                        string[] partes = criterio.Split(':');
                        if (partes.Length < 6) continue;
                        if (VersionEnRango(m, partes[5], version)) return true;
                    }
                }
            }
            return false;
        }

        private static bool VersionEnRango(JsonElement m, string versionDelCriterio, string version)
        {
            if (versionDelCriterio != "*" && versionDelCriterio != "-")
                return Comparar(version, versionDelCriterio) is not int exacto || exacto == 0;
            if (versionDelCriterio == "-") return false; // «no aplica»: no nombra una version concreta

            string? Limite(string nombre) => m.TryGetProperty(nombre, out JsonElement e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            string? ini = Limite("versionStartIncluding"), iniEx = Limite("versionStartExcluding"), fin = Limite("versionEndIncluding"), finEx = Limite("versionEndExcluding");
            bool Cumple(string? limite, Func<int, bool> regla) => limite is null || Comparar(version, limite) is not int c || regla(c);
            return Cumple(ini, c => c >= 0) && Cumple(iniEx, c => c > 0) && Cumple(fin, c => c <= 0) && Cumple(finEx, c => c < 0);
        }

        /// <summary>Compara dos versiones numericas con puntos («7.01» contra «7.1.0»); null si alguna no es puramente numerica.</summary>
        public static int? Comparar(string a, string b)
        {
            long[]? x = Partes(a), y = Partes(b);
            if (x is null || y is null) return null;
            for (int i = 0; i < Math.Max(x.Length, y.Length); i++)
            {
                long u = i < x.Length ? x[i] : 0, v = i < y.Length ? y[i] : 0;
                if (u != v) return u < v ? -1 : 1;
            }
            return 0;
        }

        private static long[]? Partes(string v)
        {
            if (!Regex.IsMatch(v, @"^[0-9]{1,9}(\.[0-9]{1,9}){0,5}\z", RegexOptions.CultureInvariant)) return null;
            return v.Split('.').Select(t => long.Parse(t, CultureInfo.InvariantCulture)).ToArray();
        }

        /// <summary>El puntaje CVSS: prefiere la medicion Primaria (la del propio NVD) y, entre iguales, la version mas nueva de CVSS.</summary>
        private static double? Puntaje(JsonElement cve)
        {
            if (!cve.TryGetProperty("metrics", out JsonElement m) || m.ValueKind != JsonValueKind.Object) return null;
            double? mejor = null;
            bool mejorPrimaria = false;
            foreach (string clave in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
            {
                if (!m.TryGetProperty(clave, out JsonElement arr) || arr.ValueKind != JsonValueKind.Array) continue;
                foreach (JsonElement e in arr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty("cvssData", out JsonElement d) || d.ValueKind != JsonValueKind.Object
                        || !d.TryGetProperty("baseScore", out JsonElement s) || s.ValueKind != JsonValueKind.Number || !s.TryGetDouble(out double p) || p < 0 || p > 10) continue;
                    bool primaria = e.TryGetProperty("type", out JsonElement t) && t.ValueKind == JsonValueKind.String && t.GetString() == "Primary";
                    // La primera medicion valida de la lista (version mas nueva) solo la reemplaza una Primaria cuando la guardada no lo era.
                    if (mejor is null || (primaria && !mejorPrimaria)) { mejor = p; mejorPrimaria = primaria; }
                }
            }
            return mejor;
        }

        private static RespuestaDeNvdLeida No(string motivo) => new(false, motivo, Array.Empty<CveEncontrado>());
    }

    /// <summary>Lo que devolvio el servidor: el codigo HTTP (null = no hubo respuesta) y el texto. <see cref="Error"/> explica un fallo de red.</summary>
    public sealed record RespuestaHttp(int? Estado, string Texto, string? Error = null);

    /// <summary>De donde salen las consultas a NVD. La implementacion real esta en Nexo.Modules.Threats.Windows; las pruebas usan una falsa.</summary>
    public interface IConsultaNvd
    {
        Task<RespuestaHttp> ConsultarCvesAsync(string cpe, CancellationToken ct);
    }

    public enum EstadoDeCruce
    {
        ConFallos,
        SinFallosConocidos,
        NoSePudoComprobar
    }

    /// <summary><see cref="Parcial"/>: hay mas fallos de los que se leyeron (ver <see cref="RespuestaDeNvdLeida.Parcial"/>); el recuento es «al menos».</summary>
    public sealed record ResultadoDeCruce(AplicacionDesactualizada App, EstadoDeCruce Estado, IReadOnlyList<CveEncontrado> Cves, string? Motivo = null, bool Parcial = false);

    /// <summary><see cref="SinMapa"/>: aplicaciones que Nexo no sabe cruzar (no estan en el mapa curado). No se consultaron.</summary>
    public sealed record ResumenDeCruce(IReadOnlyList<ResultadoDeCruce> Resultados, IReadOnlyList<AplicacionDesactualizada> SinMapa);

    /// <summary>
    /// Cruza las aplicaciones con los fallos conocidos de NVD (gratuito, sin cuenta). Reglas de honestidad:
    ///  - «Sin fallos conocidos» SOLO si el producto esta en el mapa curado, la version se pudo traducir con certeza, el servidor
    ///    contesto 200 y la respuesta se leyo entera. Cualquier otra cosa es «no se pudo comprobar» con su motivo.
    ///  - Solo salen el nombre del producto y la version (nada del usuario ni del equipo).
    ///  - Sin clave NVD permite ~5 consultas por 30 s: se espacian (<see cref="SeparacionPorOmision"/>) y, ante 403/429, se PARA
    ///    (no se insiste); lo que quedo sin consultar se declara «no comprobado».
    /// </summary>
    public static class CruceConCve
    {
        public static readonly TimeSpan SeparacionPorOmision = TimeSpan.FromSeconds(7);

        public static async Task<ResumenDeCruce> CruzarAsync(
            IReadOnlyList<AplicacionDesactualizada> apps,
            IConsultaNvd nvd,
            Func<TimeSpan, CancellationToken, Task> esperar,
            Func<DateTimeOffset> reloj,
            IProgress<string>? progreso = null,
            TimeSpan? separacion = null,
            CancellationToken ct = default)
        {
            if (apps is null) throw new ArgumentNullException(nameof(apps));
            TimeSpan minimo = separacion ?? SeparacionPorOmision;
            var resultados = new List<ResultadoDeCruce>();
            var sinMapa = new List<AplicacionDesactualizada>();
            var cache = new Dictionary<string, ResultadoDeCruce>(StringComparer.Ordinal); // mismo CPE = una sola consulta
            DateTimeOffset? ultima = null;
            string? bloqueo = null; // motivo por el que se dejo de consultar

            var pendientes = new List<(AplicacionDesactualizada App, ProductoCpe Producto)>();
            foreach (AplicacionDesactualizada a in apps)
            {
                ProductoCpe? p = MapaDeProductos.Buscar(a.Id);
                if (p is null) sinMapa.Add(a); else pendientes.Add((a, p));
            }

            int hechas = 0;
            foreach ((AplicacionDesactualizada app, ProductoCpe producto) in pendientes)
            {
                ct.ThrowIfCancellationRequested();
                hechas++;
                progreso?.Report("Consultando " + hechas + " de " + pendientes.Count + ": " + app.Nombre);

                string? version = MapaDeProductos.NormalizarVersion(producto, app.VersionInstalada);
                if (version is null)
                {
                    resultados.Add(new ResultadoDeCruce(app, EstadoDeCruce.NoSePudoComprobar, Array.Empty<CveEncontrado>(),
                        "la versión «" + app.VersionInstalada + "» no se puede traducir con certeza al formato de NVD"));
                    continue;
                }
                if (bloqueo is not null)
                {
                    resultados.Add(new ResultadoDeCruce(app, EstadoDeCruce.NoSePudoComprobar, Array.Empty<CveEncontrado>(), bloqueo));
                    continue;
                }

                string cpe = MapaDeProductos.Cpe(producto, version);
                if (cache.TryGetValue(cpe, out ResultadoDeCruce? previo)) { resultados.Add(previo with { App = app }); continue; }

                if (ultima is DateTimeOffset u)
                {
                    TimeSpan falta = minimo - (reloj() - u);
                    if (falta > TimeSpan.Zero) await esperar(falta, ct).ConfigureAwait(false);
                }

                RespuestaHttp r;
                try { r = await nvd.ConsultarCvesAsync(cpe, ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    r = new RespuestaHttp(null, "", "error inesperado (" + ex.GetType().Name + ")");
                }
                ultima = reloj();

                ResultadoDeCruce res = Interpretar(app, r, producto, version, out bool parar);
                if (parar) bloqueo = res.Motivo;
                else cache[cpe] = res;
                resultados.Add(res);
            }

            return new ResumenDeCruce(resultados, sinMapa);
        }

        private static ResultadoDeCruce Interpretar(AplicacionDesactualizada app, RespuestaHttp r, ProductoCpe producto, string version, out bool parar)
        {
            parar = false;
            if (r.Estado is null)
                return NoComprobada(app, "no hubo conexión con NVD" + (string.IsNullOrWhiteSpace(r.Error) ? "" : " (" + r.Error + ")"));
            if (r.Estado is 403 or 429)
            {
                parar = true;
                return NoComprobada(app, "NVD limitó las consultas (código " + r.Estado + "): Nexo dejó de preguntar; vuelve a intentarlo en unos minutos");
            }
            if (r.Estado != 200)
                return NoComprobada(app, "NVD respondió con el código " + r.Estado);

            RespuestaDeNvdLeida l = ParserDeNvd.Parsear(r.Texto, producto, version);
            if (!l.Reconocida) return NoComprobada(app, l.Motivo ?? "respuesta ilegible de NVD");
            if (l.Cves.Count > 0)
                return new ResultadoDeCruce(app, EstadoDeCruce.ConFallos, l.Cves.OrderByDescending(c => c.Explotada).ThenByDescending(c => c.Puntaje ?? 10).ThenBy(c => c.Id, StringComparer.Ordinal).ToList(), Parcial: l.Parcial);
            // Pagina llena y ningun fallo que afecte de verdad: lo que quedo sin leer podria tenerlos, asi que no se puede decir «sin fallos».
            if (l.Parcial)
                return NoComprobada(app, "NVD tiene demasiadas coincidencias para esta versión y las primeras no afectan a este programa");
            return new ResultadoDeCruce(app, EstadoDeCruce.SinFallosConocidos, Array.Empty<CveEncontrado>());
        }

        private static ResultadoDeCruce NoComprobada(AplicacionDesactualizada app, string motivo)
            => new(app, EstadoDeCruce.NoSePudoComprobar, Array.Empty<CveEncontrado>(), motivo);

        /// <summary>Convierte el cruce en hallazgos del mismo tipo que el resto de revisiones.</summary>
        public static ResultadoDeAnalisis Analizar(ResumenDeCruce c)
        {
            if (c is null) throw new ArgumentNullException(nameof(c));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();

            foreach (ResultadoDeCruce r in c.Resultados)
            {
                switch (r.Estado)
                {
                    case EstadoDeCruce.ConFallos:
                    {
                        bool explotada = r.Cves.Any(x => x.Explotada);
                        Severidad max = r.Cves.Select(x => x.Gravedad).Max();
                        // Un fallo que ya se usa en ataques reales (lista CISA) sube a Alta como minimo, aunque su puntaje sea menor.
                        if (explotada && max < Severidad.Alta) max = Severidad.Alta;
                        string ids = string.Join(", ", r.Cves.Take(6).Select(x => x.Id + (x.Explotada ? " (explotado)" : "")))
                                     + (r.Cves.Count > 6 ? " y " + (r.Cves.Count - 6) + " más" : "");
                        hallazgos.Add(new HallazgoDeSistema("APP-CVE", max,
                            (r.Parcial ? "Al menos " + r.Cves.Count + " fallos de seguridad conocidos" : r.Cves.Count + (r.Cves.Count == 1 ? " fallo de seguridad conocido" : " fallos de seguridad conocidos")) + " en tu versión",
                            r.App.Nombre + " " + r.App.VersionInstalada + ": " + ids + "." + (r.Parcial ? " Hay muchos más: NVD tiene demasiadas coincidencias y Nexo solo leyó las primeras 2000 (aquí van los más graves de ellas)." : "") + (explotada ? " Al menos uno figura en la lista de fallos explotados de CISA: ya se usa en ataques reales." : "") +
                            " Según la base pública NVD; que exista el fallo no prueba que te hayan atacado.",
                            "Actualiza: winget upgrade --id " + r.App.Id, r.App.Nombre));
                        break;
                    }
                    case EstadoDeCruce.SinFallosConocidos:
                        hallazgos.Add(new HallazgoDeSistema("APP-CVE-NINGUNO", Severidad.Info, "Sin fallos conocidos en NVD para tu versión",
                            r.App.Nombre + " " + r.App.VersionInstalada + ": NVD no lista fallos para esta versión. Esto no es una garantía: solo cuenta lo ya publicado.",
                            "Nada que hacer.", r.App.Nombre));
                        break;
                    default:
                        noEvaluado.Add(r.App.Nombre + " " + r.App.VersionInstalada + ": no se pudo comprobar (" + r.Motivo + ").");
                        break;
                }
            }

            if (c.SinMapa.Count > 0)
                noEvaluado.Add(c.SinMapa.Count + " aplicación(es) no están en la lista que Nexo sabe cruzar y no se consultaron: "
                               + string.Join(", ", c.SinMapa.Take(8).Select(a => a.Nombre)) + (c.SinMapa.Count > 8 ? " y " + (c.SinMapa.Count - 8) + " más" : "") + ".");
            if (c.Resultados.Count == 0 && c.SinMapa.Count == 0)
                noEvaluado.Add("no había aplicaciones que cruzar.");

            return new ResultadoDeAnalisis(
                hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Sujeto, StringComparer.Ordinal).ToList(),
                noEvaluado);
        }
    }
}
