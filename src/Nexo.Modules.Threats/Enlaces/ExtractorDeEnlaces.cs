using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Enlaces
{
    public enum OrigenDelEnlace
    {
        /// <summary>Escrito con «http://» o «https://».</summary>
        ConEsquema,
        /// <summary>Empieza por «www.» sin esquema.</summary>
        ConWww,
        /// <summary>Solo el nombre del sitio («correos-cl.top/pago»), como suelen venir en los SMS.</summary>
        SoloDominio
    }

    public sealed record EnlaceEncontrado(string Texto, int Posicion, OrigenDelEnlace Origen);

    public sealed record ExtraccionDeEnlaces(IReadOnlyList<EnlaceEncontrado> Enlaces, bool TextoRecortado, bool DemasiadosEnlaces);

    /// <summary>
    /// Saca los enlaces de un texto pegado (un SMS, un correo, un mensaje de WhatsApp). Reconoce tres formas: con «http(s)://», con
    /// «www.», y el nombre del sitio solo, que es lo habitual en los SMS de estafa. Para no tomar por enlace cualquier palabra con punto
    /// («p.ej.», «EE.UU.»), un nombre suelo solo cuenta si termina en una terminacion real de la lista de IANA (embebida, sin red).
    /// Lo que no tenga ninguna de esas formas no se reconoce: la ventana lo dice.
    /// </summary>
    public static class ExtractorDeEnlaces
    {
        public const int MaximoDeCaracteres = 20_000;
        public const int MaximoDeEnlaces = 50;

        private const string Fin = @"[^\s<>""'«»“”‘’]";

        // Una sola expresion con tres alternativas, en orden de preferencia: si empieza por http, gana esa; si no, www; si no, el nombre suelto.
        private static readonly Regex Candidatos = new Regex(
            @"(?<esquema>(?<![\p{L}\p{N}])https?://" + Fin + @"+)" +
            @"|(?<www>(?<![\p{L}\p{N}@._/-])www\." + Fin + @"+)" +
            @"|(?<dominio>(?<![\p{L}\p{N}@._/-])(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+(?<tld>\p{L}{2,24}|xn--[a-z0-9-]{1,59})(?![\p{L}\p{N}_@-])(?::[0-9]{1,5})?(?:[/?#]" + Fin + @"*)?)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));

        private static readonly Lazy<HashSet<string>> Terminaciones = new(CargarTerminaciones);

        /// <summary>La lista oficial de terminaciones de IANA (<c>tlds-alpha-by-domain.txt</c>), embebida. En minusculas y ASCII.</summary>
        public static IReadOnlySet<string> TerminacionesConocidas => Terminaciones.Value;

        public static bool EsTerminacionConocida(string tld)
        {
            if (string.IsNullOrEmpty(tld)) return false;
            string t = tld.ToLowerInvariant();
            if (!t.All(c => c < 128))
            {
                try { t = new IdnMapping().GetAscii(t).ToLowerInvariant(); }
                catch (ArgumentException) { return false; }
            }
            return Terminaciones.Value.Contains(t);
        }

        public static ExtraccionDeEnlaces Extraer(string? texto)
        {
            if (string.IsNullOrEmpty(texto)) return new ExtraccionDeEnlaces(Array.Empty<EnlaceEncontrado>(), false, false);
            bool recortado = texto.Length > MaximoDeCaracteres;
            string t = recortado ? texto.Substring(0, MaximoDeCaracteres) : texto;

            var enlaces = new List<EnlaceEncontrado>();
            var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool demasiados = false;
            MatchCollection ms;
            try { ms = Candidatos.Matches(t); _ = ms.Count; }
            catch (RegexMatchTimeoutException) { return new ExtraccionDeEnlaces(Array.Empty<EnlaceEncontrado>(), true, false); }

            foreach (Match m in ms)
            {
                OrigenDelEnlace origen = m.Groups["esquema"].Success ? OrigenDelEnlace.ConEsquema
                                       : m.Groups["www"].Success ? OrigenDelEnlace.ConWww
                                       : OrigenDelEnlace.SoloDominio;
                if (origen == OrigenDelEnlace.SoloDominio && !EsTerminacionConocida(m.Groups["tld"].Value)) continue;

                string limpio = QuitarPuntuacionFinal(m.Value);
                if (limpio.Length < 4) continue;
                if (!vistos.Add(limpio)) continue;
                if (enlaces.Count == MaximoDeEnlaces) { demasiados = true; break; }
                enlaces.Add(new EnlaceEncontrado(limpio, m.Index, origen));
            }
            return new ExtraccionDeEnlaces(enlaces, recortado, demasiados);
        }

        /// <summary>
        /// Quita lo que cierra la frase y no es parte del enlace: «visita bancoestado.cl.» o «(ver https://x.cl/a)». Un parentesis de
        /// cierre se queda si el enlace abrio uno (las direcciones de Wikipedia los llevan).
        /// </summary>
        public static string QuitarPuntuacionFinal(string s)
        {
            int fin = s.Length;
            while (fin > 0)
            {
                char c = s[fin - 1];
                if (".,;:!?¡¿'\"»”’>".IndexOf(c) >= 0) { fin--; continue; }
                if (c == ')' && Cuenta(s, '(', fin) < Cuenta(s, ')', fin)) { fin--; continue; }
                if (c == ']' && Cuenta(s, '[', fin) < Cuenta(s, ']', fin)) { fin--; continue; }
                if (c == '}' && Cuenta(s, '{', fin) < Cuenta(s, '}', fin)) { fin--; continue; }
                break;
            }
            return s.Substring(0, fin);
        }

        private static int Cuenta(string s, char c, int hasta)
        {
            int n = 0;
            for (int i = 0; i < hasta; i++) if (s[i] == c) n++;
            return n;
        }

        private static HashSet<string> CargarTerminaciones()
        {
            var r = new HashSet<string>(StringComparer.Ordinal);
            Assembly a = typeof(ExtractorDeEnlaces).Assembly;
            using Stream? s = a.GetManifestResourceStream("tlds-iana.txt");
            if (s is null) throw new InvalidOperationException("Falta la lista de terminaciones embebida (tlds-iana.txt).");
            using var lector = new StreamReader(s);
            string? linea;
            while ((linea = lector.ReadLine()) is not null)
            {
                linea = linea.Trim();
                if (linea.Length == 0 || linea[0] == '#') continue;
                r.Add(linea.ToLowerInvariant());
            }
            return r;
        }
    }

    /// <summary>
    /// Un enlace interpretado. <see cref="Sitio"/> es el nombre en ASCII y minusculas (con «xn--» si tenia letras no latinas), sin el
    /// punto final; <see cref="SitioLegible"/> es como lo veria una persona. <see cref="Clave"/> sirve para comparar direcciones
    /// completas: sitio + puerto (si no es el habitual) + ruta + consulta, sin esquema, sin «/» final y sin fragmento.
    /// </summary>
    public sealed record EnlaceNormalizado(
        string Original,
        OrigenDelEnlace Origen,
        string Sitio,
        string SitioLegible,
        bool EsIp,
        bool Cifrado,
        string? Usuario,
        bool PuertoRaro,
        int Puerto,
        bool NombreMalCodificado,
        string Clave);

    public static class NormalizadorDeEnlaces
    {
        /// <summary>Interpreta un enlace. Devuelve null y el motivo si no se puede (nombre invalido, esquema que no es web).</summary>
        public static EnlaceNormalizado? Normalizar(EnlaceEncontrado e, out string? motivo)
        {
            motivo = null;
            string texto = e.Origen == OrigenDelEnlace.ConEsquema ? e.Texto : "http://" + e.Texto;
            if (!Uri.TryCreate(texto, UriKind.Absolute, out Uri? u))
            {
                motivo = "no tiene la forma de una dirección web válida";
                return null;
            }
            if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)
            {
                motivo = "no es una dirección web (http o https)";
                return null;
            }
            bool esIp = u.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6;
            if (!esIp && u.HostNameType != UriHostNameType.Dns)
            {
                motivo = "el nombre del sitio no es válido";
                return null;
            }

            string sitio;
            try { sitio = u.IdnHost.ToLowerInvariant().TrimEnd('.'); }
            catch (UriFormatException) { motivo = "el nombre del sitio no es válido"; return null; }
            if (sitio.Length == 0) { motivo = "no tiene nombre de sitio"; return null; }

            string legible = sitio;
            bool malCodificado = false;
            if (!esIp && sitio.Contains("xn--", StringComparison.Ordinal))
            {
                try { legible = new IdnMapping().GetUnicode(sitio); }
                catch (ArgumentException) { malCodificado = true; }
            }

            string? usuario = string.IsNullOrEmpty(u.UserInfo) ? null : Uri.UnescapeDataString(u.UserInfo);
            bool puertoRaro = !u.IsDefaultPort;
            return new EnlaceNormalizado(e.Texto, e.Origen, sitio, legible, esIp, u.Scheme == Uri.UriSchemeHttps, usuario, puertoRaro, u.Port, malCodificado,
                ClaveDe(sitio, puertoRaro ? u.Port : null, u.AbsolutePath, u.Query));
        }

        public static string ClaveDe(string sitio, int? puerto, string ruta, string consulta)
        {
            string r = ruta.TrimEnd('/');
            return sitio + (puerto is int p ? ":" + p.ToString(CultureInfo.InvariantCulture) : "") + r + consulta;
        }
    }
}
