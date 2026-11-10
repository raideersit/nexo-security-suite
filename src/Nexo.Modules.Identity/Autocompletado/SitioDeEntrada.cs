using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace Nexo.Modules.Identity.Autocompletado
{
    /// <summary>La página donde se quiere rellenar, ya comprobada. <c>Motivo</c> no nulo = NO se rellena ahí.</summary>
    public sealed record PaginaParaRellenar(string? Host, string? Motivo)
    {
        public bool Valida => Motivo is null;
    }

    /// <summary>
    /// Decide si una entrada de la bóveda corresponde a la página que pide la contraseña. Es la parte que protege contra el phishing:
    /// «bancoestado.cl.verificar.top» NO es «bancoestado.cl», y una entrada sin sitio reconocible nunca se rellena sola.
    ///
    /// Reglas:
    ///  - Solo páginas https (en http la contraseña viajaría sin cifrar; tampoco se hace una excepción con localhost).
    ///  - La página coincide si su nombre ES el de la entrada o está DENTRO de él («accounts.github.com» para «github.com»). Al revés no:
    ///    una entrada de «login.banco.cl» no se rellena en «banco.cl».
    ///  - Se compara la forma ASCII (punycode): «аpple.com» con «а» cirílica es «xn--pple-43d.com», no «apple.com».
    ///  - La entrada no puede ser una terminación sola («com», «com.ar», «gob.cl»): coincidiría con miles de sitios.
    ///  - Una dirección IP solo coincide consigo misma.
    /// </summary>
    public static class SitioDeEntrada
    {
        /// <summary>
        /// Terminaciones de dos niveles en las que NO se puede guardar una entrada sola. Copia de Nexo.Modules.Threats.Enlaces.Dominios (Identity no
        /// depende de Threats): si se añade una allí, añadirla aquí. Más «gob.cl», que en Chile es una terminación de hecho.
        /// </summary>
        private static readonly HashSet<string> DosNiveles = new(StringComparer.Ordinal)
        {
            "co.uk", "org.uk", "gov.uk", "ac.uk", "com.ar", "gob.ar", "com.br", "gov.br", "net.br", "com.mx", "gob.mx", "com.pe", "gob.pe",
            "com.co", "gov.co", "com.uy", "com.ve", "com.ec", "com.bo", "com.py", "gob.cl", "com.au", "co.jp", "co.za", "com.es", "com.tr", "co.nz"
        };

        private static readonly IdnMapping Idn = new IdnMapping();

        /// <summary>
        /// El nombre de sitio de una entrada («github.com», «https://github.com/login», «www.GitHub.com/») en ASCII y minúsculas, sin «www.».
        /// null si no se reconoce un sitio («GitHub», «mi banco», una ruta de archivo): esa entrada no se rellena sola.
        /// </summary>
        public static string? HostDeEntrada(string? sitio)
        {
            if (string.IsNullOrWhiteSpace(sitio)) return null;
            string s = sitio.Trim();
            if (s.Any(char.IsWhiteSpace)) return null;
            if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
            if (!Uri.TryCreate(s, UriKind.Absolute, out Uri? u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp)) return null;
            if (!string.IsNullOrEmpty(u.UserInfo)) return null;          // «https://banco.cl@malo.top»: no se adivina cuál es el sitio
            string? host = Normalizar(u);
            if (host is null) return null;
            if (u.HostNameType == UriHostNameType.Dns)
            {
                if (host.StartsWith("www.", StringComparison.Ordinal)) host = host[4..];
                if (!host.Contains('.') || DosNiveles.Contains(host)) return null;   // «localhost», «com.ar»: no son un sitio
            }
            return host;
        }

        /// <summary>Comprueba la URL de la página que pide rellenar (la que da el navegador, no la que escribe nadie).</summary>
        public static PaginaParaRellenar AnalizarPagina(string? url)
        {
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out Uri? u))
                return new PaginaParaRellenar(null, "la dirección de la página no es válida");
            if (u.Scheme == Uri.UriSchemeHttp)
                return new PaginaParaRellenar(null, "la página no usa conexión cifrada (http): la contraseña viajaría a la vista");
            if (u.Scheme != Uri.UriSchemeHttps)
                return new PaginaParaRellenar(null, "solo se rellena en páginas web (https), no en «" + u.Scheme + ":»");
            if (!string.IsNullOrEmpty(u.UserInfo))
                return new PaginaParaRellenar(null, "la dirección lleva un usuario antes del sitio («…@…»), un truco típico de phishing");
            string? host = Normalizar(u);
            return host is null ? new PaginaParaRellenar(null, "no se reconoce el nombre del sitio") : new PaginaParaRellenar(host, null);
        }

        /// <summary>¿Se puede rellenar en <paramref name="hostPagina"/> la entrada de <paramref name="hostEntrada"/>? Ambos ya normalizados.</summary>
        public static bool Coincide(string hostPagina, string hostEntrada)
        {
            if (hostPagina.Length == 0 || hostEntrada.Length == 0) return false;
            if (hostPagina == hostEntrada) return true;
            if (IPAddress.TryParse(hostEntrada.Trim('[', ']'), out _) || IPAddress.TryParse(hostPagina.Trim('[', ']'), out _)) return false;
            return hostPagina.EndsWith("." + hostEntrada, StringComparison.Ordinal);
        }

        private static string? Normalizar(Uri u)
        {
            string h = u.Host.TrimEnd('.');
            if (h.Length == 0) return null;
            if (u.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6) return h.ToLowerInvariant();
            if (u.HostNameType != UriHostNameType.Dns) return null;
            try { return Idn.GetAscii(h).ToLowerInvariant(); }
            catch (ArgumentException) { return null; }
        }
    }
}
