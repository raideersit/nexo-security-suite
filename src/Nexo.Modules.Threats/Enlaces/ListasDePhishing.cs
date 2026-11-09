using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Enlaces
{
    public enum FuenteDeLista
    {
        /// <summary>
        /// Phishing Army (<c>phishing.army</c>): dominios de phishing recopilados de PhishTank, OpenPhish, CERT.PL y otras fuentes.
        /// Gratis para uso personal, sin cuenta. Trae en la cabecera cuantas entradas tiene y cuando se genero.
        /// </summary>
        PhishingArmy,
        /// <summary>
        /// El feed comunitario de OpenPhish (direcciones completas), publicado en GitHub. Gratis para uso no comercial, sin cuenta.
        /// Se actualiza cada 12 horas.
        /// </summary>
        OpenPhish
    }

    /// <summary>
    /// Una lista ya leida y validada. <see cref="Generada"/> es la fecha que declara la propia lista (si la declara y es creible);
    /// <see cref="Descargada"/> es cuando la bajo Nexo. Para la antiguedad manda la mas vieja de las dos.
    /// </summary>
    public sealed class ListaCargada
    {
        public ListaCargada(FuenteDeLista fuente, DateTimeOffset? generada, DateTimeOffset descargada, int entradas,
                            IReadOnlySet<string> dominios, IReadOnlySet<string> direcciones, IReadOnlySet<string> sitiosDeDirecciones)
        {
            Fuente = fuente;
            Generada = generada;
            Descargada = descargada;
            Entradas = entradas;
            Dominios = dominios;
            Direcciones = direcciones;
            SitiosDeDirecciones = sitiosDeDirecciones;
        }

        public FuenteDeLista Fuente { get; }
        public DateTimeOffset? Generada { get; }
        public DateTimeOffset Descargada { get; }
        public int Entradas { get; }
        public IReadOnlySet<string> Dominios { get; }
        public IReadOnlySet<string> Direcciones { get; }
        public IReadOnlySet<string> SitiosDeDirecciones { get; }

        public DateTimeOffset Fecha => Generada is DateTimeOffset g && g < Descargada ? g : Descargada;

        public TimeSpan Antiguedad(DateTimeOffset ahora) => ahora > Fecha ? ahora - Fecha : TimeSpan.Zero;
    }

    /// <summary>El resultado de leer una lista: o la lista, o el motivo por el que NO se acepto (nunca las dos).</summary>
    public sealed record LecturaDeLista(ListaCargada? Lista, string? Motivo);

    /// <summary>
    /// Lee y valida las listas descargadas. Una lista que no pasa la validacion se rechaza ENTERA (no se usa a medias): una descarga
    /// cortada o una pagina de error servida con 200 no puede dejar al equipo con una lista recortada que se presente como completa.
    /// </summary>
    public static class ParserDeListas
    {
        public const int MaximoDeCaracteres = 32 * 1024 * 1024;
        public const int MinimoPhishingArmy = 1000;
        public const int MinimoOpenPhish = 20;

        private static readonly Regex Dominio = new Regex(
            @"^(?=.{1,253}\z)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+\z",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex Entradas = new Regex(@"^#\s*Entries:\s*([0-9]{1,9})\s*\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex Generada = new Regex(@"^#\s*Generated:\s*(\S+)\s*\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex Formato = new Regex(@"^#\s*Format:\s*domains\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        /// <summary>
        /// Formato real (comprobado el 2026-11-09): cabecera con «#», un dominio por linea en minusculas, «# Entries: N» y
        /// «# Format: domains». Se exige que el numero de dominios validos sea EXACTAMENTE el que declara la cabecera.
        /// </summary>
        public static LecturaDeLista LeerPhishingArmy(string? texto, DateTimeOffset descargada)
        {
            if (string.IsNullOrEmpty(texto)) return Mal("la lista llegó vacía");
            if (texto.Length > MaximoDeCaracteres) return Mal("la lista es demasiado grande");

            int? declaradas = null;
            DateTimeOffset? generada = null;
            bool formato = false;
            int validas = 0, invalidas = 0;
            var dominios = new HashSet<string>(StringComparer.Ordinal);

            foreach (string bruta in Lineas(texto))
            {
                string linea = bruta.Trim();
                if (linea.Length == 0) continue;
                if (linea[0] == '#')
                {
                    Match m = Entradas.Match(linea);
                    if (m.Success) declaradas = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                    m = Generada.Match(linea);
                    if (m.Success && DateTimeOffset.TryParse(m.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset g))
                        generada = g.ToUniversalTime();
                    if (Formato.IsMatch(linea)) formato = true;
                    continue;
                }
                if (Dominio.IsMatch(linea)) { validas++; dominios.Add(linea); }
                else invalidas++;
            }

            if (!formato || declaradas is null) return Mal("no se reconoce el formato de la lista (falta la cabecera «Format: domains» o «Entries»)");
            if (validas != declaradas) return Mal("la lista llegó incompleta o cambió de formato (dice tener " + declaradas + " dominios y se leyeron " + validas + (invalidas > 0 ? ", más " + invalidas + " líneas ilegibles" : "") + ")");
            if (validas < MinimoPhishingArmy) return Mal("la lista es sospechosamente pequeña (" + validas + " dominios)");
            // Una fecha de generacion en el futuro no es creible: se usa la de descarga.
            if (generada is DateTimeOffset gg && gg > descargada.AddDays(1)) generada = null;

            return new LecturaDeLista(new ListaCargada(FuenteDeLista.PhishingArmy, generada, descargada, validas, dominios,
                new HashSet<string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.Ordinal)), null);
        }

        /// <summary>
        /// Formato real (comprobado el 2026-11-09): una direccion completa por linea, sin cabecera. Sin un recuento declarado, se exige que
        /// casi todas las lineas sean direcciones web (una pagina HTML servida con 200 no pasa) y un minimo de entradas.
        /// </summary>
        public static LecturaDeLista LeerOpenPhish(string? texto, DateTimeOffset descargada)
        {
            if (string.IsNullOrEmpty(texto)) return Mal("la lista llegó vacía");
            if (texto.Length > MaximoDeCaracteres) return Mal("la lista es demasiado grande");

            int validas = 0, invalidas = 0;
            var direcciones = new HashSet<string>(StringComparer.Ordinal);
            var sitios = new HashSet<string>(StringComparer.Ordinal);
            foreach (string bruta in Lineas(texto))
            {
                string linea = bruta.Trim();
                if (linea.Length == 0) continue;
                if (!linea.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !linea.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { invalidas++; continue; }
                EnlaceNormalizado? e = NormalizadorDeEnlaces.Normalizar(new EnlaceEncontrado(linea, 0, OrigenDelEnlace.ConEsquema), out _);
                if (e is null) { invalidas++; continue; }
                validas++;
                direcciones.Add(e.Clave);
                sitios.Add(e.Sitio);
            }

            if (validas == 0) return Mal("no se reconoce el formato de la lista (ninguna línea es una dirección web)");
            if (invalidas * 50 > validas + invalidas) return Mal("no se reconoce el formato de la lista (" + invalidas + " de " + (validas + invalidas) + " líneas no son direcciones web)");
            if (validas < MinimoOpenPhish) return Mal("la lista es sospechosamente pequeña (" + validas + " direcciones)");

            return new LecturaDeLista(new ListaCargada(FuenteDeLista.OpenPhish, null, descargada, validas,
                new HashSet<string>(StringComparer.Ordinal), direcciones, sitios), null);
        }

        private static IEnumerable<string> Lineas(string texto) => texto.Split('\n');

        private static LecturaDeLista Mal(string motivo) => new(null, motivo);
    }

    /// <summary>Las dos listas en memoria (cualquiera puede faltar) y las busquedas sobre ellas. Todo local: el enlace no sale del equipo.</summary>
    public sealed class ListasDePhishing
    {
        public static readonly ListasDePhishing Vacias = new(null, null);

        public ListasDePhishing(ListaCargada? phishingArmy, ListaCargada? openPhish)
        {
            if (phishingArmy is not null && phishingArmy.Fuente != FuenteDeLista.PhishingArmy) throw new ArgumentException("No es la lista de Phishing Army.", nameof(phishingArmy));
            if (openPhish is not null && openPhish.Fuente != FuenteDeLista.OpenPhish) throw new ArgumentException("No es la lista de OpenPhish.", nameof(openPhish));
            PhishingArmy = phishingArmy;
            OpenPhish = openPhish;
        }

        public ListaCargada? PhishingArmy { get; }
        public ListaCargada? OpenPhish { get; }

        public ListaCargada? De(FuenteDeLista f) => f == FuenteDeLista.PhishingArmy ? PhishingArmy : OpenPhish;

        public ListasDePhishing Con(ListaCargada lista)
            => lista.Fuente == FuenteDeLista.PhishingArmy ? new ListasDePhishing(lista, OpenPhish) : new ListasDePhishing(PhishingArmy, lista);

        /// <summary>
        /// El sitio, o uno de los sitios que lo contienen («login.banco-falso.com» esta dentro de «banco-falso.com»), esta en Phishing
        /// Army. Nunca se sube hasta una terminacion sola («com») ni hasta una terminacion de dos niveles («co.uk», «com.ar»).
        /// </summary>
        public string? CoincidenciaEnPhishingArmy(string sitio)
        {
            if (PhishingArmy is null) return null;
            foreach (string s in SitioYPadres(sitio))
                if (PhishingArmy.Dominios.Contains(s)) return s;
            return null;
        }

        public bool DireccionEnOpenPhish(string clave) => OpenPhish is not null && OpenPhish.Direcciones.Contains(clave);

        public bool SitioEnOpenPhish(string sitio) => OpenPhish is not null && OpenPhish.SitiosDeDirecciones.Contains(sitio);

        public static IEnumerable<string> SitioYPadres(string sitio)
        {
            string s = sitio;
            while (true)
            {
                int punto = s.IndexOf('.');
                if (punto < 0) yield break;                                   // una etiqueta sola: «com»
                if (Dominios.EsTerminacionDeDosNiveles(s)) yield break;       // «co.uk», «com.ar»
                yield return s;
                s = s.Substring(punto + 1);
            }
        }
    }
}
