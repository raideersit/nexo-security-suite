using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    public enum EstadoDeLecturaWifi
    {
        Correcta,

        /// <summary>No hay ningun adaptador Wi-Fi (comprobado aparte, sin depender del servicio WLAN). No hay nada que revisar: es un hecho, no un fallo.</summary>
        SinAdaptador,

        /// <summary>Hay adaptador pero el servicio WLAN no esta activo: no se pudo revisar.</summary>
        ServicioNoActivo,
        Error
    }

    /// <summary>Un perfil guardado. <c>Xml</c> null = no se pudo leer. El XML puede traer la clave cifrada: el parser jamas la lee y nada la conserva.</summary>
    public sealed record PerfilCrudo(string Nombre, string? Xml);

    /// <summary>La conexion activa segun Windows. Autenticacion y cifrado son los codigos DOT11_AUTH_ALGORITHM / DOT11_CIPHER_ALGORITHM.</summary>
    public sealed record ConexionActual(string Perfil, bool SeguridadActiva, uint Autenticacion, uint Cifrado);

    public sealed record AdaptadorWifi(string Descripcion, IReadOnlyList<PerfilCrudo> Perfiles, ConexionActual? Conexion);

    public sealed record InstantaneaDeWifi(EstadoDeLecturaWifi Estado, IReadOnlyList<AdaptadorWifi> Adaptadores);

    /// <summary>Lo unico que Nexo extrae de un perfil. No hay campo para la clave: su valor nunca se lee.</summary>
    public sealed record PerfilWifi(string Nombre, string Autenticacion, string Cifrado, bool? Automatico, bool? Oculta);

    /// <summary>
    /// Lee el XML de un perfil de Wi-Fi. El XML lo escribe el sistema pero se trata como no confiable: sin DTD ni entidades
    /// externas, tamano acotado, y se IGNORA todo salvo cuatro datos. El elemento <c>keyMaterial</c> (la clave, cifrada) se salta
    /// sin leer su texto. Los espacios de nombres cambian entre versiones del esquema (v1, v2, v3): se usa solo el nombre local.
    /// </summary>
    public static class ParserDePerfilWifi
    {
        public const int MaximoDeCaracteres = 64 * 1024;

        /// <summary>null si el XML no se puede interpretar o no trae autenticacion y cifrado: no se adivina.</summary>
        public static PerfilWifi? Parsear(string nombre, string? xml)
        {
            if (string.IsNullOrEmpty(xml) || xml.Length > MaximoDeCaracteres) return null;
            var o = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaximoDeCaracteres,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            };

            string? auth = null, cif = null, modo = null, oculta = null;
            try
            {
                using var r = XmlReader.Create(new StringReader(xml), o);
                r.MoveToContent();
                while (!r.EOF)
                {
                    if (r.NodeType == XmlNodeType.Element)
                    {
                        switch (r.LocalName)
                        {
                            case "keyMaterial":
                                r.Skip(); // la clave (cifrada): su texto NO se lee
                                continue;
                            case "authentication": { string v = r.ReadElementContentAsString().Trim(); auth ??= v; continue; }
                            case "encryption": { string v = r.ReadElementContentAsString().Trim(); cif ??= v; continue; }
                            case "connectionMode": { string v = r.ReadElementContentAsString().Trim(); modo ??= v; continue; }
                            case "nonBroadcast": { string v = r.ReadElementContentAsString().Trim(); oculta ??= v; continue; }
                        }
                    }
                    r.Read(); // ReadElementContentAsString y Skip ya avanzaron por su cuenta; en el resto hay que leer el siguiente nodo
                }
            }
            catch (XmlException) { return null; }
            catch (InvalidOperationException) { return null; }

            if (string.IsNullOrEmpty(auth) || string.IsNullOrEmpty(cif)) return null;
            return new PerfilWifi(nombre, auth, cif,
                modo is null ? null : string.Equals(modo, "auto", StringComparison.OrdinalIgnoreCase),
                oculta is null ? null : string.Equals(oculta, "true", StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Reglas sobre las redes Wi-Fi guardadas y la conexion actual. Solo mira el TIPO de seguridad: nunca la clave. Una
    /// combinacion que Nexo no reconoce no se da por buena: queda como «no evaluado».
    /// </summary>
    public static class AnalizadorDeWifi
    {
        private enum Clase { Abierta, Wep, Tkip, Owe, Moderna, Desconocida }

        public static ResultadoDeAnalisis Analizar(InstantaneaDeWifi s)
        {
            if (s is null) throw new ArgumentNullException(nameof(s));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();

            switch (s.Estado)
            {
                case EstadoDeLecturaWifi.SinAdaptador:
                    return new ResultadoDeAnalisis(hallazgos, noEvaluado); // nada que revisar, y se sabe por que
                case EstadoDeLecturaWifi.ServicioNoActivo:
                    noEvaluado.Add("El servicio de configuración de WLAN no está activo y el equipo tiene un adaptador Wi-Fi: no se pudieron revisar las redes guardadas ni la conexión actual.");
                    return new ResultadoDeAnalisis(hallazgos, noEvaluado);
                case EstadoDeLecturaWifi.Error:
                    noEvaluado.Add("No se pudo leer el Wi-Fi (error de la API de Windows): no se sabe si hay redes inseguras guardadas.");
                    return new ResultadoDeAnalisis(hallazgos, noEvaluado);
            }

            foreach (AdaptadorWifi a in s.Adaptadores)
            {
                foreach (PerfilCrudo p in a.Perfiles)
                {
                    if (p.Xml is null) { noEvaluado.Add("No se pudo leer el perfil de la red «" + p.Nombre + "»."); continue; }
                    PerfilWifi? perfil = ParserDePerfilWifi.Parsear(p.Nombre, p.Xml);
                    if (perfil is null) { noEvaluado.Add("El perfil de la red «" + p.Nombre + "» no tiene el formato esperado: no se pudo interpretar."); continue; }

                    Clase c = Clasificar(perfil.Autenticacion, perfil.Cifrado);
                    bool auto = perfil.Automatico == true;
                    switch (c)
                    {
                        case Clase.Abierta:
                            hallazgos.Add(auto
                                ? new HallazgoDeSistema("WIFI-RED-ABIERTA-AUTOMATICA", Severidad.Alta, "Una red Wi-Fi abierta se conecta sola",
                                    "La red «" + perfil.Nombre + "» no tiene cifrado y el equipo se conecta a ella automáticamente: cualquiera cerca puede ver el tráfico que no vaya cifrado por su cuenta, y una red falsa con el mismo nombre atraería al equipo.",
                                    "Olvida la red (Configuración > Red > Wi-Fi > Administrar redes conocidas) o desactiva la conexión automática.", perfil.Nombre)
                                : new HallazgoDeSistema("WIFI-RED-ABIERTA", Severidad.Media, "Hay una red Wi-Fi abierta guardada",
                                    "La red «" + perfil.Nombre + "» no tiene cifrado. No se conecta sola, pero está guardada.",
                                    "Olvídala si ya no la usas.", perfil.Nombre));
                            break;
                        case Clase.Wep:
                            hallazgos.Add(new HallazgoDeSistema("WIFI-WEP", Severidad.Alta, "Una red Wi-Fi guardada usa WEP",
                                "La red «" + perfil.Nombre + "» usa WEP, un cifrado roto desde hace años: su clave se obtiene en minutos con herramientas públicas.",
                                "Cambia el router a WPA2 o WPA3, y olvida esta red mientras tanto.", perfil.Nombre));
                            break;
                        case Clase.Tkip:
                            hallazgos.Add(new HallazgoDeSistema("WIFI-TKIP", Severidad.Media, "Una red Wi-Fi guardada usa cifrado TKIP",
                                "La red «" + perfil.Nombre + "» usa TKIP, un cifrado obsoleto y con debilidades conocidas.",
                                "Configura el router con WPA2-AES (o WPA3).", perfil.Nombre));
                            break;
                        case Clase.Desconocida:
                            noEvaluado.Add("La red «" + perfil.Nombre + "» usa una combinación que Nexo no reconoce (" + perfil.Autenticacion + " / " + perfil.Cifrado + "): no se evaluó.");
                            break;
                    }

                    if (perfil.Oculta == true)
                        hallazgos.Add(new HallazgoDeSistema("WIFI-RED-OCULTA", Severidad.Baja, "Una red Wi-Fi guardada es oculta",
                            "La red «" + perfil.Nombre + "» no anuncia su nombre, así que el equipo la busca por su nombre en cualquier lugar donde esté: eso delata la red y, con ella, tu casa o tu trabajo. Ocultar el nombre no mejora la seguridad.",
                            "Haz visible el nombre en el router y quita la marca de red oculta.", perfil.Nombre));
                }

                if (a.Conexion is { } k)
                {
                    if (!k.SeguridadActiva)
                        hallazgos.Add(new HallazgoDeSistema("WIFI-CONEXION-SIN-CIFRADO", Severidad.Alta, "Estás conectado a una red Wi-Fi sin cifrado",
                            "La conexión actual («" + k.Perfil + "») no está cifrada.", "Desconéctate o usa una VPN; no escribas contraseñas en sitios sin HTTPS.", k.Perfil));
                    else if (EsWep(k.Autenticacion, k.Cifrado))
                        hallazgos.Add(new HallazgoDeSistema("WIFI-CONEXION-WEP", Severidad.Alta, "Estás conectado con WEP",
                            "La conexión actual («" + k.Perfil + "») usa WEP, un cifrado roto.", "Conéctate a otra red o cambia el router a WPA2/WPA3.", k.Perfil));
                    else if (k.Cifrado == CifradoTkip)
                        hallazgos.Add(new HallazgoDeSistema("WIFI-CONEXION-TKIP", Severidad.Media, "Estás conectado con cifrado TKIP",
                            "La conexión actual («" + k.Perfil + "») usa TKIP, obsoleto.", "Configura el router con WPA2-AES (o WPA3).", k.Perfil));
                }
            }

            return new ResultadoDeAnalisis(hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Sujeto, StringComparer.Ordinal).ToList(), noEvaluado);
        }

        private const uint AutenticacionShared = 2, CifradoWep40 = 1, CifradoTkip = 2, CifradoWep104 = 5, CifradoWep = 0x101;

        private static bool EsWep(uint auth, uint cifrado) => auth == AutenticacionShared || cifrado is CifradoWep40 or CifradoWep104 or CifradoWep;

        private static Clase Clasificar(string autenticacion, string cifrado)
        {
            string a = autenticacion.Trim().ToLowerInvariant(), c = cifrado.Trim().ToLowerInvariant();
            if (c == "wep" || a == "shared") return Clase.Wep;
            if (a == "open" && c == "none") return Clase.Abierta;
            if (a == "owe") return Clase.Owe;
            if (c == "tkip") return Clase.Tkip;
            bool cifradoFuerte = c is "aes" or "ccmp" or "gcmp256";
            if (cifradoFuerte && a is "wpa" or "wpapsk" or "wpa2" or "wpa2psk" or "wpa3" or "wpa3sae" or "wpa3ent" or "wpa3ent192") return Clase.Moderna;
            return Clase.Desconocida; // incluye "open" con un cifrado que no es "none": no se adivina
        }
    }
}
