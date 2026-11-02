using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Xml;

namespace Nexo.Modules.Cleanup.Inicio
{
    /// <summary>Que retraso el arranque, segun el numero de evento de Diagnostics-Performance.</summary>
    public enum TipoDeDegradacion
    {
        /// <summary>Evento 101: una aplicacion.</summary>
        Aplicacion,
        /// <summary>Evento 102: un controlador.</summary>
        Controlador,
        /// <summary>Evento 103: un servicio.</summary>
        Servicio
    }

    /// <summary>Evento 100: un arranque medido por Windows. Los tiempos van en milisegundos.</summary>
    public sealed record ArranqueMedido(
        DateTimeOffset Cuando,
        long TotalMs,
        long? RutaPrincipalMs,
        long? PostArranqueMs,
        int? AppsDeInicio,
        bool? EsDegradacion);

    /// <summary>Eventos 101-103: algo tardo mas de lo habitual en arrancar.</summary>
    public sealed record DegradacionDeArranque(
        DateTimeOffset Cuando,
        TipoDeDegradacion Tipo,
        string Nombre,
        string? NombreAmigable,
        long TotalMs,
        long DegradacionMs);

    /// <summary>
    /// Interpreta el XML de los eventos 100-103 de <c>Microsoft-Windows-Diagnostics-Performance/Operational</c>.
    /// Es portable: recibe texto, no toca el registro de eventos.
    ///
    /// Mismas defensas que el analizador del 5157 (los nombres de aplicacion los controla cualquier programa y
    /// acaban en la consola o en una nota): sin DTD ni entidades, tamano acotado, tiempos validados y nombres con
    /// caracteres de control rechazados. Un evento que no pasa se descarta entero y se cuenta.
    ///
    /// El formato es el que documenta Microsoft (campos BootTime, MainPathBootTime, BootPostBootTime,
    /// BootNumStartupApps, BootIsDegradation; Name, FriendlyName, TotalTime, DegradationTime), no uno observado
    /// todavia en un equipo real.
    /// </summary>
    public static class ParserDeEventoDeArranque
    {
        public const int MaximoCaracteresDocumento = 64 * 1024;
        public const int MaximoCaracteresCampo = 1024;
        private const int MaximoCampos = 128;

        /// <summary>Un dia. Un tiempo mayor no es un arranque lento: es un dato roto.</summary>
        public const long MaximoMs = 24L * 60 * 60 * 1000;

        private const string ProveedorEsperado = "Microsoft-Windows-Diagnostics-Performance";

        /// <summary>Lee un evento 100 o uno de 101-103. Exactamente uno de los dos resultados queda no nulo si devuelve true.</summary>
        public static bool TryParse(string? xml, out ArranqueMedido? arranque, out DegradacionDeArranque? degradacion, out string? motivo)
        {
            arranque = null;
            degradacion = null;
            motivo = null;
            if (string.IsNullOrWhiteSpace(xml)) { motivo = "XML vacio"; return false; }
            if (xml.Length > MaximoCaracteresDocumento) { motivo = "XML demasiado grande"; return false; }

            var ajustes = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaximoCaracteresDocumento,
                MaxCharactersFromEntities = 0,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            };

            string? proveedor = null, idEvento = null, hora = null;
            var datos = new Dictionary<string, string>(StringComparer.Ordinal);

            try
            {
                using var texto = new StringReader(xml);
                using XmlReader r = XmlReader.Create(texto, ajustes);
                bool hayNodo = r.Read();
                while (hayNodo)
                {
                    if (r.NodeType != XmlNodeType.Element) { hayNodo = r.Read(); continue; }

                    // Leer el contenido deja el lector en el nodo siguiente: ahi no se vuelve a llamar a Read().
                    bool yaAvanzo = false;
                    switch (r.LocalName)
                    {
                        case "Provider":
                            proveedor ??= r.GetAttribute("Name");
                            break;
                        case "EventID":
                            idEvento ??= LeerTexto(r);
                            yaAvanzo = true;
                            break;
                        case "TimeCreated":
                            hora ??= r.GetAttribute("SystemTime");
                            break;
                        case "Data":
                            string? nombre = r.GetAttribute("Name");
                            if (nombre is null) break;
                            if (datos.Count >= MaximoCampos) { motivo = "demasiados campos"; return false; }
                            string valor = LeerTexto(r);
                            datos.TryAdd(nombre, valor);
                            yaAvanzo = true;
                            break;
                    }

                    if (!yaAvanzo) hayNodo = r.Read();
                    else hayNodo = !r.EOF;
                }
            }
            catch (XmlException e) { motivo = "XML invalido: " + e.Message; return false; }

            if (proveedor != ProveedorEsperado) { motivo = "el evento no viene de Diagnostics-Performance"; return false; }

            if (hora is null || !DateTimeOffset.TryParse(hora, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset cuando))
            { motivo = "hora invalida"; return false; }

            switch (idEvento)
            {
                case "100":
                    if (!Ms(datos, "BootTime", out long total)) { motivo = "BootTime falta o es invalido"; return false; }
                    arranque = new ArranqueMedido(cuando, total,
                        MsOpcional(datos, "MainPathBootTime"), MsOpcional(datos, "BootPostBootTime"),
                        datos.TryGetValue("BootNumStartupApps", out string? n)
                            && int.TryParse(n, NumberStyles.None, CultureInfo.InvariantCulture, out int apps) ? apps : null,
                        datos.TryGetValue("BootIsDegradation", out string? d) ? Booleano(d) : null);
                    return true;

                case "101": return Degradacion(TipoDeDegradacion.Aplicacion, cuando, datos, out degradacion, out motivo);
                case "102": return Degradacion(TipoDeDegradacion.Controlador, cuando, datos, out degradacion, out motivo);
                case "103": return Degradacion(TipoDeDegradacion.Servicio, cuando, datos, out degradacion, out motivo);

                default:
                    motivo = "no es un evento de arranque (100-103)";
                    return false;
            }
        }

        private static bool Degradacion(TipoDeDegradacion tipo, DateTimeOffset cuando, Dictionary<string, string> datos,
            out DegradacionDeArranque? degradacion, out string? motivo)
        {
            degradacion = null;
            motivo = null;
            if (!datos.TryGetValue("Name", out string? nombre) || string.IsNullOrWhiteSpace(nombre))
            { motivo = "falta el nombre"; return false; }
            if (ContieneControl(nombre)) { motivo = "el nombre contiene caracteres de control"; return false; }
            if (!Ms(datos, "TotalTime", out long total)) { motivo = "TotalTime falta o es invalido"; return false; }
            if (!Ms(datos, "DegradationTime", out long degr)) { motivo = "DegradationTime falta o es invalido"; return false; }

            // El nombre amigable es opcional: si viene roto se omite, no invalida el evento.
            string? amigable = datos.TryGetValue("FriendlyName", out string? f) && !string.IsNullOrWhiteSpace(f) && !ContieneControl(f)
                ? f.Trim() : null;

            degradacion = new DegradacionDeArranque(cuando, tipo, nombre.Trim(), amigable, total, degr);
            return true;
        }

        private static bool Ms(Dictionary<string, string> datos, string campo, out long ms)
        {
            ms = 0;
            return datos.TryGetValue(campo, out string? t)
                   && long.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out ms)
                   && ms <= MaximoMs;
        }

        private static long? MsOpcional(Dictionary<string, string> datos, string campo)
            => Ms(datos, campo, out long ms) ? ms : null;

        private static bool? Booleano(string s) => s.Trim().ToLowerInvariant() switch
        {
            "true" or "1" => true,
            "false" or "0" => false,
            _ => null
        };

        private static string LeerTexto(XmlReader r)
        {
            // Deja SIEMPRE el lector en el nodo siguiente (tambien con <Data Name="x"/>), o el bucle no termina.
            if (r.IsEmptyElement) { r.Read(); return ""; }
            string t = r.ReadElementContentAsString();
            return t.Length > MaximoCaracteresCampo ? t[..MaximoCaracteresCampo] : t;
        }

        private static bool ContieneControl(string s)
        {
            foreach (char c in s)
                if (char.IsControl(c)) return true;
            return false;
        }
    }
}
