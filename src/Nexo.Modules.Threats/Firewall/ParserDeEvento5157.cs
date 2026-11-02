using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Xml;

namespace Nexo.Modules.Threats.Firewall
{
    /// <summary>
    /// Interpreta el XML de un evento 5157 de Windows ("El Filtrado de plataforma de Windows ha bloqueado una
    /// conexion"). Es portable: recibe texto, no toca el registro de eventos.
    ///
    /// Defensivo a proposito: el XML sale del sistema, pero el nombre de la aplicacion y las direcciones los
    /// controla cualquier programa, y de aqui acaban en una nota de Markdown. Por eso:
    ///  - se prohiben los DTD y las entidades externas, y se acota el tamano del documento;
    ///  - las direcciones se validan como IP y se reescriben desde el valor ya interpretado;
    ///  - el puerto debe estar en 0-65535 y la direccion ser una de las dos conocidas;
    ///  - una ruta de aplicacion con caracteres de control (saltos de linea) se rechaza entera.
    /// Un evento que no pasa NO se convierte en un bloqueo con valores a medias: se descarta y se cuenta.
    /// </summary>
    public static class ParserDeEvento5157
    {
        public const int MaximoCaracteresDocumento = 64 * 1024;
        public const int MaximoCaracteresCampo = 2048;
        private const int MaximoCampos = 64;

        private const string ProveedorEsperado = "Microsoft-Windows-Security-Auditing";
        private const string DireccionEntrante = "%%14593";
        private const string DireccionSaliente = "%%14592";

        public static bool TryParse(string? xml, out ConexionBloqueada? conexion, out string? motivo)
        {
            conexion = null;
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

                    // Leer el contenido de un elemento ya deja el lector en el nodo siguiente: ahi NO se vuelve a
                    // llamar a Read(), o se saltaria el elemento que viene detras.
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

            if (proveedor != ProveedorEsperado) { motivo = "el evento no viene de la auditoria de seguridad"; return false; }
            if (idEvento != "5157") { motivo = "no es un evento 5157"; return false; }

            if (hora is null || !DateTimeOffset.TryParse(hora, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset cuando))
            { motivo = "hora invalida"; return false; }

            if (!datos.TryGetValue("Direction", out string? dir)) { motivo = "falta la direccion"; return false; }
            DireccionDeRegla direccion;
            if (dir == DireccionEntrante) direccion = DireccionDeRegla.Entrante;
            else if (dir == DireccionSaliente) direccion = DireccionDeRegla.Saliente;
            else { motivo = "direccion desconocida"; return false; }

            // La parte remota es el origen si la conexion es entrante y el destino si es saliente.
            string campoIp = direccion == DireccionDeRegla.Entrante ? "SourceAddress" : "DestAddress";
            string campoPuerto = direccion == DireccionDeRegla.Entrante ? "SourcePort" : "DestPort";

            if (!datos.TryGetValue(campoIp, out string? ipTexto) || !IPAddress.TryParse(ipTexto, out IPAddress? ip))
            { motivo = "direccion IP invalida"; return false; }

            if (!datos.TryGetValue(campoPuerto, out string? puertoTexto)
                || !int.TryParse(puertoTexto, NumberStyles.None, CultureInfo.InvariantCulture, out int puerto)
                || puerto is < 0 or > 65535)
            { motivo = "puerto invalido"; return false; }

            if (!datos.TryGetValue("Application", out string? app) || string.IsNullOrWhiteSpace(app))
            { motivo = "falta la aplicacion"; return false; }
            if (app == "-") app = "(sistema)";
            if (ContieneControl(app)) { motivo = "la aplicacion contiene caracteres de control"; return false; }

            string protocolo = "?";
            if (datos.TryGetValue("Protocol", out string? protoTexto)
                && int.TryParse(protoTexto, NumberStyles.None, CultureInfo.InvariantCulture, out int proto))
                protocolo = NombreDeProtocolo(proto);

            long? filtro = null;
            if (datos.TryGetValue("FilterRTID", out string? filtroTexto)
                && long.TryParse(filtroTexto, NumberStyles.None, CultureInfo.InvariantCulture, out long f))
                filtro = f;

            conexion = new ConexionBloqueada(cuando, app.Trim(), direccion, ip.ToString(), puerto, protocolo, filtro);
            return true;
        }

        private static string LeerTexto(XmlReader r)
        {
            // Deja SIEMPRE el lector en el nodo siguiente al elemento (tambien si esta vacio): si no avanzara, el
            // bucle de TryParse no terminaria con un <Data Name="x"/>.
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

        public static string NombreDeProtocolo(int numero) => numero switch
        {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => numero.ToString(CultureInfo.InvariantCulture)
        };
    }
}
