using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Xml;

namespace Nexo.Modules.Threats.Alertas
{
    /// <summary>Un evento de Windows ya interpretado: lo comun (id, proveedor, canal, fecha) y sus datos por nombre.</summary>
    public sealed record EventoDeWindows(int Id, string Proveedor, string Canal, DateTimeOffset Fecha, IReadOnlyDictionary<string, string> Datos)
    {
        public string Dato(string nombre) => Datos.TryGetValue(nombre, out string? v) ? v : "";
    }

    /// <summary>
    /// Interpreta el XML de un evento de Windows (el que da <c>EventRecord.ToXml()</c>). Portable: recibe texto. Las mismas defensas que el
    /// parser del 5157, porque varios campos los controla cualquier programa (nombres de cuenta, de servicio, de tarea, rutas) y acaban en
    /// una nota de Markdown: sin DTD ni entidades, tamaño acotado, y un campo con caracteres de control (saltos de linea) se limpia.
    /// Un evento que no pasa se descarta y se cuenta; nunca se convierte en un evento con valores a medias.
    /// </summary>
    public static class ParserDeEventoDeWindows
    {
        public const int MaximoCaracteresDocumento = 256 * 1024;   // el 4698 trae la tarea entera (XML) dentro de un campo
        public const int MaximoCaracteresCampo = 64 * 1024;
        private const int MaximoCampos = 128;

        public static bool TryParse(string? xml, out EventoDeWindows? evento, out string? motivo)
        {
            evento = null;
            motivo = null;
            if (string.IsNullOrWhiteSpace(xml)) { motivo = "XML vacío"; return false; }
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

            string? proveedor = null, id = null, hora = null, canal = null;
            var datos = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                using var texto = new StringReader(xml);
                using XmlReader r = XmlReader.Create(texto, ajustes);
                bool hay = r.Read();
                while (hay)
                {
                    if (r.NodeType != XmlNodeType.Element) { hay = r.Read(); continue; }
                    bool yaAvanzo = false;
                    switch (r.LocalName)
                    {
                        case "Provider": proveedor ??= r.GetAttribute("Name"); break;
                        case "EventID": id ??= Leer(r); yaAvanzo = true; break;
                        case "Channel": canal ??= Leer(r); yaAvanzo = true; break;
                        case "TimeCreated": hora ??= r.GetAttribute("SystemTime"); break;
                        case "Data":
                            string? nombre = r.GetAttribute("Name");
                            string valor = Leer(r);
                            yaAvanzo = true;
                            if (nombre is null) break;
                            if (datos.Count >= MaximoCampos) { motivo = "demasiados campos"; return false; }
                            if (valor.Length > MaximoCaracteresCampo) { motivo = "campo demasiado largo"; return false; }
                            datos[nombre] = valor;
                            break;
                    }
                    if (!yaAvanzo) hay = r.Read();
                    else hay = !r.EOF;
                }
            }
            catch (XmlException e) { motivo = "XML inválido: " + e.Message; return false; }

            if (id is null || !int.TryParse(id.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int n)) { motivo = "sin número de evento"; return false; }
            if (hora is null || !DateTimeOffset.TryParse(hora, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset fecha)) { motivo = "sin fecha"; return false; }
            if (string.IsNullOrEmpty(proveedor)) { motivo = "sin proveedor"; return false; }

            evento = new EventoDeWindows(n, proveedor, canal ?? "", fecha.ToUniversalTime(), datos);
            return true;
        }

        /// <summary>El texto de un elemento, sin caracteres de control (un salto de linea en un nombre podria romper la nota de Markdown).</summary>
        private static string Leer(XmlReader r)
        {
            string s = r.ReadElementContentAsString();
            var b = new System.Text.StringBuilder(s.Length);
            foreach (char c in s) b.Append(char.IsControl(c) ? ' ' : c);
            return b.ToString().Trim();
        }
    }
}
