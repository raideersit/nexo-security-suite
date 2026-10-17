using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Nexo.Reports.Model;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Construye nombres de nota legibles, validos en Windows y seguros para
    /// wikilinks de Obsidian.
    ///
    /// Formato: "2026-09-28 1432-07 - Amenaza - Win.Trojan.Agent en Descargas"
    ///          [--- fecha ---] [hora] [-tipo-] [------ titulo saneado ------]
    ///
    /// Ordena cronologicamente solo, es legible por una persona, y el timestamp
    /// al segundo mas el contador de colision garantizan unicidad.
    /// </summary>
    public static class NoteNaming
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        /// <summary>
        /// Caracteres que rompen un wikilink de Obsidian o un nombre de archivo
        /// de Windows. La union de ambos conjuntos:
        ///   Obsidian: [ ] # ^ | (y : en algunos contextos de enlace)
        ///   Windows:  \ / : * ? " &lt; &gt; |
        /// </summary>
        private static readonly char[] Prohibidos =
        {
            '[', ']', '#', '^', '|', '\\', '/', ':', '*', '?', '"', '<', '>'
        };

        /// <summary>
        /// Nombres reservados de MS-DOS que Windows sigue rechazando como nombre
        /// de archivo, con o sin extension. Un archivo de malware llamado "aux.exe"
        /// no es hipotetico: es una tecnica conocida.
        /// </summary>
        private static readonly HashSet<string> Reservados = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        /// <summary>
        /// Deja un texto utilizable como nombre de archivo y como destino de wikilink.
        /// Conserva tildes y enes: Obsidian los maneja sin problema y el vault lo
        /// lee una persona hispanohablante.
        /// </summary>
        public static string Sanear(string texto, int maxLargo = 60)
        {
            if (string.IsNullOrWhiteSpace(texto))
                return "sin titulo";

            var sb = new StringBuilder(texto.Length);
            foreach (char c in texto)
            {
                if (char.IsControl(c)) { sb.Append(' '); continue; }
                if (Array.IndexOf(Prohibidos, c) >= 0) { sb.Append('-'); continue; }
                sb.Append(c);
            }

            // Colapsa espacios y guiones repetidos que deja el paso anterior.
            var limpio = ColapsarSeparadores(sb.ToString());

            // Windows rechaza nombres terminados en punto o espacio.
            limpio = limpio.TrimEnd('.', ' ');

            if (limpio.Length > maxLargo)
                limpio = limpio.Substring(0, maxLargo).TrimEnd('.', ' ', '-');

            if (limpio.Length == 0)
                return "sin titulo";

            // Un nombre reservado se desactiva con un sufijo, no se descarta:
            // perder el nombre real de un archivo sospechoso seria peor.
            var sinExtension = Path.GetFileNameWithoutExtension(limpio);
            if (Reservados.Contains(sinExtension))
                limpio += "_";

            return limpio;
        }

        private static string ColapsarSeparadores(string s)
        {
            var sb = new StringBuilder(s.Length);
            char anterior = '\0';
            foreach (char c in s)
            {
                bool esSeparador = c == ' ' || c == '-';
                if (esSeparador && anterior == c) continue;
                sb.Append(c);
                anterior = c;
            }
            return sb.ToString().Trim();
        }

        /// <summary>Etiqueta corta del tipo de evento para el nombre de archivo.</summary>
        public static string EtiquetaDeTipo(string tipoEvento) => tipoEvento switch
        {
            TipoEvento.AmenazaDetectada => "Amenaza",
            TipoEvento.ArchivoEnCuarentena => "Cuarentena",
            TipoEvento.ArchivoRestaurado => "Restauracion",
            TipoEvento.BloqueoFirewall => "Firewall",
            TipoEvento.ResultadoEscaneo => "Escaneo",
            TipoEvento.VulnerabilidadDetectada => "Vulnerabilidad",
            TipoEvento.ConexionVpn => "VPN",
            TipoEvento.AccesoDispositivo => "Dispositivo",
            TipoEvento.SitioBloqueado => "Sitio bloqueado",
            TipoEvento.AlertaIdentidad => "Identidad",
            TipoEvento.BrechaDetectada => "Brecha",
            TipoEvento.SesionLimpieza => "Limpieza",
            TipoEvento.DuplicadosDetectados => "Duplicados",
            TipoEvento.SaludDisco => "Disco",
            TipoEvento.ArchivoTriturado => "Triturado",
            TipoEvento.ErrorModulo => "Error",
            _ => "Evento"
        };

        /// <summary>
        /// Nombre base de la nota, sin extension y sin resolver colisiones.
        /// Es exactamente el texto que ira dentro de [[ ]].
        /// </summary>
        public static string NombreBase(NexoEvent ev, int maxLargoTotal)
        {
            string fecha = ev.Fecha.ToString("yyyy-MM-dd HHmm-ss", Inv);
            string etiqueta = Sanear(EtiquetaDeTipo(ev.Tipo), 24);

            // Presupuesto para el titulo = total - fecha - etiqueta - separadores - ".md"
            int usado = fecha.Length + etiqueta.Length + " - ".Length * 2 + ".md".Length;
            int presupuesto = Math.Max(12, maxLargoTotal - usado);

            string titulo = Sanear(ev.Titulo, presupuesto);
            return fecha + " - " + etiqueta + " - " + titulo;
        }

        /// <summary>
        /// Resuelve colisiones anadiendo " (2)", " (3)"... Solo puede ocurrir si dos
        /// eventos del mismo tipo caen en el mismo segundo con el mismo titulo.
        /// El limite de 99 es una valvula: si se alcanza, algo esta en bucle y es
        /// preferible fallar ruidosamente que llenar el disco de notas.
        /// </summary>
        public static string ResolverColision(string carpeta, string nombreBase)
        {
            string candidato = nombreBase;
            for (int i = 2; i <= 99; i++)
            {
                if (!File.Exists(Path.Combine(carpeta, candidato + ".md")))
                    return candidato;
                candidato = nombreBase + " (" + i.ToString(Inv) + ")";
            }
            throw new IOException(
                "Mas de 99 notas colisionando con el nombre '" + nombreBase +
                "'. Probable bucle en el modulo que genera el evento.");
        }
    }
}
