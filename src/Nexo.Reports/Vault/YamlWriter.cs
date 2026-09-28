using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Serializador YAML minimo para front matter.
    ///
    /// Por que no YamlDotNet: esta libreria la referencian los cinco modulos y no
    /// debe arrastrar dependencias NuGet que despues choquen de version. El
    /// esquema que escribimos es cerrado (escalares y listas de texto), asi que
    /// un serializador de 80 lineas es suficiente y auditable de una sentada.
    /// Esta clase SOLO escribe; no intenta ser un parser de YAML.
    /// </summary>
    internal static class YamlWriter
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        /// <summary>
        /// Palabras que YAML 1.1 interpreta como booleano y que romperian un valor
        /// de texto legitimo. El caso clasico: un archivo llamado "no" o un pais "NO".
        /// </summary>
        private static readonly HashSet<string> BooleanosImplicitos = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "y", "n", "yes", "no", "true", "false", "on", "off", "null", "~"
        };

        public static void EscribirCampo(StringBuilder sb, string clave, object? valor)
        {
            if (valor is null)
            {
                sb.Append(clave).Append(": \n");
                return;
            }

            if (valor is string s)
            {
                sb.Append(clave).Append(": ").Append(Escalar(s)).Append('\n');
                return;
            }

            if (valor is bool b)
            {
                sb.Append(clave).Append(": ").Append(b ? "true" : "false").Append('\n');
                return;
            }

            if (valor is DateTimeOffset dto)
            {
                // Sin offset y sin comillas: es el unico formato que el panel de
                // propiedades de Obsidian reconoce nativamente como fecha y hora.
                sb.Append(clave).Append(": ").Append(dto.ToString("yyyy-MM-ddTHH:mm:ss", Inv)).Append('\n');
                return;
            }

            if (valor is DateTime dt)
            {
                sb.Append(clave).Append(": ").Append(dt.ToString("yyyy-MM-ddTHH:mm:ss", Inv)).Append('\n');
                return;
            }

            if (EsNumero(valor))
            {
                sb.Append(clave).Append(": ").Append(Convert.ToString(valor, Inv)).Append('\n');
                return;
            }

            if (valor is IEnumerable lista && !(valor is string))
            {
                sb.Append(clave).Append(":\n");
                bool alguno = false;
                foreach (object? item in lista)
                {
                    alguno = true;
                    sb.Append("  - ").Append(Escalar(Convert.ToString(item, Inv) ?? "")).Append('\n');
                }
                if (!alguno)
                {
                    // Una lista vacia en bloque es ambigua; en flujo no lo es.
                    sb.Length -= (clave.Length + 2);
                    sb.Append(clave).Append(": []\n");
                }
                return;
            }

            sb.Append(clave).Append(": ").Append(Escalar(Convert.ToString(valor, Inv) ?? "")).Append('\n');
        }

        private static bool EsNumero(object v)
            => v is int || v is long || v is short || v is byte || v is uint || v is ulong
               || v is double || v is float || v is decimal;

        /// <summary>
        /// Decide si un texto necesita comillas y las aplica. Ante la duda, cita:
        /// una nota con front matter invalido desaparece del indice de Obsidian y
        /// es exactamente el evento que menos queremos perder.
        /// </summary>
        internal static string Escalar(string valor)
        {
            if (valor.Length == 0) return "\"\"";

            bool necesitaComillas =
                BooleanosImplicitos.Contains(valor)
                || valor[0] == ' ' || valor[valor.Length - 1] == ' '
                || valor.IndexOfAny(new[] { '\n', '\r', '\t', '"', '\'', '\\' }) >= 0
                || valor.IndexOf(": ", StringComparison.Ordinal) >= 0
                || valor.EndsWith(":", StringComparison.Ordinal)
                || valor.IndexOf(" #", StringComparison.Ordinal) >= 0
                || EsInicioEspecial(valor[0])
                || EsNumericoAmbiguo(valor);

            if (!necesitaComillas) return valor;

            var sb = new StringBuilder(valor.Length + 8);
            sb.Append('"');
            foreach (char c in valor)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: sb.Append(c); break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static bool EsInicioEspecial(char c)
            => c == '-' || c == '?' || c == ':' || c == ',' || c == '[' || c == ']'
               || c == '{' || c == '}' || c == '#' || c == '&' || c == '*' || c == '!'
               || c == '|' || c == '>' || c == '%' || c == '@' || c == '`';

        /// <summary>
        /// Texto que YAML convertiria en numero y perderia formato.
        /// Ejemplo real: el hash corto "0123" se volveria 123.
        /// </summary>
        private static bool EsNumericoAmbiguo(string valor)
            => double.TryParse(valor, NumberStyles.Any, Inv, out _);
    }
}
