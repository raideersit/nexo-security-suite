using System.Globalization;
using System.Text;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Texto ajeno (rutas, nombres de programa) que se muestra en UNA linea: un plan de confirmacion, la consola
    /// o el titulo de una nota.
    ///
    /// Un nombre de archivo puede contener saltos de linea (NTFS los admite por la API nativa; Linux, siempre).
    /// Sin esto, <c>factura\n  RECHAZADO: ...</c> anadiria una linea falsa al plan que el usuario confirma, o un
    /// encabezado falso a una nota. Los caracteres de control se ESCAPAN (se ven como \n, \u0085...) en vez de
    /// quitarse: que un archivo tenga uno es en si sospechoso y el usuario debe verlo.
    /// </summary>
    public static class TextoVisible
    {
        public static string UnaLinea(string? texto)
        {
            if (texto is null || texto.Length == 0) return "";

            bool limpio = true;
            foreach (char c in texto)
                if (EsDeControl(c)) { limpio = false; break; }
            if (limpio) return texto;

            var sb = new StringBuilder(texto.Length + 8);
            foreach (char c in texto)
            {
                if (!EsDeControl(c)) { sb.Append(c); continue; }
                sb.Append(c switch
                {
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    _ => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture)
                });
            }
            return sb.ToString();
        }

        // U+2028 y U+2029 no son "de control" para .NET, pero algunos visores los muestran como salto de linea.
        private static bool EsDeControl(char c) => char.IsControl(c) || c == (char)0x2028 || c == (char)0x2029;
    }
}
