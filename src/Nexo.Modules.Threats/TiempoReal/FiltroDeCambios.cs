using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Threats.TiempoReal
{
    /// <summary>Decide si un cambio merece que se analice el archivo. Logica pura, sin disco.</summary>
    public sealed class FiltroDeCambios
    {
        private readonly HashSet<string> _extensiones;
        private readonly string[] _excluidas;

        public FiltroDeCambios(OpcionesDeTiempoReal opciones)
        {
            _extensiones = new HashSet<string>(opciones.Extensiones.Select(e => e.StartsWith('.') ? e : "." + e),
                                               StringComparer.OrdinalIgnoreCase);
            _excluidas = opciones.Excluir.Where(x => !string.IsNullOrWhiteSpace(x))
                                         .Select(x => x.TrimEnd('\\', '/')).ToArray();
        }

        /// <returns>null si hay que analizarlo; si no, el motivo para ignorarlo.</returns>
        public string? MotivoParaIgnorar(string ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta)) return "ruta vacia";

            // Los archivos temporales de descarga y copia no son el archivo final: su renombrado si llegara.
            string ext = ExtensionDe(ruta);
            if (ext.Length == 0) return "sin extension";
            if (!_extensiones.Contains(ext)) return "extension no vigilada";

            foreach (string x in _excluidas)
                if (ruta.Equals(x, StringComparison.OrdinalIgnoreCase)
                    || ruta.StartsWith(x + "\\", StringComparison.OrdinalIgnoreCase)
                    || ruta.StartsWith(x + "/", StringComparison.OrdinalIgnoreCase))
                    return "carpeta excluida";

            return null;
        }

        /// <summary>Extension en minusculas con el punto, o vacia. Funciona igual con '\' y con '/'.</summary>
        internal static string ExtensionDe(string ruta)
        {
            int sep = ruta.LastIndexOfAny(new[] { '\\', '/' });
            string nombre = sep >= 0 ? ruta[(sep + 1)..] : ruta;
            int punto = nombre.LastIndexOf('.');
            return punto > 0 && punto < nombre.Length - 1 ? nombre[punto..].ToLowerInvariant() : "";
        }
    }
}
