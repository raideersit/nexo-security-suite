using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Ui.Tray.Nucleo
{
    // Sin dependencias de Windows ni del pipe: Nexo.Ui.Desktop compila este archivo tambien para Linux.

    /// <summary>Que carpetas se escanean para revisar lo que el tiempo real perdio o no pudo analizar.</summary>
    public static class RevisionDeLoNoVisto
    {
        /// <summary>Lo que acepta escaneo.iniciar por peticion (ModuloEscaneo.MaxRutas).</summary>
        public const int MaxRutasPorEscaneo = 8;

        /// <summary>
        /// Las carpetas a escanear: sin las que ya estan dentro de otra, y como maximo <see cref="MaxRutasPorEscaneo"/>.
        /// Lo que no quepa sigue por revisar y se hace en otra pasada.
        /// </summary>
        public static IReadOnlyList<string> RutasParaRevisar(IEnumerable<string> carpetas)
        {
            var distintas = carpetas.Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.TrimEnd('\\'))
                                    .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c.Length).ToList();
            var elegidas = new List<string>();
            foreach (string c in distintas)
                if (!elegidas.Any(e => c.StartsWith(e + "\\", StringComparison.OrdinalIgnoreCase)))
                    elegidas.Add(c);
            return elegidas.Take(MaxRutasPorEscaneo).ToList();
        }
    }
}
