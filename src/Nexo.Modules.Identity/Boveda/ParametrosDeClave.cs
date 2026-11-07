using System;

namespace Nexo.Modules.Identity.Boveda
{
    /// <summary>
    /// Costo de Argon2id para derivar la clave de la boveda. Los valores por omision siguen las recomendaciones de OWASP
    /// (memoria alta, pocas iteraciones). Se guardan en el archivo para poder subirlos mas adelante sin romper bovedas
    /// viejas, y al LEER se acotan: un archivo malicioso no puede pedir gigas de memoria para colgar el equipo.
    /// </summary>
    public sealed record ParametrosDeClave(int MemoriaKiB, int Iteraciones, int Paralelismo)
    {
        /// <summary>64 MiB, 3 iteraciones, 2 hilos: ~0,3 s en un equipo normal.</summary>
        public static ParametrosDeClave Seguros { get; } = new(64 * 1024, 3, 2);

        /// <summary>Minimo para CREAR una boveda (OWASP: 19 MiB, t=2, p=1). Solo las pruebas lo rebajan, y lo piden a gritos.</summary>
        public const int MemoriaMinimaKiB = 19 * 1024;
        public const int IteracionesMinimas = 2;

        /// <summary>Techo al LEER un archivo: protege contra un archivo hecho para agotar la memoria o el tiempo.</summary>
        public const int MemoriaMaximaKiB = 1024 * 1024;
        public const int IteracionesMaximas = 12;
        public const int ParalelismoMaximo = 8;

        /// <summary>Cota de cordura al leer: que el archivo no pida menos de lo que Argon2 admite.</summary>
        public const int MemoriaMinimaAlLeerKiB = 64;

        /// <summary>true si caen dentro de lo que se acepta al abrir un archivo.</summary>
        public bool EsLegible =>
            Paralelismo is >= 1 and <= ParalelismoMaximo
            && Iteraciones is >= 1 and <= IteracionesMaximas
            && MemoriaKiB >= Math.Max(MemoriaMinimaAlLeerKiB, 8 * Paralelismo) && MemoriaKiB <= MemoriaMaximaKiB;

        /// <summary>true si son aceptables para crear una boveda real.</summary>
        public bool EsSeguro => EsLegible && MemoriaKiB >= MemoriaMinimaKiB && Iteraciones >= IteracionesMinimas;
    }
}
