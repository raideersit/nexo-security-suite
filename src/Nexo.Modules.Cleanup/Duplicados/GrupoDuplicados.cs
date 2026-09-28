using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Cleanup.Duplicados
{
    /// <summary>Un conjunto de archivos con contenido byte a byte identico.</summary>
    public sealed class GrupoDuplicados
    {
        public GrupoDuplicados(string hash, long bytesPorArchivo, IReadOnlyList<string> rutas)
        {
            Hash = hash;
            BytesPorArchivo = bytesPorArchivo;
            Rutas = rutas;
        }

        /// <summary>SHA-256 del contenido completo.</summary>
        public string Hash { get; }

        public long BytesPorArchivo { get; }

        /// <summary>Ordenadas: la primera es la que se propone conservar (la mas antigua).</summary>
        public IReadOnlyList<string> Rutas { get; }

        public int Copias => Rutas.Count;

        /// <summary>Espacio que se liberaria dejando una sola copia.</summary>
        public long BytesRecuperables => BytesPorArchivo * (Copias - 1);

        public string Conservar => Rutas[0];
        public IEnumerable<string> Sobrantes => Rutas.Skip(1);
    }
}
