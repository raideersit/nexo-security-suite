using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>
    /// Interpreta el bloque <c>VendorSpecific</c> de <c>MSStorageDriver_FailurePredictData</c>.
    ///
    /// Son 512 bytes: 2 de version y despues hasta 30 atributos de 12 bytes. Cada
    /// atributo es: id (1), flags (2, little-endian), valor (1), peor (1),
    /// crudo (6, little-endian) y 1 reservado. Un id 0 marca un hueco.
    /// </summary>
    public static class SmartParser
    {
        public const int OffsetPrimerAtributo = 2;
        public const int LargoAtributo = 12;
        public const int MaxAtributos = 30;
        public const int LargoMinimo = OffsetPrimerAtributo + MaxAtributos * LargoAtributo;   // 362

        /// <returns>false si el bloque es nulo o mas corto de lo que define la estructura.</returns>
        public static bool TryAnalizar(byte[]? datos, out IReadOnlyList<AtributoSmart> atributos)
        {
            var lista = new List<AtributoSmart>();
            atributos = lista;

            if (datos is null || datos.Length < LargoMinimo) return false;

            // 6 bytes little-endian a ulong: se rellena hasta 8 con ceros. El buffer
            // se reserva una vez fuera del bucle (CA2014).
            Span<byte> crudo8 = stackalloc byte[8];

            for (int i = 0; i < MaxAtributos; i++)
            {
                int o = OffsetPrimerAtributo + i * LargoAtributo;
                byte id = datos[o];
                if (id == 0) continue;

                ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(datos.AsSpan(o + 1, 2));

                crudo8.Clear();
                datos.AsSpan(o + 5, 6).CopyTo(crudo8);
                ulong crudo = BinaryPrimitives.ReadUInt64LittleEndian(crudo8);

                lista.Add(new AtributoSmart(id, flags, datos[o + 3], datos[o + 4], crudo));
            }
            return true;
        }
    }
}
