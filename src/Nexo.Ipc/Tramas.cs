using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ipc
{
    /// <summary>
    /// Mensajes delimitados por longitud: 4 bytes (little-endian) con el tamano del
    /// cuerpo y despues el cuerpo en JSON UTF-8. Un tamano 0 o por encima del maximo
    /// es una violacion del protocolo: no se intenta resincronizar, se cierra.
    /// </summary>
    public static class Tramas
    {
        public const int MaxBytes = 1024 * 1024;

        public sealed class ViolacionDeProtocoloException : Exception
        {
            public ViolacionDeProtocoloException(string mensaje) : base(mensaje) { }
        }

        public static async Task EscribirAsync(Stream destino, ReadOnlyMemory<byte> cuerpo, CancellationToken ct)
        {
            if (cuerpo.Length == 0 || cuerpo.Length > MaxBytes)
                throw new ViolacionDeProtocoloException("mensaje de " + cuerpo.Length + " bytes fuera de limite");

            byte[] trama = new byte[4 + cuerpo.Length];
            BinaryPrimitives.WriteInt32LittleEndian(trama, cuerpo.Length);
            cuerpo.CopyTo(trama.AsMemory(4));
            await destino.WriteAsync(trama, ct).ConfigureAwait(false);
            await destino.FlushAsync(ct).ConfigureAwait(false);
        }

        /// <returns>El cuerpo, o null si el otro lado cerro limpiamente entre mensajes.</returns>
        public static async Task<byte[]?> LeerAsync(Stream origen, CancellationToken ct)
        {
            byte[] cabecera = new byte[4];
            int leidos = await LeerHastaAsync(origen, cabecera, ct).ConfigureAwait(false);
            if (leidos == 0) return null;
            if (leidos < 4) throw new ViolacionDeProtocoloException("cabecera incompleta");

            int largo = BinaryPrimitives.ReadInt32LittleEndian(cabecera);
            if (largo <= 0 || largo > MaxBytes)
                throw new ViolacionDeProtocoloException("tamano de mensaje invalido: " + largo);

            byte[] cuerpo = new byte[largo];
            if (await LeerHastaAsync(origen, cuerpo, ct).ConfigureAwait(false) < largo)
                throw new ViolacionDeProtocoloException("mensaje truncado");
            return cuerpo;
        }

        private static async Task<int> LeerHastaAsync(Stream s, byte[] buffer, CancellationToken ct)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int n = await s.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
            }
            return total;
        }

        public static string Texto(byte[] cuerpo) => new UTF8Encoding(false, true).GetString(cuerpo);
    }
}
