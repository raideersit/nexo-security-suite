using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Identity.Autocompletado
{
    /// <summary>
    /// El formato de «native messaging» de Chromium (Brave, Edge, Chrome): cada mensaje es su longitud en 4 bytes (orden del sistema:
    /// little-endian en Windows) seguida de JSON en UTF-8. El navegador manda como mucho 4 GB y acepta como mucho 1 MB del programa;
    /// Nexo es más estricto: ningún mensaje de la extensión necesita más de <see cref="MaxEntrada"/>.
    ///
    /// Lo que llega por aquí lo controla cualquier página que engañe a la extensión, así que no se confía en ninguna longitud.
    /// </summary>
    public static class MensajeNativo
    {
        public const int MaxEntrada = 64 * 1024;
        /// <summary>El límite de Chromium para lo que manda el programa al navegador.</summary>
        public const int MaxSalida = 1024 * 1024;

        /// <summary>Lee un mensaje. null si el navegador cerró la entrada limpiamente (entre mensajes).</summary>
        /// <exception cref="InvalidDataException">Longitud 0, mayor que el máximo, o el mensaje se cortó a medias.</exception>
        public static Task<byte[]?> LeerAsync(Stream entrada, CancellationToken ct = default) => LeerAsync(entrada, MaxEntrada, ct);

        /// <summary>Igual, con otro tope (p. ej. <see cref="MaxSalida"/> para leer la respuesta de la ventana, que puede pasar de 64 KB).</summary>
        public static async Task<byte[]?> LeerAsync(Stream entrada, int maximo, CancellationToken ct)
        {
            if (maximo <= 0 || maximo > MaxSalida) throw new ArgumentOutOfRangeException(nameof(maximo));
            byte[] cabecera = new byte[4];
            int leidos = await LeerTodoAsync(entrada, cabecera, ct).ConfigureAwait(false);
            if (leidos == 0) return null;
            if (leidos < 4) throw new InvalidDataException("cabecera cortada");
            uint largo = BinaryPrimitives.ReadUInt32LittleEndian(cabecera);
            if (largo == 0 || largo > (uint)maximo) throw new InvalidDataException("longitud no válida: " + largo);
            byte[] cuerpo = new byte[largo];
            if (await LeerTodoAsync(entrada, cuerpo, ct).ConfigureAwait(false) != largo) throw new InvalidDataException("mensaje cortado");
            return cuerpo;
        }

        public static async Task EscribirAsync(Stream salida, byte[] json, CancellationToken ct = default)
        {
            if (json.Length == 0 || json.Length > MaxSalida) throw new ArgumentOutOfRangeException(nameof(json), "mensaje vacío o mayor que 1 MB");
            byte[] cabecera = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(cabecera, (uint)json.Length);
            await salida.WriteAsync(cabecera, ct).ConfigureAwait(false);
            await salida.WriteAsync(json, ct).ConfigureAwait(false);
            await salida.FlushAsync(ct).ConfigureAwait(false);
        }

        private static async Task<int> LeerTodoAsync(Stream s, byte[] b, CancellationToken ct)
        {
            int total = 0;
            while (total < b.Length)
            {
                int n = await s.ReadAsync(b.AsMemory(total), ct).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
            }
            return total;
        }
    }
}
