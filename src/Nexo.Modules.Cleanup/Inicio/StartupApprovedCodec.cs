using System;
using System.Buffers.Binary;

namespace Nexo.Modules.Cleanup.Inicio
{
    /// <summary>
    /// Lee y escribe el valor binario de <c>...\Explorer\StartupApproved\{Run,Run32,StartupFolder}</c>.
    ///
    /// Es el mismo indicador que usa la pestana "Inicio" del Administrador de
    /// tareas. Son 12 bytes: el primero manda (0x02/0x06 habilitado, 0x03
    /// deshabilitado) y los ultimos 8 guardan, como FILETIME, cuando se deshabilito.
    ///
    /// Si el valor no existe, Windows lo considera habilitado.
    /// </summary>
    public static class StartupApprovedCodec
    {
        public const int Largo = 12;

        public static EstadoDeInicio Leer(byte[]? datos)
        {
            if (datos is null) return EstadoDeInicio.Habilitada;   // sin valor = habilitado
            if (datos.Length == 0) return EstadoDeInicio.Desconocida;

            return datos[0] switch
            {
                0x02 or 0x06 => EstadoDeInicio.Habilitada,
                0x03 => EstadoDeInicio.Deshabilitada,
                _ => EstadoDeInicio.Desconocida
            };
        }

        public static byte[] Escribir(bool habilitada, DateTimeOffset ahora)
        {
            var datos = new byte[Largo];
            datos[0] = habilitada ? (byte)0x02 : (byte)0x03;

            // El Administrador de tareas deja la marca de tiempo en cero al
            // habilitar y la fecha de deshabilitado al deshabilitar.
            if (!habilitada)
                BinaryPrimitives.WriteInt64LittleEndian(datos.AsSpan(4), ahora.UtcDateTime.ToFileTimeUtc());

            return datos;
        }

        /// <summary>Cuando se deshabilito, o null si el valor no lo registra.</summary>
        public static DateTimeOffset? FechaDeshabilitado(byte[]? datos)
        {
            if (datos is null || datos.Length < Largo || datos[0] != 0x03) return null;
            long ft = BinaryPrimitives.ReadInt64LittleEndian(datos.AsSpan(4));
            return ft <= 0 ? null : DateTimeOffset.FromFileTime(ft);
        }
    }
}
