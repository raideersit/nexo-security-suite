using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Nexo.Native.Storage
{
    /// <summary>
    /// Consultas de bajo nivel sobre el dispositivo de almacenamiento de un volumen.
    ///
    /// Se usa IOCTL_STORAGE_QUERY_PROPERTY con StorageDeviceSeekPenaltyProperty:
    /// un disco magnetico "incurre en penalizacion de busqueda" (el cabezal se
    /// mueve) y un SSD no. Es la misma pregunta que hace la herramienta de
    /// desfragmentacion de Windows para decidir si optimiza o hace TRIM.
    ///
    /// No necesita administrador: se abre el volumen con acceso 0, que solo da
    /// derecho a consultar propiedades, no a leer ni escribir datos.
    /// </summary>
    public static class StorageQuery
    {
        private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
        private const int StorageDeviceSeekPenaltyProperty = 7;
        private const int PropertyStandardQuery = 0;

        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint OPEN_EXISTING = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_PROPERTY_QUERY
        {
            public int PropertyId;
            public int QueryType;
            public byte AdditionalParameters;   // la API declara un arreglo de 1 byte
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DEVICE_SEEK_PENALTY_DESCRIPTOR
        {
            public uint Version;
            public uint Size;
            [MarshalAs(UnmanagedType.U1)] public bool IncursSeekPenalty;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice, uint dwIoControlCode,
            ref STORAGE_PROPERTY_QUERY lpInBuffer, int nInBufferSize,
            out DEVICE_SEEK_PENALTY_DESCRIPTOR lpOutBuffer, int nOutBufferSize,
            out int lpBytesReturned, IntPtr lpOverlapped);

        /// <summary>
        /// true = disco magnetico, false = SSD, null = no se pudo determinar
        /// (puente USB que no pasa el comando, controladora RAID, volumen virtual…).
        /// </summary>
        /// <param name="letraUnidad">Letra de unidad, por ejemplo 'C'.</param>
        public static bool? IncurreEnPenalizacionDeBusqueda(char letraUnidad)
        {
            if (!char.IsAsciiLetter(letraUnidad)) return null;

            using SafeFileHandle volumen = CreateFileW(
                @"\\.\" + char.ToUpperInvariant(letraUnidad) + ":",
                dwDesiredAccess: 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

            if (volumen.IsInvalid) return null;

            var consulta = new STORAGE_PROPERTY_QUERY
            {
                PropertyId = StorageDeviceSeekPenaltyProperty,
                QueryType = PropertyStandardQuery,
                AdditionalParameters = 0
            };

            bool ok = DeviceIoControl(
                volumen, IOCTL_STORAGE_QUERY_PROPERTY,
                ref consulta, Marshal.SizeOf<STORAGE_PROPERTY_QUERY>(),
                out DEVICE_SEEK_PENALTY_DESCRIPTOR resultado,
                Marshal.SizeOf<DEVICE_SEEK_PENALTY_DESCRIPTOR>(),
                out _, IntPtr.Zero);

            // Un fallo aqui es normal en varios tipos de dispositivo (puentes USB,
            // RAID): no es una excepcion, simplemente no se sabe.
            return ok ? resultado.IncursSeekPenalty : null;
        }
    }
}
