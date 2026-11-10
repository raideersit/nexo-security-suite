using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Nexo.Native.Files
{
    /// <summary>
    /// El número de archivo de NTFS (FileId de 64 bits): no cambia al renombrar ni al mover dentro del mismo volumen, y lleva
    /// un número de secuencia, así que no se confunde con un archivo nuevo que reutilice la misma entrada. Sirve para saber
    /// a dónde se fue un archivo que ya no está en su sitio.
    ///
    /// NO exige administrador: abrir por número (OpenFileById) comprueba los permisos del archivo de destino, como abrirlo
    /// por su ruta. Las funciones no lanzan: devuelven null y el código Win32, para que quien llama lo cuente.
    /// </summary>
    public static class NumeroDeArchivo
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2, FILE_SHARE_DELETE = 0x4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        public const int ErrorNoEncontrado = 2;
        public const int ErrorRutaNoEncontrada = 3;
        public const int ErrorParametroIncorrecto = 87;

        // Pack = 4: los FILETIME son dos DWORD (alineados a 4). Con «long» sin Pack se colaba un relleno tras dwFileAttributes y el
        // número de archivo salía corrido (la mitad baja siempre 0): lo cazó la prueba real (§2am).
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public long ftCreationTime, ftLastAccessTime, ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh, nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh, nFileIndexLow;
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        private struct FILE_ID_DESCRIPTOR
        {
            [FieldOffset(0)] public uint dwSize;
            [FieldOffset(4)] public uint Type;        // 0 = FileIdType (64 bits)
            [FieldOffset(8)] public ulong FileId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string nombre, uint acceso, uint compartir, IntPtr seguridad,
            uint creacion, uint banderas, IntPtr plantilla);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle OpenFileById(SafeFileHandle pista, ref FILE_ID_DESCRIPTOR id, uint acceso,
            uint compartir, IntPtr seguridad, uint banderas);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder ruta, uint tam, uint banderas);

        /// <summary>Número de archivo de <paramref name="ruta"/> (sin seguir enlaces), o null con el código de error.</summary>
        public static ulong? De(string ruta, out int error)
        {
            using SafeFileHandle h = CreateFileW(ruta, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (h.IsInvalid) { error = Marshal.GetLastWin32Error(); return null; }
            return De(h, out error);
        }

        /// <summary>Número de archivo de un manejador ya abierto.</summary>
        public static ulong? De(SafeFileHandle h, out int error)
        {
            if (!GetFileInformationByHandle(h, out BY_HANDLE_FILE_INFORMATION i)) { error = Marshal.GetLastWin32Error(); return null; }
            error = 0;
            return ((ulong)i.nFileIndexHigh << 32) | i.nFileIndexLow;
        }

        /// <summary>
        /// Ruta actual del archivo con ese número, en el volumen de <paramref name="pistaEnElVolumen"/> (cualquier carpeta del volumen).
        /// null con <paramref name="error"/> = 0: no existe (ni con otro nombre). null con otro código: no se pudo saber.
        /// </summary>
        public static string? RutaPorNumero(string pistaEnElVolumen, ulong numero, out int error)
        {
            using SafeFileHandle pista = CreateFileW(pistaEnElVolumen, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (pista.IsInvalid) { error = Marshal.GetLastWin32Error(); return null; }

            var id = new FILE_ID_DESCRIPTOR { dwSize = 24, Type = 0, FileId = numero };
            using SafeFileHandle h = OpenFileById(pista, ref id, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            if (h.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                // Un número que ya no existe (o cuya secuencia cambió) da «parámetro incorrecto» o «no encontrado»: es «no existe».
                error = e is ErrorParametroIncorrecto or ErrorNoEncontrado or ErrorRutaNoEncontrada ? 0 : e;
                return null;
            }

            var sb = new StringBuilder(520);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n >= sb.Capacity)
            {
                sb = new StringBuilder((int)n + 1);
                n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            }
            if (n == 0) { error = Marshal.GetLastWin32Error(); if (error == 0) error = -1; return null; }

            error = 0;
            string r = sb.ToString();
            if (r.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + r[8..];
            return r.StartsWith(@"\\?\", StringComparison.Ordinal) ? r[4..] : r;
        }

        public static string Describir(int codigo) => codigo switch
        {
            5 => "acceso denegado",
            -1 => "Windows no devolvió la ruta",
            _ => new Win32Exception(codigo).Message
        };
    }
}
