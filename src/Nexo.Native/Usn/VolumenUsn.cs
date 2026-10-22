using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Nexo.Native.Usn
{
    /// <summary>Datos del diario USN de un volumen (USN_JOURNAL_DATA).</summary>
    public readonly record struct DatosDelDiario(ulong IdDelDiario, long PrimerUsn, long SiguienteUsn);

    /// <summary>
    /// Acceso al diario USN de un volumen NTFS: el registro que NTFS mantiene de cada cambio de
    /// archivo. A diferencia de FileSystemWatcher no tiene buffer que se desborde: se lee
    /// desde un USN y, si el diario ya sobrescribio lo que se pedia, se sabe (error 1181).
    ///
    /// Abrir el volumen EXIGE administrador (o SYSTEM, que es como corre el servicio). Sin eso
    /// <see cref="Abrir"/> devuelve el codigo de error en vez de lanzar, para que quien llama
    /// lo informe en vez de fingir que vigila.
    ///
    /// NOTA: esta capa habla con el sistema y solo se puede ejercitar elevada; la decodificacion
    /// del buffer (la parte con riesgo de desbordes) vive aparte, es portable y esta probada.
    /// </summary>
    public sealed class VolumenUsn : IDisposable
    {
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2, FILE_SHARE_DELETE = 0x4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_READ_ATTRIBUTES = 0x80;

        private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;

        public const int ErrorAccesoDenegado = 5;
        public const int ErrorDiarioNoActivo = 1179;
        public const int ErrorBorrandoDiario = 1178;
        public const int ErrorEntradaDelDiarioBorrada = 1181;
        public const int ErrorEsperaAgotada = 258;

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        private struct FILE_ID_DESCRIPTOR
        {
            [FieldOffset(0)] public uint dwSize;
            [FieldOffset(4)] public uint Type;        // 0 = FileIdType
            [FieldOffset(8)] public ulong FileId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string nombre, uint acceso, uint compartir, IntPtr seguridad,
            uint creacion, uint banderas, IntPtr plantilla);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(SafeFileHandle h, uint codigo, byte[] entrada, int tamEntrada,
            byte[] salida, int tamSalida, out int devueltos, IntPtr superpuesto);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle OpenFileById(SafeFileHandle pista, ref FILE_ID_DESCRIPTOR id, uint acceso,
            uint compartir, IntPtr seguridad, uint banderas);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder ruta, uint tam, uint banderas);

        private readonly SafeFileHandle _volumen;

        private VolumenUsn(SafeFileHandle volumen) => _volumen = volumen;

        /// <summary>Abre el volumen. null + codigo Win32 si no se pudo (5 = hace falta administrador).</summary>
        public static VolumenUsn? Abrir(char letra, out int error)
        {
            error = 0;
            if (!char.IsAsciiLetter(letra)) { error = 87; return null; }

            SafeFileHandle h = CreateFileW(@"\\.\" + char.ToUpperInvariant(letra) + ":", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid)
            {
                error = Marshal.GetLastWin32Error();
                h.Dispose();
                return null;
            }
            return new VolumenUsn(h);
        }

        public DatosDelDiario? Consultar(out int error)
        {
            byte[] salida = new byte[80];
            if (!DeviceIoControl(_volumen, FSCTL_QUERY_USN_JOURNAL, Array.Empty<byte>(), 0, salida, salida.Length, out _, IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                return null;
            }
            error = 0;
            // USN_JOURNAL_DATA_V0: UsnJournalID(8) FirstUsn(8) NextUsn(8) ...
            return new DatosDelDiario(BitConverter.ToUInt64(salida, 0), BitConverter.ToInt64(salida, 8), BitConverter.ToInt64(salida, 16));
        }

        /// <summary>
        /// Lee registros a partir de <paramref name="desde"/>. Solo los que cierran un archivo
        /// (ReturnOnlyOnClose): llegan cuando el programa termino de escribir, que es justo cuando
        /// se puede analizar sin ver el archivo a medias.
        /// </summary>
        /// <returns>Bytes devueltos (el buffer lo decodifica ParserDeUsn), o -1 con el codigo de error.</returns>
        public int Leer(long desde, ulong idDelDiario, uint mascaraDeMotivos, byte[] buffer, int esperaSegundos, out int error)
        {
            // READ_USN_JOURNAL_DATA_V1, pidiendo solo registros V2 (FRN de 64 bits).
            byte[] entrada = new byte[44];
            BitConverter.TryWriteBytes(entrada.AsSpan(0), desde);
            BitConverter.TryWriteBytes(entrada.AsSpan(8), mascaraDeMotivos);
            BitConverter.TryWriteBytes(entrada.AsSpan(12), 1u);                         // ReturnOnlyOnClose
            BitConverter.TryWriteBytes(entrada.AsSpan(16), (ulong)esperaSegundos);      // Timeout (segundos)
            BitConverter.TryWriteBytes(entrada.AsSpan(24), 1ul);                        // BytesToWaitFor: espera a que haya algo
            BitConverter.TryWriteBytes(entrada.AsSpan(32), idDelDiario);
            BitConverter.TryWriteBytes(entrada.AsSpan(40), (ushort)2);                  // MinMajorVersion
            BitConverter.TryWriteBytes(entrada.AsSpan(42), (ushort)2);                  // MaxMajorVersion

            if (!DeviceIoControl(_volumen, FSCTL_READ_USN_JOURNAL, entrada, entrada.Length, buffer, buffer.Length, out int n, IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                return -1;
            }
            error = 0;
            return n;
        }

        /// <summary>Ruta completa de un archivo o carpeta a partir de su numero de referencia, o null si ya no existe.</summary>
        public string? RutaDe(ulong frn)
        {
            var id = new FILE_ID_DESCRIPTOR { dwSize = 24, Type = 0, FileId = frn };
            using SafeFileHandle h = OpenFileById(_volumen, ref id, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, FILE_FLAG_BACKUP_SEMANTICS);
            if (h.IsInvalid) return null;

            var sb = new StringBuilder(520);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            if (n >= sb.Capacity)
            {
                sb = new StringBuilder((int)n + 1);
                if (GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0) == 0) return null;
            }

            string r = sb.ToString();
            return r.StartsWith(@"\\?\", StringComparison.Ordinal) ? r[4..] : r;
        }

        public static string DescribirError(int codigo) => codigo switch
        {
            ErrorAccesoDenegado => "acceso denegado (hace falta administrador)",
            ErrorDiarioNoActivo => "el diario USN no esta activo en ese volumen",
            ErrorBorrandoDiario => "el diario USN se esta borrando",
            ErrorEntradaDelDiarioBorrada => "el diario ya sobrescribio las entradas pedidas",
            _ => new Win32Exception(codigo).Message
        };

        public void Dispose() => _volumen.Dispose();
    }
}
