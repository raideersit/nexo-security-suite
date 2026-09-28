using System;
using System.Runtime.InteropServices;

namespace Nexo.Native.Shell
{
    /// <summary>
    /// Envoltura de SHFileOperation para enviar archivos a la Papelera de reciclaje.
    ///
    /// Por que la Papelera y no File.Delete: es la unica red de seguridad real ante
    /// un bug en el catalogo de rutas. File.Delete es irreversible; esto no.
    /// El borrado permanente existe, pero es una eleccion explicita del usuario.
    ///
    /// Se usa SHFileOperation (ANSI/Unicode, disponible desde Windows 2000) y no
    /// IFileOperation (COM, Vista+) porque para esta operacion concreta la API
    /// antigua no esta deprecada, no requiere apartamento COM y acepta una lista
    /// de rutas en una sola llamada, que es exactamente lo que necesitamos.
    /// </summary>
    public static class ShellFileOperations
    {
        private const uint FO_DELETE = 0x0003;

        // Envia a la papelera en vez de borrar definitivamente.
        private const ushort FOF_ALLOWUNDO = 0x0040;
        // Sin dialogos: la confirmacion ya la dio el usuario en la vista previa de Nexo.
        private const ushort FOF_NOCONFIRMATION = 0x0010;
        private const ushort FOF_SILENT = 0x0004;
        private const ushort FOF_NOERRORUI = 0x0400;
        // No mostrar la ruta completa en los (inexistentes) dialogos de error.
        private const ushort FOF_SIMPLEPROGRESS = 0x0100;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            public uint wFunc;
            [MarshalAs(UnmanagedType.LPWStr)] public string pFrom;
            [MarshalAs(UnmanagedType.LPWStr)] public string? pTo;
            public ushort fFlags;
            [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszProgressTitle;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int SHFileOperationW(ref SHFILEOPSTRUCT lpFileOp);

        /// <summary>
        /// Envia archivos a la Papelera. Devuelve el codigo de SHFileOperation
        /// (0 = exito) y si el usuario o el shell abortaron la operacion.
        /// </summary>
        /// <param name="rutas">
        /// Rutas absolutas. Se empaquetan en una cadena con doble terminador nulo,
        /// que es el formato que exige la API; una sola llamada para toda la lista
        /// evita N ventanas de progreso y N viajes al shell.
        /// </param>
        public static (int Codigo, bool Abortado) EnviarAPapelera(string[] rutas)
        {
            if (rutas is null) throw new ArgumentNullException(nameof(rutas));
            if (rutas.Length == 0) return (0, false);

            // pFrom: "ruta1\0ruta2\0...\0\0"
            string pFrom = string.Join("\0", rutas) + "\0\0";

            var op = new SHFILEOPSTRUCT
            {
                hwnd = IntPtr.Zero,
                wFunc = FO_DELETE,
                pFrom = pFrom,
                pTo = null,
                fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
                         | FOF_NOERRORUI | FOF_SIMPLEPROGRESS,
                fAnyOperationsAborted = false,
                hNameMappings = IntPtr.Zero,
                lpszProgressTitle = null
            };

            int resultado = SHFileOperationW(ref op);
            return (resultado, op.fAnyOperationsAborted);
        }
    }
}
