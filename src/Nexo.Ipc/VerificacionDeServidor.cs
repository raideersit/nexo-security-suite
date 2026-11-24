using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace Nexo.Ipc
{
    /// <summary>
    /// Comprueba QUIEN esta al otro lado del pipe antes de mandarle nada.
    ///
    /// Por que hace falta: la ACL del pipe dice quien puede CONECTAR, no quien puede CREARLO PRIMERO. Si el servicio no esta
    /// corriendo (esta en inicio manual por omision), un proceso normal del usuario puede crear un pipe con el mismo nombre
    /// y quedarse con lo que el cliente le mande: la identidad del usuario (nivel Impersonation) y las peticiones. Tambien
    /// puede contestar «todo en orden» a la bandeja y a la ventana.
    ///
    /// Que se comprueba: la ruta del ejecutable del proceso servidor. Debe estar dentro de una carpeta de confianza (por
    /// omision, Archivos de programa), que un usuario normal no puede modificar: el instalador ya se niega a instalar el
    /// servicio en una carpeta modificable. Se lee con PROCESS_QUERY_LIMITED_INFORMATION, que un usuario normal tiene
    /// sobre un proceso de SYSTEM (no hace falta abrir su token, que un usuario normal no puede abrir).
    ///
    /// Limite: protege frente a procesos que no sean administradores. Uno con permisos de administrador puede
    /// todo lo demas de todos modos.
    /// </summary>
    public static class VerificacionDeServidor
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint acceso, bool heredar, uint pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(IntPtr proceso, uint banderas, StringBuilder ruta, ref int tamano);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr objeto);

        /// <summary>Carpetas donde puede vivir el ejecutable del servicio. Solo debe contener carpetas que un usuario normal no pueda escribir.</summary>
        public static IReadOnlyList<string> CarpetasDeConfianzaPorOmision()
        {
            var l = new List<string>();
            foreach (Environment.SpecialFolder f in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                string p = Environment.GetFolderPath(f);
                if (!string.IsNullOrEmpty(p)) l.Add(p);
            }
            return l;
        }

        /// <summary>Si el proceso que atiende ese pipe esta en una carpeta de confianza. null = si; si no, el motivo.</summary>
        /// <param name="pipe">Un cliente YA conectado.</param>
        public static string? Comprobar(NamedPipeClientStream pipe, IEnumerable<string>? carpetasDeConfianza = null)
        {
            if (!OperatingSystem.IsWindows()) return null;   // el servicio y su pipe son solo de Windows

            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid) || pid == 0)
                return "no se pudo saber que proceso atiende el pipe (error " + Marshal.GetLastWin32Error() + ")";

            IntPtr proceso = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (proceso == IntPtr.Zero)
                return "no se pudo abrir el proceso " + pid + " del servidor (error " + Marshal.GetLastWin32Error() + ")";
            try
            {
                var ruta = new StringBuilder(1024);
                int tamano = ruta.Capacity;
                if (!QueryFullProcessImageNameW(proceso, 0, ruta, ref tamano))
                    return "no se pudo leer la ruta del proceso " + pid + " (error " + Marshal.GetLastWin32Error() + ")";

                string exe = Path.GetFullPath(ruta.ToString());
                foreach (string carpeta in carpetasDeConfianza ?? CarpetasDeConfianzaPorOmision())
                {
                    string c = Path.TrimEndingDirectorySeparator(Path.GetFullPath(carpeta)) + Path.DirectorySeparatorChar;
                    if (exe.StartsWith(c, StringComparison.OrdinalIgnoreCase)) return null;
                }
                return "el proceso " + pid + " que atiende el pipe corre desde «" + exe + "», que no es una carpeta de confianza";
            }
            finally { CloseHandle(proceso); }
        }
    }
}
