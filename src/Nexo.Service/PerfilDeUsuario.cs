using System;
using System.IO;
using System.Security.Principal;
using Microsoft.Win32;
using Nexo.Modules.Cleanup.Junk;

namespace Nexo.Service
{
    /// <summary>
    /// Las carpetas del PERFIL DEL USUARIO que llama, no las de la cuenta del servicio. Si el servicio
    /// preguntara por «mi carpeta AppData» (Environment.GetFolderPath) obtendria la de SYSTEM y limpiaria
    /// otra cosa. Se resuelven por el SID del llamador en la lista de perfiles del registro de Windows.
    ///
    /// Limite: se usan las subcarpetas estandar (AppData\Local, AppData\Roaming). Si el usuario tiene
    /// esas carpetas REDIRIGIDAS a otro sitio (poco habitual fuera de dominios) no se siguen.
    /// </summary>
    public static class PerfilDeUsuario
    {
        private const string ListaDePerfiles = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\";

        /// <summary>Carpeta del perfil de ese usuario, o null si no tiene (o no es una ruta absoluta existente).</summary>
        public static string? RutaDe(SecurityIdentifier sid)
        {
            try
            {
                using RegistryKey? k = Registry.LocalMachine.OpenSubKey(ListaDePerfiles + sid.Value, writable: false);
                if (k?.GetValue("ProfileImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string cruda) return null;

                string ruta = Environment.ExpandEnvironmentVariables(cruda);
                // Una ruta absoluta con letra de unidad y que exista: nada relativo ni de red.
                if (ruta.Length < 3 || !char.IsAsciiLetter(ruta[0]) || ruta[1] != ':' || ruta[2] != '\\') return null;
                return Directory.Exists(ruta) ? Path.GetFullPath(ruta) : null;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException || ex is UnauthorizedAccessException || ex is IOException)
            {
                return null;
            }
        }

        /// <summary>
        /// Las bases del catalogo para ese usuario. Lo compartido (ProgramData, Windows) es del equipo; lo demas,
        /// del perfil. Null si no se pudo localizar el perfil: sin perfil no se limpia nada.
        /// </summary>
        public static System.Collections.Generic.IReadOnlyDictionary<BaseDeRuta, string>? BasesDe(SecurityIdentifier sid)
        {
            string? perfil = RutaDe(sid);
            if (perfil is null) return null;

            var d = new System.Collections.Generic.Dictionary<BaseDeRuta, string>
            {
                [BaseDeRuta.UserProfile] = perfil,
                [BaseDeRuta.LocalAppData] = Path.Combine(perfil, "AppData", "Local"),
                [BaseDeRuta.RoamingAppData] = Path.Combine(perfil, "AppData", "Roaming"),
                [BaseDeRuta.ProgramData] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            };
            string? sistema = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(sistema)) d[BaseDeRuta.SystemRoot] = sistema;
            return d;
        }
    }
}
