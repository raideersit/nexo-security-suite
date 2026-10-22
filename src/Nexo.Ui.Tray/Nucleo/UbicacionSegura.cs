using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Nexo.Ui.Tray.Nucleo
{
    /// <summary>
    /// ¿Puede un proceso NORMAL del usuario reescribir este ejecutable o su carpeta? La bandeja se relanza elevada
    /// (aviso de UAC) a si misma: si un proceso del usuario pudiera sustituir ese .exe, el aviso de UAC diria «Nexo» y
    /// ejecutaria con permisos de administrador lo que el atacante haya puesto. Por eso solo se eleva desde una
    /// ubicacion que el usuario no pueda modificar (p. ej. Program Files).
    ///
    /// Se considera que puede escribir si hay una regla que PERMITE escribir, borrar o cambiar permisos a: el propio
    /// usuario, Usuarios, Todos, Usuarios autenticados, Interactivo o cualquier otro grupo de su token, salvo
    /// Administradores, SYSTEM y TrustedInstaller (un proceso sin elevar no actua como ellos). Si no se puede
    /// comprobar, se asume que NO es segura.
    /// </summary>
    public static class UbicacionSegura
    {
        private const FileSystemRights Modifica =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

        /// <summary>true si ni el ejecutable ni su carpeta los puede modificar un proceso normal del usuario.</summary>
        public static bool EsSegura(string rutaEjecutable, out string motivo)
        {
            try
            {
                string completa = Path.GetFullPath(rutaEjecutable);
                string? carpeta = Path.GetDirectoryName(completa);
                if (carpeta is null) { motivo = "no se pudo determinar la carpeta"; return false; }

                if (EscribiblePorElUsuario(new FileInfo(completa).GetAccessControl(), out string? quien))
                { motivo = "el archivo lo puede modificar " + quien; return false; }

                if (EscribiblePorElUsuario(new DirectoryInfo(carpeta).GetAccessControl(), out quien))
                { motivo = "la carpeta la puede modificar " + quien; return false; }

                motivo = "";
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidOperationException
                                       || ex is ArgumentException || ex is NotSupportedException || ex is PlatformNotSupportedException)
            {
                motivo = "no se pudo comprobar la ubicacion (" + ex.GetType().Name + ")";
                return false;
            }
        }

        private static bool EscribiblePorElUsuario(FileSystemSecurity seguridad, out string? quien)
        {
            using WindowsIdentity yo = WindowsIdentity.GetCurrent();
            var miSid = yo.User;
            var misGrupos = (yo.Groups ?? new System.Security.Principal.IdentityReferenceCollection())
                .OfType<SecurityIdentifier>().ToList();

            foreach (FileSystemAccessRule r in seguridad.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (r.AccessControlType != AccessControlType.Allow || (r.FileSystemRights & Modifica) == 0) continue;
                var sid = (SecurityIdentifier)r.IdentityReference;
                if (EsDeConfianza(sid)) continue;

                bool soyYo = sid == miSid || misGrupos.Contains(sid)
                    || sid.IsWellKnown(WellKnownSidType.WorldSid) || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)
                    || sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) || sid.IsWellKnown(WellKnownSidType.InteractiveSid);
                if (soyYo) { quien = sid.Value; return true; }
            }
            quien = null;
            return false;
        }

        /// <summary>Administradores, SYSTEM y TrustedInstaller: un proceso del usuario sin elevar no es ninguno de ellos.</summary>
        private static bool EsDeConfianza(SecurityIdentifier sid)
            => sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
               || sid.Value.StartsWith("S-1-5-80-", StringComparison.Ordinal);       // NT SERVICE\*, incluido TrustedInstaller
    }
}
