using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Permisos NTFS de la carpeta de copias (§2au del traspaso). Hueco que se cazó en la prueba real en <c>E:\</c>: la carpeta heredaba los
    /// permisos de la raíz del disco, donde «Usuarios autenticados» puede modificar, así que un programa de la persona (un ransomware, por ejemplo)
    /// podía borrar o alterar las copias.
    ///
    /// Qué hace: deja la carpeta SIN herencia, con control total solo para SYSTEM y Administradores, y a los Usuarios solo leer y ejecutar. Lo que
    /// se cree dentro después hereda eso. Quien restaura o verifica (la ventana, con los permisos de la persona) solo necesita leer.
    ///
    /// Qué NO hace, a propósito:
    ///  - No protege de un proceso con permisos de administrador (si el ransomware está elevado, esto no lo para).
    ///  - Si el disco no admite permisos (FAT/exFAT, típico de un disco externo) o la ruta no se puede comprobar, NO finge: devuelve el motivo.
    ///  - Si este proceso no es SYSTEM ni administrador, no toca nada y lo dice: dejar el control solo a SYSTEM y Administradores le quitaría
    ///    el acceso a su propia copia (un servicio que corre como usuario normal).
    ///
    /// Devuelve <c>null</c> si la carpeta quedó (o ya estaba) protegida; si no, el motivo en español.
    /// </summary>
    public static class ProteccionDeCopiaWindows
    {
        private static readonly SecurityIdentifier Sistema = new(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);

        // Lo que cuenta como «poder cambiar o borrar»: si algo que no sea SYSTEM o Administradores lo tiene permitido, no está protegida.
        private const FileSystemRights Escritura = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

        public static string? Proteger(string carpeta)
        {
            try
            {
                string completa = Path.GetFullPath(carpeta);
                var dir = new DirectoryInfo(completa);
                if (!dir.Exists) return "La carpeta de copias no existe: " + completa;

                string? fs = SistemaDeArchivos(completa);
                if (fs is null)
                    return "No se pudo comprobar si el destino admite permisos (¿es una ruta de red?): las copias no quedan protegidas contra cambios.";
                if (!fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase) && !fs.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
                    return "El destino usa " + fs + ", que no admite permisos: las copias no quedan protegidas contra cambios. Con NTFS sí se protegerían.";

                if (EstaProtegida(completa)) return null;

                if (!PuedeAjustarPermisos())
                    return "Nexo no corre como SYSTEM ni como administrador: no puede proteger la carpeta de copias contra cambios.";

                var seguridad = new DirectorySecurity();
                seguridad.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (SecurityIdentifier sid in new[] { Sistema, Admins })
                    seguridad.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                seguridad.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                // El dueño de una carpeta siempre puede cambiar sus permisos: si el dueño fuera la persona, un programa suyo podría devolverse el acceso.
                try { seguridad.SetOwner(Admins); } catch (Exception) { /* sin el privilegio: se aplica el resto y se comprueba abajo */ }
                dir.SetAccessControl(seguridad);

                return EstaProtegida(completa)
                    ? null
                    : "Se cambiaron los permisos de la carpeta de copias, pero al releerlos no quedaron como se esperaba: no se puede asegurar que estén protegidas.";
            }
            catch (Exception e)
            {
                return "No se pudo proteger la carpeta de copias: " + e.Message;
            }
        }

        /// <summary>
        /// ¿Está sin herencia y sin que nadie más que SYSTEM y Administradores pueda escribir, borrar o cambiar permisos? Se usa para no reaplicar
        /// (y no recorrer toda una copia grande) en cada copia, y para comprobar el resultado tras aplicar.
        /// </summary>
        public static bool EstaProtegida(string carpeta)
        {
            try
            {
                DirectorySecurity seg = new DirectoryInfo(carpeta).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                if (!seg.AreAccessRulesProtected) return false;
                var reglas = seg.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                                .Where(r => r.AccessControlType == AccessControlType.Allow).ToList();
                bool completo(SecurityIdentifier sid) => reglas.Any(r => r.IdentityReference.Equals(sid) && (r.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);
                if (!completo(Sistema) || !completo(Admins)) return false;
                if (reglas.Any(r => !r.IdentityReference.Equals(Sistema) && !r.IdentityReference.Equals(Admins) && (r.FileSystemRights & Escritura) != 0)) return false;
                // El dueño debe ser SYSTEM o Administradores: si no, puede reescribir los permisos.
                return seg.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier dueno && (dueno.Equals(Sistema) || dueno.Equals(Admins));
            }
            catch (Exception) { return false; }
        }

        private static bool PuedeAjustarPermisos()
        {
            using WindowsIdentity yo = WindowsIdentity.GetCurrent();
            if (yo.IsSystem) return true;
            // Con el enum, no con texto: IsInRole("Administrator") da falso en una Windows en español.
            return new WindowsPrincipal(yo).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string? SistemaDeArchivos(string ruta)
        {
            try
            {
                string? raiz = Path.GetPathRoot(ruta);
                if (string.IsNullOrEmpty(raiz) || raiz.StartsWith(@"\\", StringComparison.Ordinal)) return null;
                return new DriveInfo(raiz).DriveFormat;
            }
            catch (Exception) { return null; }
        }
    }
}
