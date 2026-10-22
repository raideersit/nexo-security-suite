using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Nexo.Ipc
{
    /// <summary>
    /// ACL del pipe (Salida 0, §2): SYSTEM y Administradores control total; el usuario
    /// interactivo, lectura y escritura; y se DENIEGA explicitamente la red. Nadie mas
    /// (ni Everyone, ni usuarios de servicios, ni invitados) recibe un permiso.
    ///
    /// Que el usuario interactivo pueda hablar con el servicio es la superficie de
    /// ataque: por eso el servicio valida cada peticion y las acciones destructivas
    /// llevan token de confirmacion. La ACL solo reduce quien puede llamar.
    /// </summary>
    public static class SeguridadDePipe
    {
        public static PipeSecurity Crear()
        {
            var seg = new PipeSecurity();
            // Sin herencia ni propietario implicito de otros: se parte de una DACL vacia.
            seg.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            seg.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
                PipeAccessRights.FullControl, AccessControlType.Deny));
            seg.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            seg.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            // La cuenta que ejecuta el servicio (SYSTEM en produccion; el usuario en las pruebas): sin
            // esto no podria abrir la segunda instancia del pipe, porque el creador no es "dueno" implicito.
            SecurityIdentifier? yo = WindowsIdentity.GetCurrent().User;
            if (yo is not null)
                seg.AddAccessRule(new PipeAccessRule(yo, PipeAccessRights.FullControl, AccessControlType.Allow));
            seg.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
                PipeAccessRights.ReadWrite, AccessControlType.Allow));
            return seg;
        }
    }
}
