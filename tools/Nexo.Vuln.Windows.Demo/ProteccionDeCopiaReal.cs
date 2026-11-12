using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private static bool EsAdminAhora() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        private static string Icacls(string ruta)
        {
            var psi = new ProcessStartInfo("icacls.exe", "\"" + ruta + "\"") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
            using Process p = Process.Start(psi)!;
            string s = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return s;
        }

        /// <summary>Hay una línea de icacls (permisos con (M), (W), (F), (D)...) cuyo dueño NO es SYSTEM ni Administradores.</summary>
        private static string? QuienMasPuedeEscribir(string icacls)
        {
            foreach (string l in icacls.Split('\n').Select(x => x.Trim()).Where(x => x.Contains("(")))
            {
                bool escribe = l.Contains("(F)") || l.Contains("(M)") || l.Contains("(W)") || l.Contains("(D)") || l.Contains("(DC)") || l.Contains("(WD)") || l.Contains("(AD)");
                bool esDeConfianza = l.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) || l.Contains("Administrador", StringComparison.OrdinalIgnoreCase);
                if (escribe && !esDeConfianza) return l;
            }
            return null;
        }

        private static void ProbarProteccionDeCopiaReal()
        {
            Console.WriteLine("18. Permisos de la carpeta de copias (disco NTFS real, carpeta temporal propia)");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-perm-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(raiz);
                string carpeta = Path.Combine(raiz, "NexoCopias");
                Check(ProteccionDeCopiaWindows.Proteger(Path.Combine(raiz, "no-existe"))?.Contains("no existe") == true, "una carpeta que no existe: lo dice, no inventa");

                Directory.CreateDirectory(carpeta);
                string previo = Path.Combine(carpeta, "viejo", "lista.json");
                Directory.CreateDirectory(Path.GetDirectoryName(previo)!);
                File.WriteAllText(previo, "{}");
                Check(!ProteccionDeCopiaWindows.EstaProtegida(carpeta), "recién creada hereda los permisos de arriba: NO está protegida");
                Check(QuienMasPuedeEscribir(Icacls(carpeta)) is not null, "icacls lo confirma: hay alguien más que puede escribir (el caso real de E:\\)", QuienMasPuedeEscribir(Icacls(carpeta)));

                if (!EsAdminAhora())
                {
                    string? motivo = ProteccionDeCopiaWindows.Proteger(carpeta);
                    Check(motivo is not null && motivo.Contains("SYSTEM") && motivo.Contains("administrador"), "sin administrador: no toca nada y dice por qué", motivo);
                    Check(!ProteccionDeCopiaWindows.EstaProtegida(carpeta) && File.Exists(previo), "y la carpeta queda como estaba (no se encierra a sí mismo)");
                    Console.WriteLine("  (sin administrador: la parte que cambia permisos se omite; ejecútalo desde una consola de administrador)");
                    return;
                }

                string? r = ProteccionDeCopiaWindows.Proteger(carpeta);
                Check(r is null, "como administrador: queda protegida", r);
                Check(ProteccionDeCopiaWindows.EstaProtegida(carpeta), "EstaProtegida lo confirma releyendo los permisos");
                string ic = Icacls(carpeta);
                Check(QuienMasPuedeEscribir(ic) is null, "icacls (otra herramienta) confirma: solo SYSTEM y Administradores pueden escribir", QuienMasPuedeEscribir(ic));
                Check(ic.Contains("(RX)", StringComparison.Ordinal), "y los Usuarios conservan leer y ejecutar (la ventana restaura y verifica leyendo)");
                DirectorySecurity seg = new DirectoryInfo(carpeta).GetAccessControl();
                Check(seg.AreAccessRulesProtected, "sin herencia de la carpeta de arriba");

                string hijaPrevia = Icacls(previo);
                Check(QuienMasPuedeEscribir(hijaPrevia) is null, "lo que YA había dentro (una copia anterior) también quedó protegido", QuienMasPuedeEscribir(hijaPrevia));

                string nuevaCarpeta = Path.Combine(carpeta, "contenido", "ab");
                Directory.CreateDirectory(nuevaCarpeta);
                string nuevoArchivo = Path.Combine(nuevaCarpeta, "ab12");
                File.WriteAllText(nuevoArchivo, "contenido");
                Check(QuienMasPuedeEscribir(Icacls(nuevoArchivo)) is null && QuienMasPuedeEscribir(Icacls(nuevaCarpeta)) is null, "lo que se crea DESPUÉS hereda la protección");

                Check(ProteccionDeCopiaWindows.Proteger(carpeta) is null, "volver a protegerla es inocuo (idempotente)");
                // Un permiso de escritura añadido a mano después se detecta (no se da por buena una carpeta que ya no lo es).
                var abierta = new DirectorySecurity();
                abierta.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), FileSystemRights.Modify,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(carpeta).SetAccessControl(abierta);
                Check(!ProteccionDeCopiaWindows.EstaProtegida(carpeta), "si alguien le da «modificar» a Usuarios autenticados, EstaProtegida lo detecta");
                Check(ProteccionDeCopiaWindows.Proteger(carpeta) is null && ProteccionDeCopiaWindows.EstaProtegida(carpeta) && QuienMasPuedeEscribir(Icacls(carpeta)) is null, "y volver a protegerla lo corrige");
            }
            finally
            {
                // Como administrador (SYSTEM y Administradores con control total) se puede borrar; sin administrador nunca se tocó.
                try { Directory.Delete(raiz, true); } catch (Exception e) { Console.WriteLine("  (no se pudo borrar " + raiz + ": " + e.Message + ")"); }
            }
        }
    }
}
