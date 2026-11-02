using System;
using System.Runtime.InteropServices;

namespace Nexo.Native.Audit
{
    /// <summary>Que se audita de una subcategoria de la politica de auditoria avanzada de Windows.</summary>
    [Flags]
    public enum AuditoriaActiva
    {
        Nada = 0,
        Exito = 1,
        Fallo = 2
    }

    /// <summary>
    /// Consulta la politica de auditoria avanzada (la que se ve con <c>auditpol /get</c>). Solo LEE: nunca la
    /// cambia. Exige administrador (SeSecurityPrivilege); sin el, devuelve null y no inventa un valor.
    /// </summary>
    public static class PoliticaDeAuditoria
    {
        /// <summary>"Filtering Platform Connection": de aqui sale el evento 5157 (conexion bloqueada) cuando se audita el fallo.</summary>
        public static readonly Guid FiltradoDeConexiones = new Guid("0CCE9226-69AE-11D9-BED3-505054503030");

        // AUDIT_POLICY_INFORMATION: GUID, ULONG, GUID.
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation
        {
            public Guid AuditSubCategoryGuid;
            public uint AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            [In, MarshalAs(UnmanagedType.LPArray)] Guid[] pSubCategoryGuids,
            uint policyCount,
            out IntPtr ppAuditPolicy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        /// <summary>Lo que se audita de la subcategoria, o null si no se pudo averiguar (sin permisos, error).</summary>
        public static AuditoriaActiva? Consultar(Guid subcategoria)
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                if (!AuditQuerySystemPolicy(new[] { subcategoria }, 1, out buffer) || buffer == IntPtr.Zero)
                    return null;

                var info = Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
                // Los bits 0 y 1 son exito y fallo; los demas (p. ej. "sin auditoria" = 4) no cuentan.
                return (AuditoriaActiva)(info.AuditingInformation & 0x3);
            }
            catch (Exception e) when (e is EntryPointNotFoundException or DllNotFoundException or SEHException)
            {
                return null;
            }
            finally
            {
                if (buffer != IntPtr.Zero) AuditFree(buffer);
            }
        }
    }
}
