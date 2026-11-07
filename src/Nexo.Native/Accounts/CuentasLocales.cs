using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Nexo.Native.Accounts
{
    /// <summary>
    /// Una cuenta local tal como la describe <c>NetUserEnum</c> nivel 20: nombre, banderas (<c>UF_*</c>) y RID (el final del SID:
    /// 500 = Administrador integrado, 501 = Invitado; el RID no depende del idioma, el nombre si).
    /// </summary>
    public readonly record struct CuentaLocalNativa(string Nombre, uint Banderas, uint Rid)
    {
        public const uint CuentaDeshabilitada = 0x0002;
        public const uint ContrasenaNoRequerida = 0x0020;
        public const uint Bloqueada = 0x0010;
        public const uint ContrasenaNoExpira = 0x10000;

        public bool Tiene(uint bandera) => (Banderas & bandera) != 0;
    }

    /// <summary>Politica de contrasenas local (NetUserModalsGet niveles 0 y 3). Ver <see cref="CuentasLocales.LeerPolitica"/>.</summary>
    public readonly record struct PoliticaNativa(uint LongitudMinima, uint EdadMaximaSegundos, uint HistorialDeContrasenas, uint UmbralDeBloqueo)
    {
        /// <summary><c>TIMEQ_FOREVER</c>: las contrasenas no caducan.</summary>
        public const uint ParaSiempre = 0xFFFFFFFF;
    }

    /// <summary>
    /// Cuentas locales y politica de contrasenas por la API de red de Windows (netapi32). SOLO LEE metadatos: nunca toca la SAM
    /// ni obtiene contrasenas ni hashes (linea roja del proyecto). No necesita administrador. Cuando algo no se puede leer
    /// devuelve null y el codigo de error, en vez de inventar un valor.
    /// </summary>
    public static class CuentasLocales
    {
        private const uint FILTER_NORMAL_ACCOUNT = 0x0002;
        private const int MAX_PREFERRED_LENGTH = -1;
        private const uint NERR_Success = 0, ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential)]
        private struct UserInfo20
        {
            public IntPtr Nombre;
            public IntPtr NombreCompleto;
            public IntPtr Comentario;
            public uint Banderas;
            public uint UserId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UserModalsInfo0
        {
            public uint MinPasswdLen;
            public uint MaxPasswdAge;
            public uint MinPasswdAge;
            public uint ForceLogoff;
            public uint PasswordHistLen;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UserModalsInfo3
        {
            public uint LockoutDuration;
            public uint LockoutObservationWindow;
            public uint LockoutThreshold;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint NetUserEnum(string? servername, uint level, uint filter, out IntPtr bufptr, int prefmaxlen,
                                               out uint entriesread, out uint totalentries, ref uint resume_handle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint NetUserModalsGet(string? servername, uint level, out IntPtr bufptr);

        [DllImport("netapi32.dll", ExactSpelling = true)]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        /// <summary>Las cuentas locales normales, o null si no se pudieron enumerar (codigo de error en <paramref name="error"/>).</summary>
        public static IReadOnlyList<CuentaLocalNativa>? Enumerar(out uint error)
        {
            error = 0;
            var cuentas = new List<CuentaLocalNativa>();
            uint resume = 0;
            try
            {
                while (true)
                {
                    uint estado = NetUserEnum(null, 20, FILTER_NORMAL_ACCOUNT, out IntPtr buffer, MAX_PREFERRED_LENGTH, out uint leidas, out _, ref resume);
                    try
                    {
                        if (estado != NERR_Success && estado != ERROR_MORE_DATA) { error = estado; return null; }
                        int tam = Marshal.SizeOf<UserInfo20>();
                        for (uint i = 0; i < leidas; i++)
                        {
                            var u = Marshal.PtrToStructure<UserInfo20>(IntPtr.Add(buffer, (int)i * tam));
                            string? nombre = Marshal.PtrToStringUni(u.Nombre);
                            if (!string.IsNullOrEmpty(nombre)) cuentas.Add(new CuentaLocalNativa(nombre, u.Banderas, u.UserId));
                        }
                    }
                    finally
                    {
                        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
                    }
                    if (estado == NERR_Success) return cuentas;
                }
            }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or SEHException)
            {
                error = uint.MaxValue;
                return null;
            }
        }

        /// <summary>La politica local de contrasenas, o null si no se pudo leer (codigo en <paramref name="error"/>).</summary>
        public static PoliticaNativa? LeerPolitica(out uint error)
        {
            error = 0;
            IntPtr b0 = IntPtr.Zero, b3 = IntPtr.Zero;
            try
            {
                uint e0 = NetUserModalsGet(null, 0, out b0);
                if (e0 != NERR_Success || b0 == IntPtr.Zero) { error = e0 == 0 ? uint.MaxValue : e0; return null; }
                uint e3 = NetUserModalsGet(null, 3, out b3);
                if (e3 != NERR_Success || b3 == IntPtr.Zero) { error = e3 == 0 ? uint.MaxValue : e3; return null; }

                var m0 = Marshal.PtrToStructure<UserModalsInfo0>(b0);
                var m3 = Marshal.PtrToStructure<UserModalsInfo3>(b3);
                return new PoliticaNativa(m0.MinPasswdLen, m0.MaxPasswdAge, m0.PasswordHistLen, m3.LockoutThreshold);
            }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or SEHException)
            {
                error = uint.MaxValue;
                return null;
            }
            finally
            {
                if (b0 != IntPtr.Zero) NetApiBufferFree(b0);
                if (b3 != IntPtr.Zero) NetApiBufferFree(b3);
            }
        }
    }
}
