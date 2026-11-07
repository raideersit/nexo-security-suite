using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Nexo.Native.Wifi
{
    public enum EstadoDeLecturaWlan
    {
        Correcta,

        /// <summary>El servicio «Configuracion automatica de WLAN» no esta activo. En un PC sin Wi-Fi es lo normal; no se puede distinguir de un servicio detenido.</summary>
        ServicioNoActivo,
        Error
    }

    /// <summary>Un perfil guardado: nombre y su XML. El XML puede traer la clave CIFRADA (nunca en texto plano: no se pide); quien lo use no debe conservarla.</summary>
    public sealed record PerfilWlanNativo(string Nombre, string? Xml, uint CodigoDeError);

    /// <summary>Lo que Windows dice de la conexion activa de un adaptador.</summary>
    public sealed record ConexionWlanNativa(string Perfil, bool SeguridadActiva, uint Autenticacion, uint Cifrado);

    public sealed record InterfazWlanNativa(string Descripcion, int Estado, IReadOnlyList<PerfilWlanNativo> Perfiles, ConexionWlanNativa? Conexion);

    public sealed record LecturaWlan(EstadoDeLecturaWlan Estado, uint Codigo, IReadOnlyList<InterfazWlanNativa> Interfaces);

    /// <summary>
    /// Native Wifi API (wlanapi.dll) en SOLO LECTURA: adaptadores, perfiles guardados y conexion actual. No necesita
    /// administrador. Nunca pide la clave en texto plano (<c>WLAN_PROFILE_GET_PLAINTEXT_KEY</c>): la bandera de lectura es
    /// siempre 0, y Windows devuelve la clave, si la incluye, cifrada. Nunca modifica perfiles ni se conecta ni desconecta.
    /// </summary>
    public static class WlanNativo
    {
        private const uint ClienteVersion2 = 2;
        private const uint ERROR_SUCCESS = 0, ERROR_SERVICE_NOT_ACTIVE = 1062;
        private const int wlan_intf_opcode_current_connection = 7;
        private const int MaximoDeInterfaces = 64, MaximoDePerfiles = 1024;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct InterfaceInfo
        {
            public Guid Guid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Descripcion;
            public int Estado;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProfileInfo
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Nombre;
            public uint Banderas;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ConnectionAttributes
        {
            public int Estado;
            public int Modo;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Perfil;
            // WLAN_ASSOCIATION_ATTRIBUTES
            public uint SsidLongitud;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Ssid;
            public int BssType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
            public int PhyType;
            public uint PhyIndex;
            public uint Calidad;
            public uint RxRate;
            public uint TxRate;
            // WLAN_SECURITY_ATTRIBUTES
            public int SeguridadActiva;
            public int OneX;
            public int Autenticacion;
            public int Cifrado;
        }

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern uint WlanGetProfileList(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr reserved, out IntPtr profileList);

        [DllImport("wlanapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint WlanGetProfile(IntPtr clientHandle, ref Guid interfaceGuid, string profileName, IntPtr reserved,
                                                  out IntPtr profileXml, ref uint flags, out uint grantedAccess);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern uint WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode, IntPtr reserved,
                                                      out uint dataSize, out IntPtr data, out int opcodeValueType);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        private static extern void WlanFreeMemory(IntPtr memory);

        public static LecturaWlan Leer()
        {
            IntPtr cliente = IntPtr.Zero;
            try
            {
                uint e = WlanOpenHandle(ClienteVersion2, IntPtr.Zero, out _, out cliente);
                if (e == ERROR_SERVICE_NOT_ACTIVE) return new LecturaWlan(EstadoDeLecturaWlan.ServicioNoActivo, e, Array.Empty<InterfazWlanNativa>());
                if (e != ERROR_SUCCESS) return new LecturaWlan(EstadoDeLecturaWlan.Error, e, Array.Empty<InterfazWlanNativa>());

                e = WlanEnumInterfaces(cliente, IntPtr.Zero, out IntPtr lista);
                if (e != ERROR_SUCCESS) return new LecturaWlan(EstadoDeLecturaWlan.Error, e, Array.Empty<InterfazWlanNativa>());

                var interfaces = new List<InterfazWlanNativa>();
                try
                {
                    uint n = (uint)Marshal.ReadInt32(lista, 0);
                    if (n > MaximoDeInterfaces) return new LecturaWlan(EstadoDeLecturaWlan.Error, uint.MaxValue, Array.Empty<InterfazWlanNativa>());
                    int tam = Marshal.SizeOf<InterfaceInfo>();
                    for (uint i = 0; i < n; i++)
                    {
                        var info = Marshal.PtrToStructure<InterfaceInfo>(IntPtr.Add(lista, 8 + (int)i * tam));
                        Guid guid = info.Guid;
                        interfaces.Add(new InterfazWlanNativa(info.Descripcion, info.Estado, LeerPerfiles(cliente, ref guid), LeerConexion(cliente, ref guid)));
                    }
                }
                finally { WlanFreeMemory(lista); }

                return new LecturaWlan(EstadoDeLecturaWlan.Correcta, 0, interfaces);
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
            {
                return new LecturaWlan(EstadoDeLecturaWlan.Error, uint.MaxValue, Array.Empty<InterfazWlanNativa>());
            }
            finally
            {
                if (cliente != IntPtr.Zero) WlanCloseHandle(cliente, IntPtr.Zero);
            }
        }

        private static IReadOnlyList<PerfilWlanNativo> LeerPerfiles(IntPtr cliente, ref Guid guid)
        {
            var perfiles = new List<PerfilWlanNativo>();
            uint e = WlanGetProfileList(cliente, ref guid, IntPtr.Zero, out IntPtr lista);
            if (e != ERROR_SUCCESS) return new[] { new PerfilWlanNativo("", null, e) }; // no se pudo ni listar: se informa, no se calla
            try
            {
                uint n = (uint)Marshal.ReadInt32(lista, 0);
                if (n > MaximoDePerfiles) return new[] { new PerfilWlanNativo("", null, uint.MaxValue) };
                int tam = Marshal.SizeOf<ProfileInfo>();
                for (uint i = 0; i < n; i++)
                {
                    var p = Marshal.PtrToStructure<ProfileInfo>(IntPtr.Add(lista, 8 + (int)i * tam));
                    uint banderas = 0; // JAMAS WLAN_PROFILE_GET_PLAINTEXT_KEY: la clave no se pide
                    uint er = WlanGetProfile(cliente, ref guid, p.Nombre, IntPtr.Zero, out IntPtr xml, ref banderas, out _);
                    if (er != ERROR_SUCCESS) { perfiles.Add(new PerfilWlanNativo(p.Nombre, null, er)); continue; }
                    try { perfiles.Add(new PerfilWlanNativo(p.Nombre, Marshal.PtrToStringUni(xml), 0)); }
                    finally { WlanFreeMemory(xml); }
                }
            }
            finally { WlanFreeMemory(lista); }
            return perfiles;
        }

        private static ConexionWlanNativa? LeerConexion(IntPtr cliente, ref Guid guid)
        {
            uint e = WlanQueryInterface(cliente, ref guid, wlan_intf_opcode_current_connection, IntPtr.Zero, out uint tam, out IntPtr datos, out _);
            if (e != ERROR_SUCCESS || datos == IntPtr.Zero) return null; // sin conexion activa (o no legible): no se inventa una
            try
            {
                if (tam < Marshal.SizeOf<ConnectionAttributes>()) return null;
                var c = Marshal.PtrToStructure<ConnectionAttributes>(datos);
                return new ConexionWlanNativa(c.Perfil, c.SeguridadActiva != 0, (uint)c.Autenticacion, (uint)c.Cifrado);
            }
            finally { WlanFreeMemory(datos); }
        }
    }
}
