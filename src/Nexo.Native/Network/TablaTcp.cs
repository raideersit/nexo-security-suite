using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace Nexo.Native.Network
{
    /// <summary>Una conexion TCP establecida: proceso dueño, direccion remota y puerto remoto.</summary>
    public readonly record struct ConexionTcpNativa(int Pid, string IpRemota, int PuertoRemoto);

    /// <summary>Resultado de leer la tabla TCP. <c>Correcta</c> false = no se pudo leer (no es «ninguna conexion»).</summary>
    public sealed record LecturaTcp(bool Correcta, IReadOnlyList<ConexionTcpNativa> Conexiones, int CodigoDeError);

    /// <summary>
    /// Conexiones TCP establecidas con el PID de su proceso (GetExtendedTcpTable, IPv4 e IPv6). Solo lectura, sin administrador.
    /// No lanza: devuelve el codigo Win32 para que quien llama lo cuente como «no evaluado».
    /// </summary>
    public static class TablaTcp
    {
        private const int AF_INET = 2, AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const uint EstadoEstablecida = 5;
        private const int ErrorBufferInsuficiente = 122;

        [DllImport("iphlpapi.dll", SetLastError = false)]
        private static extern int GetExtendedTcpTable(IntPtr tabla, ref int tamano, bool ordenar, int familia, int clase, uint reservado);

        public static LecturaTcp Leer()
        {
            var lista = new List<ConexionTcpNativa>();
            int e4 = Familia(AF_INET, lista);
            if (e4 != 0) return new LecturaTcp(false, Array.Empty<ConexionTcpNativa>(), e4);
            int e6 = Familia(AF_INET6, lista);
            if (e6 != 0) return new LecturaTcp(false, Array.Empty<ConexionTcpNativa>(), e6);
            return new LecturaTcp(true, lista, 0);
        }

        private static int Familia(int familia, List<ConexionTcpNativa> salida)
        {
            int tamano = 0;
            // La tabla puede crecer entre la consulta de tamaño y la lectura: se reintenta unas veces.
            for (int intento = 0; intento < 5; intento++)
            {
                int r = GetExtendedTcpTable(IntPtr.Zero, ref tamano, false, familia, TCP_TABLE_OWNER_PID_ALL, 0);
                if (r != ErrorBufferInsuficiente && r != 0) return r;
                tamano += 4096;
                IntPtr buf = Marshal.AllocHGlobal(tamano);
                try
                {
                    r = GetExtendedTcpTable(buf, ref tamano, false, familia, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (r == ErrorBufferInsuficiente) continue;
                    if (r != 0) return r;
                    Analizar(buf, familia, salida);
                    return 0;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return ErrorBufferInsuficiente;
        }

        private static void Analizar(IntPtr buf, int familia, List<ConexionTcpNativa> salida)
        {
            int n = Marshal.ReadInt32(buf);
            // IPv4: estado, ipLocal, puertoLocal, ipRemota, puertoRemoto, pid = 6 x 4 B.
            // IPv6: ipLocal(16), scopeLocal, puertoLocal, ipRemota(16), scopeRemoto, puertoRemoto, estado, pid = 56 B.
            int fila = familia == AF_INET ? 24 : 56;
            for (int i = 0; i < n; i++)
            {
                IntPtr p = buf + 4 + i * fila;
                if (familia == AF_INET)
                {
                    uint estado = (uint)Marshal.ReadInt32(p, 0);
                    if (estado != EstadoEstablecida) continue;
                    uint ip = (uint)Marshal.ReadInt32(p, 12);
                    int puerto = PuertoDeRed(Marshal.ReadInt32(p, 16));
                    int pid = Marshal.ReadInt32(p, 20);
                    salida.Add(new ConexionTcpNativa(pid, new IPAddress(ip).ToString(), puerto));
                }
                else
                {
                    uint estado = (uint)Marshal.ReadInt32(p, 48);
                    if (estado != EstadoEstablecida) continue;
                    var bytes = new byte[16];
                    Marshal.Copy(p + 24, bytes, 0, 16);
                    int puerto = PuertoDeRed(Marshal.ReadInt32(p, 44));
                    int pid = Marshal.ReadInt32(p, 52);
                    salida.Add(new ConexionTcpNativa(pid, new IPAddress(bytes).ToString(), puerto));
                }
            }
        }

        /// <summary>El puerto viene en los 2 bytes bajos, en orden de red.</summary>
        public static int PuertoDeRed(int crudo)
        {
            int bajo = crudo & 0xFFFF;
            return ((bajo & 0xFF) << 8) | ((bajo >> 8) & 0xFF);
        }
    }
}
