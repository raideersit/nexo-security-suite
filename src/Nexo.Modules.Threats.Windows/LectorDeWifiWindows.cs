using System;
using System.Linq;
using System.Net.NetworkInformation;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Native.Wifi;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee de Windows las redes Wi-Fi guardadas y la conexion actual para <see cref="AnalizadorDeWifi"/>. Solo lectura, sin
    /// administrador. Nunca pide la clave. Para saber si el equipo TIENE Wi-Fi no depende del servicio WLAN (usa los
    /// adaptadores de red de .NET): asi «no hay Wi-Fi» (un hecho) no se confunde con «el servicio esta parado» (un fallo).
    /// </summary>
    public static class LectorDeWifiWindows
    {
        public static InstantaneaDeWifi Leer()
        {
            if (!HayAdaptadorWifi()) return new InstantaneaDeWifi(EstadoDeLecturaWifi.SinAdaptador, Array.Empty<AdaptadorWifi>());

            LecturaWlan l = WlanNativo.Leer();
            EstadoDeLecturaWifi estado = l.Estado switch
            {
                EstadoDeLecturaWlan.Correcta => EstadoDeLecturaWifi.Correcta,
                EstadoDeLecturaWlan.ServicioNoActivo => EstadoDeLecturaWifi.ServicioNoActivo,
                _ => EstadoDeLecturaWifi.Error
            };

            var adaptadores = l.Interfaces.Select(i => new AdaptadorWifi(
                i.Descripcion,
                i.Perfiles.Where(p => p.Nombre.Length > 0 || p.Xml is not null || p.CodigoDeError != 0)
                          .Select(p => new PerfilCrudo(p.Nombre.Length > 0 ? p.Nombre : "(lista de perfiles)", p.Xml)).ToList(),
                i.Conexion is null ? null : new ConexionActual(i.Conexion.Perfil, i.Conexion.SeguridadActiva, i.Conexion.Autenticacion, i.Conexion.Cifrado))).ToList();

            return new InstantaneaDeWifi(estado, adaptadores);
        }

        /// <summary>true si Windows lista algun adaptador inalambrico 802.11 (esté conectado o no).</summary>
        public static bool HayAdaptadorWifi()
        {
            try { return NetworkInterface.GetAllNetworkInterfaces().Any(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211); }
            catch (NetworkInformationException) { return true; } // si no se puede ni listar, no se afirma que no haya: se intenta la lectura y, si falla, queda como no evaluado
        }
    }
}
