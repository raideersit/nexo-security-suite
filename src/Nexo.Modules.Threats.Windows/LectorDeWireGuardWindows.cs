using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using Nexo.Modules.Threats.Vpn;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Mira si WireGuard para Windows esta instalado y que tuneles tiene, sin administrador y sin cambiar nada: el ejecutable en
    /// «Archivos de programa\WireGuard» y los servicios <c>WireGuardTunnel$*</c> (asi los crea <c>wireguard /installtunnelservice</c>, segun su
    /// documentacion). No ejecuta wireguard.exe ni wg.exe. Un servicio que no se puede consultar es «desconocido», no «detenido».
    /// </summary>
    public sealed class LectorDeWireGuardWindows : ILectorDeWireGuard
    {
        public const string PrefijoDeServicio = "WireGuardTunnel$";

        public EstadoDeWireGuard Leer()
        {
            string ruta = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe");
            bool instalado = File.Exists(ruta);
            string? version = null;
            if (instalado)
            {
                try { version = FileVersionInfo.GetVersionInfo(ruta).ProductVersion?.Trim(); }
                catch (FileNotFoundException) { }
            }

            ServiceController[] servicios;
            try { servicios = ServiceController.GetServices(); }
            catch (Exception e) when (e is Win32Exception or InvalidOperationException)
            {
                return new EstadoDeWireGuard(instalado, version, instalado ? ruta : null, Array.Empty<TunelInstalado>(), false,
                    "no se pudo leer la lista de servicios de Windows (" + e.GetType().Name + ")");
            }

            var tuneles = new List<TunelInstalado>();
            bool gestor = false;
            try
            {
                foreach (ServiceController s in servicios)
                {
                    if (s.ServiceName.Equals("WireGuardManager", StringComparison.OrdinalIgnoreCase)) gestor = Estado(s) == EstadoDeTunel.Activo;
                    if (!s.ServiceName.StartsWith(PrefijoDeServicio, StringComparison.OrdinalIgnoreCase)) continue;
                    tuneles.Add(new TunelInstalado(s.ServiceName.Substring(PrefijoDeServicio.Length), Estado(s)));
                }
            }
            finally
            {
                foreach (ServiceController s in servicios) s.Dispose();
            }
            return new EstadoDeWireGuard(instalado, version, instalado ? ruta : null,
                tuneles.OrderBy(t => t.Nombre, StringComparer.OrdinalIgnoreCase).ToList(), gestor, null);
        }

        private static EstadoDeTunel Estado(ServiceController s)
        {
            try
            {
                return s.Status switch
                {
                    ServiceControllerStatus.Running => EstadoDeTunel.Activo,
                    ServiceControllerStatus.Stopped => EstadoDeTunel.Detenido,
                    _ => EstadoDeTunel.Cambiando
                };
            }
            catch (Exception e) when (e is Win32Exception or InvalidOperationException) { return EstadoDeTunel.Desconocido; }
        }
    }
}
