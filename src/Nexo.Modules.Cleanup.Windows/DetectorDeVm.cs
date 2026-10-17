using System;
using System.Management;
using System.Runtime.Versioning;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Dice si el programa corre dentro de una maquina virtual.
    ///
    /// Existe para hacer cumplir una regla dura del proyecto con codigo y no con
    /// un aviso: el borrado PERMANENTE de la limpieza solo se ejecuta en una VM.
    ///
    /// Se mira el fabricante y el modelo que informa el firmware virtual, no la
    /// presencia de un hipervisor: un equipo real con Hyper-V activado tambien
    /// ejecuta Windows sobre un hipervisor, y no es una VM desechable.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class DetectorDeVm
    {
        public static (bool EsVm, string Descripcion) Detectar()
        {
            try
            {
                using var buscador = new ManagementObjectSearcher(
                    @"root\cimv2", "SELECT Manufacturer, Model FROM Win32_ComputerSystem");

                foreach (ManagementBaseObject o in buscador.Get())
                {
                    string fabricante = (o["Manufacturer"] as string ?? "").Trim();
                    string modelo = (o["Model"] as string ?? "").Trim();
                    string descripcion = fabricante + " / " + modelo;

                    return (EsFirmwareVirtual(fabricante, modelo), descripcion);
                }
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException)
            {
                // Ante la duda NO es una VM: el borrado permanente se niega.
            }
            return (false, "no se pudo determinar");
        }

        /// <summary>Separado para poder probarlo sin WMI.</summary>
        public static bool EsFirmwareVirtual(string fabricante, string modelo)
        {
            string f = fabricante.ToLowerInvariant();
            string m = modelo.ToLowerInvariant();

            return m.Contains("virtualbox", StringComparison.Ordinal)
                   || m.Contains("vmware", StringComparison.Ordinal)
                   || m.Contains("kvm", StringComparison.Ordinal)
                   || m.Contains("qemu", StringComparison.Ordinal)
                   || m.Contains("virtual machine", StringComparison.Ordinal)   // Hyper-V
                   || m.Contains("parallels", StringComparison.Ordinal)
                   || f.Contains("vmware", StringComparison.Ordinal)
                   || f.Contains("innotek", StringComparison.Ordinal)           // VirtualBox
                   || f.Contains("qemu", StringComparison.Ordinal)
                   || f.Contains("xen", StringComparison.Ordinal)
                   || f.Contains("parallels", StringComparison.Ordinal);
        }
    }
}
