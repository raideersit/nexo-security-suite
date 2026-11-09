using System;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Vpn;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private static void ProbarWireGuardReal()
        {
            Console.WriteLine("10. WireGuard REAL en este equipo (solo lectura, sin administrador)");
            EstadoDeWireGuard e = new LectorDeWireGuardWindows().Leer();
            string ruta = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe");
            Console.WriteLine("           instalado: " + e.Instalado + ", versión: " + (e.Version ?? "-") + ", túneles: " + e.Tuneles.Count +
                              (e.Tuneles.Count > 0 ? " (" + string.Join(", ", e.Tuneles.Select(t => t.Nombre + "=" + t.Estado)) + ")" : "") + ", gestor en marcha: " + e.GestorEnMarcha);
            Check(e.Error is null, "la lista de servicios de Windows se leyó sin error", e.Error);
            Check(e.Instalado == File.Exists(ruta) && (e.Instalado ? e.Ruta == ruta : e.Ruta is null), "«instalado» coincide con que exista " + ruta);
            Check(!e.Instalado || !string.IsNullOrEmpty(e.Version), "si está instalado, se lee su versión");
            Check(e.Tuneles.All(t => ParserDeWireGuard.ValidarNombre(t.Nombre) is null), "los túneles leídos tienen nombres que WireGuard acepta");
        }
    }
}
