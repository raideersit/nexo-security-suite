using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  FIREWALL POR APP EN ANDROID (Salida 7, 3.6). Portable: decide QUE apps entran al tunel y SI se crea. El VpnService de la app
    //  solo ejecuta el plan. El truco del diseño: la VPN incluye SOLO las apps bloqueadas y Nexo nunca lee el tunel, asi su trafico no
    //  sale. Las demas ni pasan por la VPN.
    //
    //  PELIGRO que esta clase evita: un VpnService.Builder SIN ninguna addAllowedApplication mete a TODAS las apps en el tunel, y el
    //  telefono entero queda sin internet. Por eso, con cero apps validas el plan dice «no establecer» y la app cierra la VPN.
    // =====================================================================================================

    public sealed class ReglasDelFirewall
    {
        public bool Encendido { get; set; }
        public HashSet<string> Bloqueadas { get; set; } = new(StringComparer.Ordinal);
        /// <summary>Android quito la VPN (el usuario la apago en Ajustes u otra app de VPN tomo el control). Se muestra en la pantalla.</summary>
        public bool Revocado { get; set; }
        public int Version { get; set; } = 1;

        private static readonly JsonSerializerOptions Opciones = new() { WriteIndented = false };

        public void Guardar(string ruta)
        {
            var carpeta = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (!string.IsNullOrEmpty(carpeta)) Directory.CreateDirectory(carpeta);
            var temporal = ruta + ".tmp";
            File.WriteAllText(temporal, JsonSerializer.Serialize(this, Opciones));
            File.Move(temporal, ruta, overwrite: true);
        }

        /// <summary>Un archivo dañado o desconocido empieza APAGADO: ante la duda, no se toca el internet de nadie.</summary>
        public static ReglasDelFirewall Cargar(string ruta, out string? aviso)
        {
            aviso = null;
            if (!File.Exists(ruta)) return new ReglasDelFirewall();
            try
            {
                var r = JsonSerializer.Deserialize<ReglasDelFirewall>(File.ReadAllText(ruta), Opciones);
                if (r is null || r.Version != 1 || r.Bloqueadas is null)
                { aviso = "Las reglas del firewall tienen un formato desconocido: el firewall queda apagado."; return new ReglasDelFirewall(); }
                return r;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                aviso = "Las reglas del firewall estaban dañadas: el firewall queda apagado.";
                return new ReglasDelFirewall();
            }
        }
    }

    public sealed record PlanDeFirewall(bool Establecer, IReadOnlyList<string> Paquetes, IReadOnlyList<string> Ignoradas);

    public static class PlanDeFirewallMovil
    {
        public const string PermisoDeInternet = "android.permission.INTERNET";

        /// <summary>
        /// Que paquetes entran al tunel. Se quitan el propio Nexo (bloquearse a si mismo no tiene sentido) y los que ya no estan instalados
        /// (addAllowedApplication lanza con un paquete inexistente); siguen en las reglas por si se reinstalan. Orden estable.
        /// </summary>
        public static PlanDeFirewall Calcular(ReglasDelFirewall reglas, IReadOnlySet<string> instaladas, string propioPaquete)
        {
            var paquetes = new List<string>();
            var ignoradas = new List<string>();
            foreach (var p in reglas.Bloqueadas.OrderBy(x => x, StringComparer.Ordinal))
            {
                if (string.IsNullOrWhiteSpace(p) || p == propioPaquete || !instaladas.Contains(p)) ignoradas.Add(p);
                else paquetes.Add(p);
            }
            return new PlanDeFirewall(reglas.Encendido && paquetes.Count > 0, paquetes, ignoradas);
        }

        /// <summary>Solo tiene sentido bloquear una app que pide permiso de internet.</summary>
        public static bool EsBloqueable(ModeloDeApp app, string propioPaquete) =>
            app.Paquete != propioPaquete && app.PermisosPedidos.Contains(PermisoDeInternet);
    }
}
