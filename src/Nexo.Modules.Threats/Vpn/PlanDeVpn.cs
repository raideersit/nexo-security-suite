using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vpn
{
    public enum AccionDeVpn
    {
        Conectar,
        Desconectar
    }

    /// <summary>
    /// Lo que se va a hacer, ANTES de hacerlo. Con algun rechazo no hay cambios (ni token). <see cref="Conf"/> solo existe para conectar y
    /// nunca se describe ni se devuelve: contiene la clave privada y solo vive en memoria del servicio hasta que se aplica o caduca el token.
    /// </summary>
    public sealed class PlanDeVpn
    {
        public PlanDeVpn(AccionDeVpn accion, string tunel, string? conf, IReadOnlyList<string> cambios, IReadOnlyList<string> rechazos, IReadOnlyList<string> advertencias)
        {
            Accion = accion; Tunel = tunel; Conf = conf; Cambios = cambios; Rechazos = rechazos; Advertencias = advertencias;
        }

        public AccionDeVpn Accion { get; }
        public string Tunel { get; }
        internal string? Conf { get; }
        public IReadOnlyList<string> Cambios { get; }
        public IReadOnlyList<string> Rechazos { get; }
        public IReadOnlyList<string> Advertencias { get; }
        public bool HayCambios => Rechazos.Count == 0 && Cambios.Count > 0;

        /// <summary>El texto del archivo, solo para quien lo ejecuta (el servicio). No se usa para describir nada.</summary>
        public string? ConfParaEjecutar() => Conf;

        public string Describir()
        {
            var sb = new StringBuilder();
            sb.AppendLine(Accion == AccionDeVpn.Conectar ? "Conectar la VPN «" + Tunel + "»" : "Desconectar y quitar la VPN «" + Tunel + "»");
            if (Rechazos.Count > 0)
            {
                sb.AppendLine("No se puede hacer:");
                foreach (string r in Rechazos) sb.AppendLine("• " + r);
            }
            else
            {
                sb.AppendLine("Se hará:");
                foreach (string c in Cambios) sb.AppendLine("• " + c);
            }
            if (Advertencias.Count > 0)
            {
                sb.AppendLine("Ten en cuenta:");
                foreach (string a in Advertencias) sb.AppendLine("• " + a);
            }
            return sb.ToString().TrimEnd();
        }
    }

    public sealed record ResultadoDeVpn(bool Exito, string Mensaje);

    /// <summary>Quien ejecuta los cambios (la implementacion real usa wireguard.exe como SYSTEM). Las pruebas usan una falsa.</summary>
    public interface IEjecutorDeWireGuard
    {
        /// <summary>La carpeta protegida donde Nexo guarda los archivos de los tuneles que instala (solo SYSTEM y administradores).</summary>
        string Carpeta { get; }

        /// <summary>true si el tunel lo instalo Nexo (su archivo esta en <see cref="Carpeta"/>).</summary>
        bool EsDeNexo(string tunel);

        Task<ResultadoDeVpn> ConectarAsync(string tunel, string conf, CancellationToken ct);

        Task<ResultadoDeVpn> DesconectarAsync(string tunel, CancellationToken ct);
    }

    /// <summary>
    /// Prepara los planes de conectar y desconectar. Reglas (todas probadas):
    ///  - Sin WireGuard instalado, o sin saber su estado, no se prepara nada.
    ///  - Solo se conecta un archivo que WireGuard aceptaria, con un nombre valido, sin comandos (PreUp/PostUp...) y sin ningun hallazgo Alta.
    ///  - No se pisa un tunel que ya existe con el mismo nombre.
    ///  - Solo se desconectan los tuneles que instalo Nexo: los demas son del usuario (se manejan desde WireGuard).
    ///  - Los hallazgos Media (fuga IPv6, sin DNS...) no impiden conectar, pero se avisan en la vista previa.
    /// </summary>
    public static class PlanificadorDeVpn
    {
        public static PlanDeVpn PrepararConexion(string? texto, string archivo, EstadoDeWireGuard estado, IEjecutorDeWireGuard ejecutor, ListasDePhishing? listas = null)
        {
            var rechazos = new List<string>();
            var advertencias = new List<string>();
            var cambios = new List<string>();
            LecturaDeConfiguracionWg l = ParserDeWireGuard.Leer(texto, archivo ?? "");
            string tunel = l.NombreDeTunel ?? "";

            if (estado.Error is not null) rechazos.Add("no se pudo saber el estado de WireGuard: " + estado.Error);
            else if (!estado.Instalado) rechazos.Add("WireGuard no está instalado (winget install WireGuard.WireGuard)");

            if (l.Configuracion is null) rechazos.Add("WireGuard rechazaría el archivo: " + string.Join("; ", l.Errores.Take(3)) + (l.Errores.Count > 3 ? "…" : ""));
            if (l.ErrorDeNombre is not null) rechazos.Add("el nombre del túnel no vale (" + l.ErrorDeNombre + "): renombra el archivo");

            ResultadoDeAnalisis? a = l.Configuracion is null ? null : AnalizadorDeVpn.Analizar(l.Configuracion, listas);
            if (l.Configuracion is { } c && c.Interfaz.Scripts.Count > 0)
                rechazos.Add("el archivo trae comandos (" + string.Join(", ", c.Interfaz.Scripts.Select(s => s.Clave).Distinct()) + "): Nexo no instala archivos con comandos");
            foreach (HallazgoDeSistema h in a?.Hallazgos.Where(h => h.Severidad >= Severidad.Alta && h.Id != "VPN-SCRIPTS") ?? Enumerable.Empty<HallazgoDeSistema>())
                rechazos.Add(h.Titulo);

            if (l.ErrorDeNombre is null && tunel.Length > 0 && estado.Tuneles.Any(t => string.Equals(t.Nombre, tunel, StringComparison.OrdinalIgnoreCase)))
                rechazos.Add("ya hay un túnel llamado «" + tunel + "»: desconéctalo antes o renombra el archivo");

            if (rechazos.Count == 0)
            {
                ConfiguracionWg cfg = l.Configuracion!;
                List<string> ips = cfg.Peers.SelectMany(p => p.IpsPermitidas).ToList();
                string servidor = string.Join(", ", cfg.Peers.Where(p => p.Endpoint is not null).Select(p => p.Endpoint!));
                cambios.Add("guardar una copia del archivo en «" + ejecutor.Carpeta + "», que solo pueden leer SYSTEM y los administradores");
                cambios.Add("instalar el túnel «" + tunel + "» en WireGuard (servicio de Windows «WireGuardTunnel$" + tunel + "») y conectarlo");
                cambios.Add(AnalizadorDeVpn.TodoIpv4(ips) || AnalizadorDeVpn.TodoIpv6(ips)
                    ? "a partir de ahí, tu tráfico pasará por " + (servidor.Length > 0 ? servidor : "el servidor de la VPN") + ", que lo verá todo"
                    : "solo el tráfico hacia " + string.Join(", ", ips.Take(4)) + (ips.Count > 4 ? "…" : "") + " pasará por la VPN");
                foreach (HallazgoDeSistema h in a!.Hallazgos.Where(h => h.Severidad is Severidad.Media or Severidad.Baja)) advertencias.Add(h.Titulo);
                foreach (TunelInstalado t in estado.Tuneles.Where(t => t.Estado == EstadoDeTunel.Activo))
                    advertencias.Add("ya hay otro túnel activo («" + t.Nombre + "»): dos VPN a la vez pueden chocar");
            }
            return new PlanDeVpn(AccionDeVpn.Conectar, tunel, rechazos.Count == 0 ? texto : null, cambios, rechazos, advertencias);
        }

        public static PlanDeVpn PrepararDesconexion(string? tunel, EstadoDeWireGuard estado, IEjecutorDeWireGuard ejecutor)
        {
            var rechazos = new List<string>();
            var cambios = new List<string>();
            string t = (tunel ?? "").Trim();
            if (ParserDeWireGuard.ValidarNombre(t) is string e) rechazos.Add("el nombre del túnel no es válido (" + e + ")");
            else if (estado.Error is not null) rechazos.Add("no se pudo saber el estado de WireGuard: " + estado.Error);
            else if (!estado.Instalado) rechazos.Add("WireGuard no está instalado");
            else if (!estado.Tuneles.Any(x => string.Equals(x.Nombre, t, StringComparison.OrdinalIgnoreCase))) rechazos.Add("no hay ningún túnel llamado «" + t + "»");
            else if (!ejecutor.EsDeNexo(t)) rechazos.Add("el túnel «" + t + "» no lo instaló Nexo: desconéctalo desde WireGuard");

            if (rechazos.Count == 0)
            {
                cambios.Add("detener y quitar el túnel «" + t + "» (servicio «WireGuardTunnel$" + t + "»): tu tráfico volverá a salir directo por tu conexión");
                cambios.Add("borrar la copia del archivo que Nexo guardó en «" + ejecutor.Carpeta + "»");
            }
            return new PlanDeVpn(AccionDeVpn.Desconectar, t, null, cambios, rechazos, Array.Empty<string>());
        }

        /// <summary>
        /// Ejecuta el plan, volviendo a mirar el estado justo antes (entre la vista previa y la aprobacion pueden pasar minutos): si ya no
        /// vale, no se toca nada y se dice por que.
        /// </summary>
        public static async Task<ResultadoDeVpn> AplicarAsync(PlanDeVpn plan, EstadoDeWireGuard ahora, IEjecutorDeWireGuard ejecutor, CancellationToken ct)
        {
            if (!plan.HayCambios) return new ResultadoDeVpn(false, "el plan no tiene cambios que aplicar");
            if (ahora.Error is not null || !ahora.Instalado) return new ResultadoDeVpn(false, "WireGuard ya no está disponible: " + (ahora.Error ?? "no está instalado") + ". No se cambió nada.");
            bool existe = ahora.Tuneles.Any(t => string.Equals(t.Nombre, plan.Tunel, StringComparison.OrdinalIgnoreCase));
            if (plan.Accion == AccionDeVpn.Conectar)
            {
                if (existe) return new ResultadoDeVpn(false, "mientras tanto apareció un túnel llamado «" + plan.Tunel + "». No se cambió nada.");
                return await ejecutor.ConectarAsync(plan.Tunel, plan.ConfParaEjecutar()!, ct).ConfigureAwait(false);
            }
            if (!existe) return new ResultadoDeVpn(false, "el túnel «" + plan.Tunel + "» ya no existe. No se cambió nada.");
            if (!ejecutor.EsDeNexo(plan.Tunel)) return new ResultadoDeVpn(false, "el túnel «" + plan.Tunel + "» no lo instaló Nexo. No se cambió nada.");
            return await ejecutor.DesconectarAsync(plan.Tunel, ct).ConfigureAwait(false);
        }
    }
}
