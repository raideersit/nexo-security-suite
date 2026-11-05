using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    public sealed record ReglaDeNexo(string Nombre, string Accion, string Direccion, string? Ruta, bool Habilitada);

    public sealed record PerfilDetallado(string Perfil, bool Activo, string EntradaPorDefecto);

    /// <summary>firewall.estado completo (la pestaña Estado solo usa el resumen, <see cref="EstadoDeFirewall"/>).</summary>
    public sealed record DetalleDeFirewall(IReadOnlyList<ReglaDeNexo> Reglas, bool Sigiloso, IReadOnlyList<PerfilDetallado> Perfiles);

    /// <summary>Para que direccion se pide una regla. Ambas = el servicio crea una entrante y una saliente.</summary>
    public enum DireccionPedida
    {
        Ambas,
        Saliente,
        Entrante
    }

    /// <summary>
    /// El firewall visto desde la ventana. Leer el estado solo lee. Bloquear, quitar y el modo sigiloso: el servicio prepara el
    /// plan (no cambia nada), se confirma y se aplica con el token. El servicio solo toca reglas del grupo «Nexo Security Suite»,
    /// nunca bloquea procesos del sistema ni a Defender, y no enciende un firewall apagado: eso lo decide el, no la ventana.
    /// </summary>
    public interface IServicioDeFirewall
    {
        Task<Consulta<DetalleDeFirewall>> EstadoAsync(CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarBloqueoAsync(string rutaDelPrograma, DireccionPedida direccion, CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarQuitarAsync(string nombreDeLaRegla, CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarSigilosoAsync(bool activar, CancellationToken ct);
        Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct);
    }

    public sealed class ServicioDeFirewallNoDisponible : IServicioDeFirewall
    {
        private readonly string _motivo;

        public ServicioDeFirewallNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<DetalleDeFirewall>> EstadoAsync(CancellationToken ct) => Task.FromResult(Consulta<DetalleDeFirewall>.Mal(_motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarBloqueoAsync(string r, DireccionPedida d, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarQuitarAsync(string n, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarSigilosoAsync(bool a, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
    }

    public static class LectorDeFirewall
    {
        /// <summary>Los parametros de firewall.previsualizar para bloquear un programa. Sin «direccion» = las dos.</summary>
        public static object ParametrosDeBloqueo(string ruta, DireccionPedida d) => d switch
        {
            DireccionPedida.Saliente => new { tipo = "regla", ruta, accion = "bloquear", direccion = "saliente" },
            DireccionPedida.Entrante => new { tipo = "regla", ruta, accion = "bloquear", direccion = "entrante" },
            _ => new { tipo = "regla", ruta, accion = "bloquear" }
        };

        /// <summary>firewall.estado. Una regla o un perfil con otra forma invalida la respuesta entera.</summary>
        public static Consulta<DetalleDeFirewall> Estado(RespuestaCruda r)
        {
            if (!r.Exito) return Consulta<DetalleDeFirewall>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<DetalleDeFirewall>.Mal("respuesta vacía del servicio");
            try
            {
                return Consulta<DetalleDeFirewall>.Bien(new DetalleDeFirewall(
                    e.GetProperty("reglas_de_nexo").EnumerateArray().Select(x => new ReglaDeNexo(
                        x.GetProperty("nombre").GetString() ?? throw new InvalidOperationException(),
                        x.GetProperty("accion").GetString() ?? "",
                        x.GetProperty("direccion").GetString() ?? "",
                        x.TryGetProperty("ruta", out JsonElement ru) && ru.ValueKind == JsonValueKind.String ? ru.GetString() : null,
                        x.GetProperty("habilitada").GetBoolean())).ToList(),
                    e.GetProperty("sigiloso").GetBoolean(),
                    e.GetProperty("perfiles").EnumerateArray().Select(p => new PerfilDetallado(
                        p.GetProperty("perfil").GetString() ?? "?",
                        p.GetProperty("activo").GetBoolean(),
                        p.GetProperty("entrada_por_defecto").GetString() ?? "")).ToList()));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<DetalleDeFirewall>.Mal("respuesta del servicio no reconocida");
            }
        }

        public static string NombreDePerfil(string p) => p switch
        {
            "Publico" => "Público",
            _ => p
        };
    }
}
