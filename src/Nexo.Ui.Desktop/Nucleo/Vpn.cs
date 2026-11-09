using System.Threading;
using System.Threading.Tasks;
#if WINDOWS
using Nexo.Ui.Tray.Nucleo;
#endif

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// Conectar y desconectar la VPN, vistos desde la ventana. El servicio prepara el plan (no cambia nada), la ventana lo muestra y pide
    /// confirmar, y se aplica con el token (con UAC si la politica lo exige). Las reglas (que se conecta y que se rechaza) son del servicio.
    /// </summary>
    public interface IServicioDeVpn
    {
        Task<Consulta<PlanDelServicio>> PrevisualizarConexionAsync(string conf, string archivo, CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarDesconexionAsync(string tunel, CancellationToken ct);
        Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct);
    }

    public sealed class ServicioDeVpnNoDisponible : IServicioDeVpn
    {
        private readonly string _motivo;
        public ServicioDeVpnNoDisponible(string motivo) => _motivo = motivo;
        public Task<Consulta<PlanDelServicio>> PrevisualizarConexionAsync(string conf, string archivo, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarDesconexionAsync(string tunel, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
    }

#if WINDOWS
    /// <summary>vpn.* por el pipe. Aplicar va por AccionesDelServicio (TipoDeAccion.Vpn), igual que el firewall.</summary>
    public sealed class ServicioDeVpnPorPipe : IServicioDeVpn
    {
        private readonly string _pipe;
        private readonly System.TimeSpan _espera;
        private readonly ILanzadorElevado _lanzador;

        public ServicioDeVpnPorPipe(string pipe, System.TimeSpan espera, ILanzadorElevado? lanzador = null)
        {
            _pipe = pipe;
            _espera = espera;
            _lanzador = lanzador ?? new LanzadorPorBandeja(pipe);
        }

        public async Task<Consulta<PlanDelServicio>> PrevisualizarConexionAsync(string conf, string archivo, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "vpn.previsualizar", new { tipo = "conectar", conf, archivo }, ct).ConfigureAwait(false));

        public async Task<Consulta<PlanDelServicio>> PrevisualizarDesconexionAsync(string tunel, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "vpn.previsualizar", new { tipo = "desconectar", tunel }, ct).ConfigureAwait(false));

        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Vpn, token, _lanzador, ct);
    }
#endif
}
