#if WINDOWS
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Ui.Tray;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// escaneo.* y cuarentena.* por el pipe. Una conexion por llamada, como la bandeja. Aplicar la cuarentena usa el mismo
    /// camino que la bandeja (AccionesDelServicio): si el servicio exige aprobacion de administrador, se abre nexo-tray.exe
    /// elevado con el token; la ventana nunca se eleva a si misma.
    /// </summary>
    public sealed class ServicioDeEscaneoPorPipe : IServicioDeEscaneo
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;
        private readonly ILanzadorElevado _lanzador;

        public ServicioDeEscaneoPorPipe(string pipe, TimeSpan espera, ILanzadorElevado? lanzador = null)
        {
            _pipe = pipe;
            _espera = espera;
            _lanzador = lanzador ?? new LanzadorPorBandeja(pipe);
        }

        public async Task<Consulta<string>> IniciarAsync(IReadOnlyList<string> rutas, int paralelo, CancellationToken ct)
            => LectorDeEscaneo.Iniciar(await LlamarAsync("escaneo.iniciar", new { rutas, paralelo }, ct).ConfigureAwait(false));

        public async Task<Consulta<AvanceDeEscaneo>> AvanceAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Avance(await LlamarAsync("escaneo.progreso", new { id }, ct).ConfigureAwait(false));

        public async Task<Consulta<ResultadoDeEscaneoVista>> ResultadoAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Resultado(await LlamarAsync("escaneo.resultado", new { id }, ct).ConfigureAwait(false));

        public async Task<Consulta<string>> CancelarAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Cancelar(await LlamarAsync("escaneo.cancelar", new { id }, ct).ConfigureAwait(false));

        public async Task<Consulta<PlanDeCuarentena>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamarAsync("cuarentena.previsualizar", new { escaneo = id }, ct).ConfigureAwait(false));

        public async Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct)
        {
            try
            {
                ResultadoDeAplicar r = await AccionesDelServicio.AplicarConAprobacionAsync(
                    _pipe, TipoDeAccion.Cuarentena, token, _lanzador, _espera, ct).ConfigureAwait(false);
                return new ResultadoDeAccion(r.Exito, r.NecesitaElevacion, r.Mensaje);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException
                                       || ex is JsonException || ex is KeyNotFoundException || ex is InvalidOperationException)
            {
                return new ResultadoDeAccion(false, false, "No se pudo hablar con el servicio (" + ex.GetType().Name + "). No se ha cambiado nada.");
            }
        }

        private async Task<RespuestaCruda> LlamarAsync(string metodo, object parametros, CancellationToken ct)
        {
            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(_pipe, _espera, ct).ConfigureAwait(false);
                Respuesta r = await c.LlamarAsync(metodo, parametros, ct).ConfigureAwait(false);
                return new RespuestaCruda(r.Exito, r.Error?.Mensaje, r.Resultado);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            {
                return new RespuestaCruda(false, ex is TimeoutException ? "el servicio no está en marcha" : "no se pudo hablar con el servicio (" + ex.GetType().Name + ")", null);
            }
        }
    }

    /// <summary>
    /// La aprobacion (UAC) la pide nexo-tray.exe, que ya sabe aplicar un plan elevado y comprueba que su ubicacion no la
    /// pueda modificar el usuario. Tiene que estar en la misma carpeta que esta ventana.
    /// </summary>
    internal sealed class LanzadorPorBandeja : ILanzadorElevado
    {
        private readonly string _pipe;
        private readonly string _bandeja;

        public LanzadorPorBandeja(string pipe, string? rutaDeLaBandeja = null)
        {
            _pipe = pipe;
            _bandeja = rutaDeLaBandeja ?? Path.Combine(AppContext.BaseDirectory, "nexo-tray.exe");
        }

        public string? UltimoMotivo { get; private set; }

        public bool Lanzar(TipoDeAccion tipo, string token)
        {
            if (!File.Exists(_bandeja))
            {
                UltimoMotivo = "no se encontró nexo-tray.exe junto a la ventana (" + _bandeja + "); la aprobación se pide desde la bandeja";
                return false;
            }
            var real = new LanzadorElevado(_pipe, _bandeja);
            bool ok = real.Lanzar(tipo, token);
            UltimoMotivo = real.UltimoMotivo;
            return ok;
        }
    }
}
#endif
