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

        public async Task<Consulta<PlanDelServicio>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamarAsync("cuarentena.previsualizar", new { escaneo = id }, ct).ConfigureAwait(false));

        public Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Cuarentena, token, _lanzador, ct);

        private Task<RespuestaCruda> LlamarAsync(string metodo, object parametros, CancellationToken ct)
            => LlamadaPorPipe.LlamarAsync(_pipe, _espera, metodo, parametros, ct);
    }

    /// <summary>cuarentena.* por el pipe. Restaurar y purgar van por AccionesDelServicio, igual que en la bandeja.</summary>
    public sealed class ServicioDeCuarentenaPorPipe : IServicioDeCuarentena
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;
        private readonly ILanzadorElevado _lanzador;

        public ServicioDeCuarentenaPorPipe(string pipe, TimeSpan espera, ILanzadorElevado? lanzador = null)
        {
            _pipe = pipe;
            _espera = espera;
            _lanzador = lanzador ?? new LanzadorPorBandeja(pipe);
        }

        public async Task<Consulta<ListaDeCuarentena>> ListarAsync(CancellationToken ct)
            => LectorDeCuarentena.Listar(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "cuarentena.listar", null, ct).ConfigureAwait(false));

        public async Task<Consulta<PlanDelServicio>> PrevisualizarRestauracionAsync(string id, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "cuarentena.previsualizar-restauracion", new { id }, ct).ConfigureAwait(false));

        public Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Restauracion, token, _lanzador, ct);

        public async Task<Consulta<PlanDelServicio>> PrevisualizarPurgaAsync(CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "cuarentena.previsualizar-purga", null, ct).ConfigureAwait(false));

        public Task<ResultadoDeAccion> PurgarAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Purga, token, _lanzador, ct);
    }

    /// <summary>firewall.* por el pipe. Aplicar va por AccionesDelServicio (TipoDeAccion.Firewall), igual que en la bandeja.</summary>
    public sealed class ServicioDeFirewallPorPipe : IServicioDeFirewall
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;
        private readonly ILanzadorElevado _lanzador;

        public ServicioDeFirewallPorPipe(string pipe, TimeSpan espera, ILanzadorElevado? lanzador = null)
        {
            _pipe = pipe;
            _espera = espera;
            _lanzador = lanzador ?? new LanzadorPorBandeja(pipe);
        }

        public async Task<Consulta<DetalleDeFirewall>> EstadoAsync(CancellationToken ct)
            => LectorDeFirewall.Estado(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "firewall.estado", null, ct).ConfigureAwait(false));

        public Task<Consulta<PlanDelServicio>> PrevisualizarBloqueoAsync(string rutaDelPrograma, DireccionPedida direccion, CancellationToken ct)
            => PrevisualizarAsync(LectorDeFirewall.ParametrosDeBloqueo(rutaDelPrograma, direccion), ct);

        public Task<Consulta<PlanDelServicio>> PrevisualizarQuitarAsync(string nombreDeLaRegla, CancellationToken ct)
            => PrevisualizarAsync(new { tipo = "quitar", nombre = nombreDeLaRegla }, ct);

        public Task<Consulta<PlanDelServicio>> PrevisualizarSigilosoAsync(bool activar, CancellationToken ct)
            => PrevisualizarAsync(new { tipo = "sigiloso", activar }, ct);

        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Firewall, token, _lanzador, ct);

        // La descripcion del servicio ya incluye los cambios, los rechazos y los avisos.
        private async Task<Consulta<PlanDelServicio>> PrevisualizarAsync(object parametros, CancellationToken ct)
            => LectorDeEscaneo.Plan(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "firewall.previsualizar", parametros, ct).ConfigureAwait(false));
    }

    /// <summary>limpieza.* por el pipe. Aplicar va por AccionesDelServicio (TipoDeAccion.Limpieza), igual que en la bandeja.</summary>
    public sealed class ServicioDeLimpiezaPorPipe : IServicioDeLimpieza
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;
        private readonly ILanzadorElevado _lanzador;

        public ServicioDeLimpiezaPorPipe(string pipe, TimeSpan espera, ILanzadorElevado? lanzador = null)
        {
            _pipe = pipe;
            _espera = espera;
            _lanzador = lanzador ?? new LanzadorPorBandeja(pipe);
        }

        public async Task<Consulta<CatalogoDeLimpieza>> ReglasAsync(CancellationToken ct)
            => LectorDeLimpieza.Reglas(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "limpieza.reglas", null, ct).ConfigureAwait(false));

        public async Task<Consulta<VistaDeLimpieza>> PrevisualizarAsync(IReadOnlyList<string> reglas, CancellationToken ct)
            => LectorDeLimpieza.Vista(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "limpieza.previsualizar", new { reglas }, ct).ConfigureAwait(false));

        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct)
            => LlamadaPorPipe.AplicarAsync(_pipe, _espera, TipoDeAccion.Limpieza, token, _lanzador, ct);
    }

    /// <summary>tiempo-real.estado y tiempo-real.detecciones por el pipe. Solo lectura: el pipe no ofrece cambiar nada del tiempo real.</summary>
    public sealed class ServicioDeTiempoRealPorPipe : IServicioDeTiempoReal
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public ServicioDeTiempoRealPorPipe(string pipe, TimeSpan espera)
        {
            _pipe = pipe;
            _espera = espera;
        }

        public async Task<Consulta<DetalleDeTiempoReal>> ConsultarAsync(CancellationToken ct)
        {
            RespuestaCruda estado = await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "tiempo-real.estado", null, ct).ConfigureAwait(false);
            if (!estado.Exito) return LectorDeTiempoReal.Leer(estado, estado);
            RespuestaCruda detecciones = await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "tiempo-real.detecciones", null, ct).ConfigureAwait(false);
            return LectorDeTiempoReal.Leer(estado, detecciones);
        }
    }

    /// <summary>disco.estado y disco.leer por el pipe. Los dos solo leen; el servicio limita las lecturas nuevas.</summary>
    public sealed class ServicioDeDiscoPorPipe : IServicioDeDisco
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public ServicioDeDiscoPorPipe(string pipe, TimeSpan espera)
        {
            _pipe = pipe;
            _espera = espera;
        }

        public async Task<Consulta<EstadoDeDiscos>> EstadoAsync(CancellationToken ct)
            => LectorDeDisco.Estado(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "disco.estado", null, ct).ConfigureAwait(false));

        public async Task<Consulta<PedidoDeLectura>> PedirLecturaAsync(CancellationToken ct)
            => LectorDeDisco.Pedido(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "disco.leer", null, ct).ConfigureAwait(false));
    }

    internal static class LlamadaPorPipe
    {
        /// <summary>Una llamada en su propia conexion. Un fallo de conexion vuelve como respuesta con error, no como excepcion.</summary>
        public static async Task<RespuestaCruda> LlamarAsync(string pipe, TimeSpan espera, string metodo, object? parametros, CancellationToken ct)
        {
            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
                Respuesta r = await c.LlamarAsync(metodo, parametros, ct).ConfigureAwait(false);
                return new RespuestaCruda(r.Exito, r.Error?.Mensaje, r.Resultado);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            {
                return new RespuestaCruda(false, ex is TimeoutException ? "el servicio no está en marcha" : "no se pudo hablar con el servicio (" + ex.GetType().Name + ")", null);
            }
        }

        /// <summary>Aplica un plan por el mismo camino que la bandeja: normal y, si el servicio exige UAC, con nexo-tray.exe elevado.</summary>
        public static async Task<ResultadoDeAccion> AplicarAsync(string pipe, TimeSpan espera, TipoDeAccion tipo, string token,
                                                                 ILanzadorElevado lanzador, CancellationToken ct)
        {
            try
            {
                ResultadoDeAplicar r = await AccionesDelServicio.AplicarConAprobacionAsync(pipe, tipo, token, lanzador, espera, ct).ConfigureAwait(false);
                return new ResultadoDeAccion(r.Exito, r.NecesitaElevacion, r.Mensaje);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException
                                       || ex is JsonException || ex is KeyNotFoundException || ex is InvalidOperationException)
            {
                return new ResultadoDeAccion(false, false, "No se pudo hablar con el servicio (" + ex.GetType().Name + "). No se ha cambiado nada.");
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
