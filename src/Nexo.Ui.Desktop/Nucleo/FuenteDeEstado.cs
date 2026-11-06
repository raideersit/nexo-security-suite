using System;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ui.Tray.Nucleo;
#if WINDOWS
using System.IO;
using System.Text.Json;
using Nexo.Ipc;
#endif

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>De donde saca la ventana el estado del servicio. Solo LECTURA.</summary>
    public interface IFuenteDeEstado
    {
        Task<EstadoCompleto> ConsultarAsync(CancellationToken ct);
    }

#if WINDOWS
    /// <summary>
    /// El servicio real, por el named pipe. Lo del tiempo real se pide con el mismo consultor que la bandeja; el resto de
    /// modulos, en una segunda conexion, cada uno por separado: si uno falla, los otros se siguen mostrando.
    /// Todos los metodos usados son de solo lectura.
    /// </summary>
    public sealed class FuentePorPipe : IFuenteDeEstado
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public FuentePorPipe(string pipe, TimeSpan espera)
        {
            _pipe = pipe;
            _espera = espera;
        }

        public async Task<EstadoCompleto> ConsultarAsync(CancellationToken ct)
        {
            InstantaneaDelServicio s = await ConsultorDelServicio.ConsultarAsync(_pipe, _espera, ct).ConfigureAwait(false);
            if (!s.Conectado) return EstadoCompleto.SinConexion(s);

            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(_pipe, _espera, ct).ConfigureAwait(false);
                return new EstadoCompleto(
                    s,
                    LectorDeModulos.Motor(await LlamarAsync(c, "escaneo.estado", ct).ConfigureAwait(false)),
                    LectorDeModulos.Programado(await LlamarAsync(c, "escaneo-programado.estado", ct).ConfigureAwait(false)),
                    LectorDeModulos.Firewall(await LlamarAsync(c, "firewall.estado", ct).ConfigureAwait(false)),
                    LectorDeModulos.Cuarentena(await LlamarAsync(c, "cuarentena.listar", ct).ConfigureAwait(false)));
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            {
                return EstadoCompleto.SoloServicio(s, "no se pudo pedir el detalle al servicio (" + ex.GetType().Name + ")");
            }
        }

        private static async Task<RespuestaCruda> LlamarAsync(ClienteDePipe c, string metodo, CancellationToken ct)
        {
            Respuesta r = await c.LlamarAsync(metodo, ct: ct).ConfigureAwait(false);
            return new RespuestaCruda(r.Exito, r.Error?.Mensaje, r.Resultado);
        }
    }
#endif

    /// <summary>
    /// No hay con quien hablar (Linux, o una compilacion sin el pipe). Siempre devuelve «sin conexion» con el motivo:
    /// la ventana lo muestra tal cual y no aparenta un estado que no conoce.
    /// </summary>
    public sealed class FuenteNoDisponible : IFuenteDeEstado
    {
        private readonly string _motivo;

        public FuenteNoDisponible(string motivo) => _motivo = motivo;

        public Task<EstadoCompleto> ConsultarAsync(CancellationToken ct)
            => Task.FromResult(EstadoCompleto.SinConexion(InstantaneaDelServicio.SinConexion(_motivo)));
    }

    public static class Fuentes
    {
        public static readonly TimeSpan Espera = TimeSpan.FromSeconds(3);

        public static IFuenteDeEstado PorDefecto(string pipe)
        {
#if WINDOWS
            return new FuentePorPipe(pipe, Espera);
#else
            return new FuenteNoDisponible(SinServicio);
#endif
        }

        public static IServicioDeEscaneo EscaneoPorDefecto(string pipe)
        {
#if WINDOWS
            return new ServicioDeEscaneoPorPipe(pipe, Espera);
#else
            return new ServicioDeEscaneoNoDisponible(SinServicio);
#endif
        }

        public static IServicioDeCuarentena CuarentenaPorDefecto(string pipe)
        {
#if WINDOWS
            return new ServicioDeCuarentenaPorPipe(pipe, Espera);
#else
            return new ServicioDeCuarentenaNoDisponible(SinServicio);
#endif
        }

        public static IServicioDeFirewall FirewallPorDefecto(string pipe)
        {
#if WINDOWS
            return new ServicioDeFirewallPorPipe(pipe, Espera);
#else
            return new ServicioDeFirewallNoDisponible(SinServicio);
#endif
        }

        public static IServicioDeLimpieza LimpiezaPorDefecto(string pipe)
        {
#if WINDOWS
            return new ServicioDeLimpiezaPorPipe(pipe, Espera);
#else
            return new ServicioDeLimpiezaNoDisponible(SinServicio);
#endif
        }

        public static IServicioDeTiempoReal TiempoRealPorDefecto(string pipe)
        {
#if WINDOWS
            return new ServicioDeTiempoRealPorPipe(pipe, Espera);
#else
            return new ServicioDeTiempoRealNoDisponible(SinServicio);
#endif
        }

        private static string SinServicio => OperatingSystem.IsWindows()
            ? "esta compilación no incluye la conexión con el servicio (use la de Windows)"
            : "el servicio de Nexo todavía no existe para Linux";
    }
}
