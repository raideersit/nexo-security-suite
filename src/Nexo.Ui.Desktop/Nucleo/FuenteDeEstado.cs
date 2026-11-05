using System;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>De donde saca la ventana el estado del servicio. Solo LECTURA.</summary>
    public interface IFuenteDeEstado
    {
        Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct);
    }

#if WINDOWS
    /// <summary>El servicio real, por el named pipe (lo mismo que consulta la bandeja).</summary>
    public sealed class FuentePorPipe : IFuenteDeEstado
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public FuentePorPipe(string pipe, TimeSpan espera)
        {
            _pipe = pipe;
            _espera = espera;
        }

        public Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct)
            => ConsultorDelServicio.ConsultarAsync(_pipe, _espera, ct);
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

        public Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct)
            => Task.FromResult(InstantaneaDelServicio.SinConexion(_motivo));
    }

    public static class Fuentes
    {
        public static readonly TimeSpan Espera = TimeSpan.FromSeconds(3);

        public static IFuenteDeEstado PorDefecto(string pipe)
        {
#if WINDOWS
            return new FuentePorPipe(pipe, Espera);
#else
            return new FuenteNoDisponible(OperatingSystem.IsWindows()
                ? "esta compilación no incluye la conexión con el servicio (use la de Windows)"
                : "el servicio de Nexo todavía no existe para Linux");
#endif
        }
    }
}
