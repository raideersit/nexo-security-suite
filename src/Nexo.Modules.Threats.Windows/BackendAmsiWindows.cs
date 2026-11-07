using System;
using Nexo.Modules.Threats.Escaner;
using Nexo.Native.Amsi;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// AMSI real de Windows para <see cref="MotorAmsi"/>. Abre un contexto la primera vez que se usa y lo reutiliza.
    /// Si no se puede abrir (sin <c>amsi.dll</c>) cada llamada devuelve un fallo con el motivo: nunca finge que hay AMSI.
    /// </summary>
    public sealed class BackendAmsiWindows : IBackendAmsi, IDisposable
    {
        private readonly object _cerrojo = new object();
        private ContextoAmsi? _contexto;
        private string? _motivo;
        private bool _intentado;

        public RespuestaDeAmsi Escanear(byte[] datos, int longitud, string nombreDelContenido)
        {
            ContextoAmsi? ctx;
            lock (_cerrojo)
            {
                if (!_intentado)
                {
                    _intentado = true;
                    _contexto = ContextoAmsi.Abrir("Nexo", out _motivo);
                }
                ctx = _contexto;
            }
            if (ctx is null) return RespuestaDeAmsi.Fallo(_motivo ?? "AMSI no se pudo abrir.");

            RespuestaNativaAmsi r = ctx.Escanear(datos, longitud, nombreDelContenido);
            return r.Exito ? RespuestaDeAmsi.Ok(r.Codigo) : RespuestaDeAmsi.Fallo(r.Motivo ?? "fallo desconocido");
        }

        public void Dispose()
        {
            lock (_cerrojo) { _contexto?.Dispose(); _contexto = null; }
        }
    }
}
