using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// Un modulo que trabaja CON LA IDENTIDAD DEL USUARIO (limpieza) no puede escribir sus notas con esa misma
    /// identidad: el vault es del servicio y el usuario no tiene (ni debe tener) permiso para escribirlo. Este
    /// envoltorio hace cada escritura con la identidad del servicio aunque se llame desde dentro de la suplantacion.
    /// </summary>
    public sealed class ReportesFueraDeSuplantacion : IReportWriter
    {
        private readonly IReportWriter _interno;
        public ReportesFueraDeSuplantacion(IReportWriter interno) => _interno = interno;

        public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
            => ContextoDeLlamada.FueraDeSuplantacionAsync(() => _interno.EscribirAsync(evento, ct));

        public Task InicializarVaultAsync(CancellationToken ct = default)
            => ContextoDeLlamada.FueraDeSuplantacionAsync(async () => { await _interno.InicializarVaultAsync(ct).ConfigureAwait(false); return 0; });
    }
}
