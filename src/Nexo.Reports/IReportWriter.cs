using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports.Model;

namespace Nexo.Reports
{
    /// <summary>
    /// Contrato unico que ven los modulos de amenazas, privacidad, identidad y
    /// limpieza. Ninguno de ellos sabe que existe Obsidian, ni markdown, ni YAML:
    /// publican un NexoEvent y esta libreria decide como se persiste.
    ///
    /// Esa indireccion es la que permite, en una fase futura, cambiar el backend
    /// (SQLite, un panel propio, un plugin de Obsidian en TypeScript) sin tocar
    /// una sola linea de los modulos que lo consumen.
    /// </summary>
    public interface IReportWriter
    {
        /// <summary>
        /// Escribe la nota del evento, crea las notas de entidad que falten y
        /// enlaza el evento desde la nota-resumen del dia.
        /// </summary>
        Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default);

        /// <summary>
        /// Crea la estructura de carpetas, la nota de entrada y la advertencia de
        /// seguridad. Idempotente: se puede llamar en cada arranque del servicio.
        /// </summary>
        Task InicializarVaultAsync(CancellationToken ct = default);
    }
}
