using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Service
{
    /// <summary>
    /// Un modulo que el servicio aloja y que contesta a metodos con su prefijo
    /// (p. ej. "firewall."). Version minima de INexoModule de la Salida 0: aun sin
    /// StartAsync/StopAsync ni bus de eventos, que llegaran con el primer modulo que los necesite.
    /// </summary>
    public interface IModuloDelServicio
    {
        /// <summary>Los metodos exactos que atiende. Todo lo demas es "desconocido".</summary>
        IReadOnlyList<string> Metodos { get; }

        System.Threading.Tasks.Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct);
    }
}
