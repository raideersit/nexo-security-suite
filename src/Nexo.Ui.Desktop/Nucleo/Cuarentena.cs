using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Una entrada de cuarentena.listar.</summary>
    public sealed record ElementoDeCuarentena(string Id, string RutaOriginal, long Bytes, string Firma, DateTimeOffset Fecha, DateTimeOffset Vence);

    public sealed record ListaDeCuarentena(IReadOnlyList<ElementoDeCuarentena> Elementos);

    /// <summary>
    /// La cuarentena vista desde la ventana. Listar solo lee. Restaurar y eliminar los vencidos van en dos pasos: el servicio
    /// prepara el plan (no cambia nada) y despues se aplica con su token, con la aprobacion que el servicio exija.
    /// No hay «eliminar uno ahora»: el servicio no lo ofrece, y la ventana no lo inventa.
    /// </summary>
    public interface IServicioDeCuarentena
    {
        Task<Consulta<ListaDeCuarentena>> ListarAsync(CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarRestauracionAsync(string id, CancellationToken ct);
        Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct);
        Task<Consulta<PlanDelServicio>> PrevisualizarPurgaAsync(CancellationToken ct);
        Task<ResultadoDeAccion> PurgarAsync(string token, CancellationToken ct);
    }

    public sealed class ServicioDeCuarentenaNoDisponible : IServicioDeCuarentena
    {
        private readonly string _motivo;

        public ServicioDeCuarentenaNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<ListaDeCuarentena>> ListarAsync(CancellationToken ct) => Task.FromResult(Consulta<ListaDeCuarentena>.Mal(_motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarRestauracionAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
        public Task<Consulta<PlanDelServicio>> PrevisualizarPurgaAsync(CancellationToken ct) => Task.FromResult(Consulta<PlanDelServicio>.Mal(_motivo));
        public Task<ResultadoDeAccion> PurgarAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
    }

    public static class LectorDeCuarentena
    {
        /// <summary>cuarentena.listar. Una entrada rota invalida la lista entera: no se muestra una lista a medias como si fuera toda.</summary>
        public static Consulta<ListaDeCuarentena> Listar(RespuestaCruda r)
        {
            if (!r.Exito) return Consulta<ListaDeCuarentena>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<ListaDeCuarentena>.Mal("respuesta vacía del servicio");
            try
            {
                return Consulta<ListaDeCuarentena>.Bien(new ListaDeCuarentena(e.GetProperty("elementos").EnumerateArray()
                    .Select(x => new ElementoDeCuarentena(
                        x.GetProperty("id").GetString() ?? throw new InvalidOperationException(),
                        x.GetProperty("ruta_original").GetString() ?? "",
                        x.GetProperty("bytes").GetInt64(),
                        x.GetProperty("firma").GetString() ?? "",
                        x.GetProperty("fecha").GetDateTimeOffset(),
                        x.GetProperty("vence").GetDateTimeOffset()))
                    .ToList()));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<ListaDeCuarentena>.Mal("respuesta del servicio no reconocida");
            }
        }
    }
}
