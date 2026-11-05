using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Una regla del catalogo (limpieza.reglas). Riesgo: Bajo | Medio | Alto.</summary>
    public sealed record ReglaDeLimpiezaVista(string Id, string Nombre, string Categoria, string Riesgo, bool RequiereAdmin, bool ActivaPorDefecto);

    /// <summary>limpieza.reglas. Modo: papelera | simulado | borrado-permanente (lo fija la configuracion del servicio).</summary>
    public sealed record CatalogoDeLimpieza(string Modo, bool Reversible, IReadOnlyList<ReglaDeLimpiezaVista> Reglas);

    public sealed record CategoriaDeLimpieza(string Categoria, int Archivos, long Bytes);

    public sealed record EjemploDeLimpieza(string Ruta, long Bytes, string Categoria);

    /// <summary>limpieza.previsualizar: lo que se borraria. No borra nada. Sin archivos no hay token.</summary>
    public sealed record VistaDeLimpieza(
        int TotalArchivos,
        long TotalBytes,
        bool Reversible,
        IReadOnlyList<CategoriaDeLimpieza> Categorias,
        IReadOnlyList<EjemploDeLimpieza> Ejemplos,
        IReadOnlyList<string> Omitidas,
        int OmitidasTotal,
        IReadOnlyList<string> ReglasSinPermisos,
        string? Token,
        DateTimeOffset? Expira);

    /// <summary>
    /// La limpieza vista desde la ventana. El cliente elige reglas del catalogo por id, nunca rutas; el servicio recorre y borra
    /// con la identidad del usuario, y el modo (Papelera, simulado o permanente) lo decide su configuracion, no la ventana.
    /// </summary>
    public interface IServicioDeLimpieza
    {
        Task<Consulta<CatalogoDeLimpieza>> ReglasAsync(CancellationToken ct);
        Task<Consulta<VistaDeLimpieza>> PrevisualizarAsync(IReadOnlyList<string> reglas, CancellationToken ct);
        Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct);
    }

    public sealed class ServicioDeLimpiezaNoDisponible : IServicioDeLimpieza
    {
        private readonly string _motivo;

        public ServicioDeLimpiezaNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<CatalogoDeLimpieza>> ReglasAsync(CancellationToken ct) => Task.FromResult(Consulta<CatalogoDeLimpieza>.Mal(_motivo));
        public Task<Consulta<VistaDeLimpieza>> PrevisualizarAsync(IReadOnlyList<string> reglas, CancellationToken ct) => Task.FromResult(Consulta<VistaDeLimpieza>.Mal(_motivo));
        public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
    }

    public static class LectorDeLimpieza
    {
        public static Consulta<CatalogoDeLimpieza> Reglas(RespuestaCruda r)
            => Leer(r, e => new CatalogoDeLimpieza(
                e.GetProperty("modo").GetString() ?? throw new InvalidOperationException(),
                e.GetProperty("reversible").GetBoolean(),
                e.GetProperty("reglas").EnumerateArray().Select(x => new ReglaDeLimpiezaVista(
                    x.GetProperty("id").GetString() ?? throw new InvalidOperationException(),
                    x.GetProperty("nombre").GetString() ?? "",
                    x.GetProperty("categoria").GetString() ?? "",
                    x.GetProperty("riesgo").GetString() ?? "",
                    x.GetProperty("requiere_admin").GetBoolean(),
                    x.GetProperty("activa_por_defecto").GetBoolean())).ToList()));

        public static Consulta<VistaDeLimpieza> Vista(RespuestaCruda r)
            => Leer(r, e => new VistaDeLimpieza(
                e.GetProperty("total_archivos").GetInt32(),
                e.GetProperty("total_bytes").GetInt64(),
                e.GetProperty("reversible").GetBoolean(),
                e.GetProperty("categorias").EnumerateArray().Select(c => new CategoriaDeLimpieza(
                    c.GetProperty("categoria").GetString() ?? "", c.GetProperty("archivos").GetInt32(), c.GetProperty("bytes").GetInt64())).ToList(),
                e.GetProperty("ejemplos").EnumerateArray().Select(x => new EjemploDeLimpieza(
                    x.GetProperty("ruta").GetString() ?? "", x.GetProperty("bytes").GetInt64(), x.GetProperty("categoria").GetString() ?? "")).ToList(),
                e.GetProperty("omitidas").EnumerateArray().Select(o => o.GetString() ?? "").ToList(),
                e.GetProperty("omitidas_total").GetInt32(),
                e.GetProperty("reglas_sin_permisos").EnumerateArray().Select(o => o.GetString() ?? "").ToList(),
                e.TryGetProperty("token", out JsonElement t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null,
                e.TryGetProperty("expira", out JsonElement x2) && x2.ValueKind == JsonValueKind.String ? x2.GetDateTimeOffset() : null));

        private static Consulta<T> Leer<T>(RespuestaCruda r, Func<JsonElement, T> leer) where T : class
        {
            if (!r.Exito) return Consulta<T>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<T>.Mal("respuesta vacía del servicio");
            try
            {
                return Consulta<T>.Bien(leer(e));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<T>.Mal("respuesta del servicio no reconocida");
            }
        }

        /// <summary>Que significa el modo del servicio, dicho para una persona.</summary>
        public static string Modo(string modo) => modo switch
        {
            "papelera" => "a la Papelera (se puede recuperar)",
            "simulado" => "simulado (solo anota lo que borraría; no borra nada)",
            "borrado-permanente" => "borrado PERMANENTE (no se puede recuperar)",
            _ => modo
        };
    }
}
