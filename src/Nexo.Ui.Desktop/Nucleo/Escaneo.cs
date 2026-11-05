using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>escaneo.progreso. Estado: corriendo | terminado | cancelado | fallido.</summary>
    public sealed record AvanceDeEscaneo(string Id, string Estado, int Analizados, string? Error);

    public sealed record DeteccionDeEscaneo(string Ruta, string Firma, long Bytes, string? Sha256);

    /// <summary>escaneo.resultado. Si <see cref="Listo"/> es false no hay resultado (sigue, se cancelo o fallo).</summary>
    public sealed record ResultadoDeEscaneoVista(
        string Id,
        string Estado,
        bool Listo,
        int Analizados,
        bool CompletamenteLimpio,
        bool Incompleto,
        string? MotivoIncompleto,
        double DuracionSegundos,
        IReadOnlyList<DeteccionDeEscaneo> Detecciones,
        IReadOnlyList<string> Omitidos,
        int OmitidosTotal,
        string? Error);

    /// <summary>cuarentena.previsualizar: lo que se moveria. No cambia nada; el token permite aplicarlo despues.</summary>
    public sealed record PlanDeCuarentena(string Descripcion, bool HayCambios, string? Token, IReadOnlyList<string> Avisos);

    /// <summary>Lo que paso al pedir que se aplique un plan.</summary>
    public sealed record ResultadoDeAccion(bool Exito, bool PidioAprobacion, string Mensaje);

    /// <summary>El escaneo bajo demanda, visto desde la ventana. Escanear solo lee; poner en cuarentena va con vista previa y token.</summary>
    public interface IServicioDeEscaneo
    {
        Task<Consulta<string>> IniciarAsync(IReadOnlyList<string> rutas, int paralelo, CancellationToken ct);
        Task<Consulta<AvanceDeEscaneo>> AvanceAsync(string id, CancellationToken ct);
        Task<Consulta<ResultadoDeEscaneoVista>> ResultadoAsync(string id, CancellationToken ct);
        Task<Consulta<string>> CancelarAsync(string id, CancellationToken ct);
        Task<Consulta<PlanDeCuarentena>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct);
        Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct);
    }

    /// <summary>Sin servicio (Linux): todo contesta que no se puede, con el motivo.</summary>
    public sealed class ServicioDeEscaneoNoDisponible : IServicioDeEscaneo
    {
        private readonly string _motivo;

        public ServicioDeEscaneoNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<string>> IniciarAsync(IReadOnlyList<string> rutas, int paralelo, CancellationToken ct) => Task.FromResult(Consulta<string>.Mal(_motivo));
        public Task<Consulta<AvanceDeEscaneo>> AvanceAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<AvanceDeEscaneo>.Mal(_motivo));
        public Task<Consulta<ResultadoDeEscaneoVista>> ResultadoAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<ResultadoDeEscaneoVista>.Mal(_motivo));
        public Task<Consulta<string>> CancelarAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<string>.Mal(_motivo));
        public Task<Consulta<PlanDeCuarentena>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<PlanDeCuarentena>.Mal(_motivo));
        public Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct) => Task.FromResult(new ResultadoDeAccion(false, false, _motivo));
    }

    /// <summary>Lee las respuestas de escaneo.* y cuarentena.previsualizar. Mismas reglas que <see cref="LectorDeModulos"/>.</summary>
    public static class LectorDeEscaneo
    {
        public static Consulta<string> Iniciar(RespuestaCruda r)
            => Leer(r, e => e.GetProperty("id").GetString() ?? throw new InvalidOperationException());

        public static Consulta<AvanceDeEscaneo> Avance(RespuestaCruda r)
            => Leer(r, e => new AvanceDeEscaneo(
                e.GetProperty("id").GetString() ?? "", e.GetProperty("estado").GetString() ?? "",
                e.GetProperty("analizados").GetInt32(), Texto(e, "error")));

        public static Consulta<ResultadoDeEscaneoVista> Resultado(RespuestaCruda r)
            => Leer(r, e =>
            {
                string id = e.GetProperty("id").GetString() ?? "";
                string estado = e.GetProperty("estado").GetString() ?? "";
                if (!e.GetProperty("listo").GetBoolean())
                    return new ResultadoDeEscaneoVista(id, estado, false, 0, false, false, null, 0,
                        Array.Empty<DeteccionDeEscaneo>(), Array.Empty<string>(), 0, Texto(e, "error"));

                return new ResultadoDeEscaneoVista(
                    id, estado, true,
                    Analizados: e.GetProperty("analizados").GetInt32(),
                    CompletamenteLimpio: e.GetProperty("completamente_limpio").GetBoolean(),
                    Incompleto: e.GetProperty("incompleto").GetBoolean(),
                    MotivoIncompleto: Texto(e, "motivo_incompleto"),
                    DuracionSegundos: e.GetProperty("duracion_segundos").GetDouble(),
                    Detecciones: e.GetProperty("detecciones").EnumerateArray().Select(d => new DeteccionDeEscaneo(
                        d.GetProperty("ruta").GetString() ?? "", d.GetProperty("firma").GetString() ?? "",
                        d.GetProperty("bytes").GetInt64(), Texto(d, "sha256"))).ToList(),
                    Omitidos: e.GetProperty("omitidos").EnumerateArray().Select(o => o.GetString() ?? "").ToList(),
                    OmitidosTotal: e.GetProperty("omitidos_total").GetInt32(),
                    Error: Texto(e, "error"));
            });

        public static Consulta<string> Cancelar(RespuestaCruda r) => Leer(r, e => e.GetProperty("id").GetString() ?? "");

        public static Consulta<PlanDeCuarentena> Plan(RespuestaCruda r)
            => Leer(r, e => new PlanDeCuarentena(
                e.GetProperty("descripcion").GetString() ?? "",
                e.GetProperty("hay_cambios").GetBoolean(),
                Texto(e, "token"),
                e.TryGetProperty("avisos", out JsonElement a) && a.ValueKind == JsonValueKind.Array
                    ? a.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                    : new List<string>()));

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

        private static string? Texto(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    public enum FaseDeEscaneo
    {
        /// <summary>No se ha lanzado ninguno (o se puede lanzar otro).</summary>
        Listo,
        Iniciando,
        Corriendo,
        Terminado,
        Cancelado,
        Fallido
    }

    /// <summary>
    /// El recuadro de resultado de la pestaña «Escaneo». Nunca dice «limpio» si algo no se analizo, si el escaneo quedo a
    /// medias, si se cancelo o si fallo.
    /// </summary>
    public static class ResumirEscaneo
    {
        public static (Indicador Indicador, string Titulo, string Detalle) Desde(FaseDeEscaneo fase, int analizados,
                                                                               ResultadoDeEscaneoVista? r, string? error)
        {
            switch (fase)
            {
                case FaseDeEscaneo.Listo:
                    return (Indicador.SinDatos, "Elija qué analizar y pulse «Iniciar escaneo».",
                        "Escanear no modifica nada: poner en cuarentena es una acción aparte.");
                case FaseDeEscaneo.Iniciando:
                    return (Indicador.SinDatos, "Iniciando el escaneo...", "");
                case FaseDeEscaneo.Corriendo:
                    return (Indicador.SinDatos, "Escaneando...", Archivos(analizados) + " analizados hasta ahora. Escanear no modifica nada.");
                case FaseDeEscaneo.Cancelado:
                    return (Indicador.Atencion, "Escaneo cancelado.",
                        "Se analizaron " + Archivos(analizados) + " antes de cancelar. No cubre todo: no cuenta como limpio.");
                case FaseDeEscaneo.Fallido:
                    return (Indicador.Atencion, "El escaneo no se pudo completar.", "Motivo: " + (error ?? "desconocido") + ". No cuenta como limpio.");
            }

            if (r is null || !r.Listo)
                return (Indicador.SinDatos, "No se recibió el resultado.", "Motivo: " + (error ?? r?.Error ?? "desconocido") + ".");

            int d = r.Detecciones.Count;
            string omit = r.OmitidosTotal == 1 ? "1 archivo no se pudo analizar" : r.OmitidosTotal + " archivos no se pudieron analizar";

            if (r.Incompleto)
                return (d > 0 ? Indicador.Alerta : Indicador.Atencion,
                    "Escaneo INCOMPLETO" + (d > 0 ? ": ya hay " + Detecciones(d) + "." : "."),
                    "Motivo: " + (r.MotivoIncompleto ?? "no informado") + ". Lo que no se analizó no cuenta como limpio.");
            if (d > 0)
                return (Indicador.Alerta, Detecciones(d) + ".",
                    "Los archivos no se han tocado: puede ponerlos en cuarentena." + (r.OmitidosTotal > 0 ? " Además, " + omit + "." : ""));
            if (r.OmitidosTotal > 0)
                return (Indicador.Atencion, "Sin detecciones, pero " + omit + ".",
                    "Esos archivos no cuentan como limpios: vea la lista de abajo.");
            if (r.CompletamenteLimpio)
                return (Indicador.Correcto, "Sin detecciones, y se pudo analizar todo.",
                    Archivos(r.Analizados) + " en " + r.DuracionSegundos.ToString("0.#", CultureInfo.InvariantCulture) + " s.");
            return (Indicador.SinDatos, "El servicio no confirmó que esté limpio.", Archivos(r.Analizados) + " analizados.");
        }

        private static string Archivos(int n) => n == 1 ? "1 archivo" : n.ToString("#,0", CultureInfo.InvariantCulture).Replace(",", " ") + " archivos";

        private static string Detecciones(int n) => n == 1 ? "1 detección" : n + " detecciones";
    }
}
