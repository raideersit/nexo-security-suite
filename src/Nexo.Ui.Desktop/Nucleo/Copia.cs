using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    public sealed record OmitidoVista(string Ruta, string Motivo);

    public sealed record UltimaCopiaVista(bool Correcto, string? Error, int Archivos, int Nuevos, int Omitidos, IReadOnlyList<OmitidoVista> PrimerosOmitidos,
                                          bool Sospechosa, string? MotivoSospecha, int Podadas, bool PodaSuspendida, string? MotivoPoda);

    /// <summary>copia.estado. Apagada: <c>Activo == false</c> y solo hay <c>Nota</c>.</summary>
    public sealed record EstadoDeCopiaVista(bool Activo, string? Destino, bool DestinoDisponible, int VersionesAConservar, int VersionesEnDestino, int ListasIlegibles,
                                            double? AutomaticaCadaHoras, bool EnCurso, DateTimeOffset? UltimaCorrecta, UltimaCopiaVista? Ultimo,
                                            IReadOnlyList<string> Carpetas, IReadOnlyList<string> SinCopia, string? Aviso, string Nota, int? SospechosasGuardadas = null,
                                            string? AvisoDeProteccion = null);

    /// <summary>copia.hacer. <c>Exito == false</c> con <c>Error</c>: la copia no se hizo (disco ausente, fallo...).</summary>
    public sealed record ResultadoDeHacerCopia(bool Exito, string? Error, int Archivos, int Nuevos, int Omitidos, bool Sospechosa, string? MotivoSospecha,
                                               string? AvisoDeProteccion = null);

    /// <summary>copia.descartar. <c>Exito == false</c> con <c>Error</c>: no se dio por buena (no existe, ya no era sospechosa, disco ausente...).</summary>
    public sealed record ResultadoDeDescartar(bool Exito, string? Error);

    /// <summary>
    /// La copia versionada vista desde la ventana. Por el pipe se consulta el estado, se pide una copia y se da por buena una sospechosa (por su id: la
    /// carpeta de copias es de solo lectura para la persona, así que solo el servicio puede reescribir su lista). Restaurar y verificar los hace la
    /// ventana con los permisos de la persona, que solo necesitan leer (el servicio es SYSTEM y no debe escribir donde le diga un proceso cualquiera).
    /// </summary>
    public interface IServicioDeCopia
    {
        Task<Consulta<EstadoDeCopiaVista>> EstadoAsync(CancellationToken ct);
        Task<Consulta<ResultadoDeHacerCopia>> HacerAsync(CancellationToken ct);
        Task<Consulta<ResultadoDeDescartar>> DescartarAsync(string id, CancellationToken ct);
    }

    public sealed class ServicioDeCopiaNoDisponible : IServicioDeCopia
    {
        private readonly string _motivo;
        public ServicioDeCopiaNoDisponible(string motivo) => _motivo = motivo;
        public Task<Consulta<EstadoDeCopiaVista>> EstadoAsync(CancellationToken ct) => Task.FromResult(Consulta<EstadoDeCopiaVista>.Mal(_motivo));
        public Task<Consulta<ResultadoDeHacerCopia>> HacerAsync(CancellationToken ct) => Task.FromResult(Consulta<ResultadoDeHacerCopia>.Mal(_motivo));
        public Task<Consulta<ResultadoDeDescartar>> DescartarAsync(string id, CancellationToken ct) => Task.FromResult(Consulta<ResultadoDeDescartar>.Mal(_motivo));
    }

    public static class LectorDeCopia
    {
        public static Consulta<EstadoDeCopiaVista> Estado(RespuestaCruda r)
        {
            if (!r.Exito)
                return Consulta<EstadoDeCopiaVista>.Mal(r.Error is { Length: > 0 } err && err.Contains("desconocido", StringComparison.OrdinalIgnoreCase)
                    ? "este servicio es de una versión que no tiene copia de seguridad" : string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<EstadoDeCopiaVista>.Mal("respuesta vacía del servicio");
            try
            {
                string nota = Texto(e, "nota") ?? "";
                if (!e.GetProperty("activo").GetBoolean())
                    return Consulta<EstadoDeCopiaVista>.Bien(new EstadoDeCopiaVista(false, null, false, 0, 0, 0, null, false, null, null, Array.Empty<string>(), Array.Empty<string>(), null, nota));

                UltimaCopiaVista? ultimo = null;
                if (e.TryGetProperty("ultimo", out JsonElement u) && u.ValueKind == JsonValueKind.Object)
                    ultimo = new UltimaCopiaVista(u.GetProperty("correcto").GetBoolean(), Texto(u, "error"), u.GetProperty("archivos").GetInt32(), u.GetProperty("nuevos").GetInt32(),
                        u.GetProperty("omitidos").GetInt32(),
                        u.GetProperty("primeros_omitidos").EnumerateArray().Select(o => new OmitidoVista(o.GetProperty("ruta").GetString() ?? "", o.GetProperty("motivo").GetString() ?? "")).ToList(),
                        u.GetProperty("sospechosa").GetBoolean(), Texto(u, "motivo_sospecha"), u.GetProperty("podadas").GetInt32(), u.GetProperty("poda_suspendida").GetBoolean(), Texto(u, "motivo_poda"));

                return Consulta<EstadoDeCopiaVista>.Bien(new EstadoDeCopiaVista(true, e.GetProperty("destino").GetString() ?? throw new InvalidOperationException(),
                    e.GetProperty("destino_disponible").GetBoolean(), e.GetProperty("versiones_a_conservar").GetInt32(), e.GetProperty("versiones_en_destino").GetInt32(),
                    e.GetProperty("listas_ilegibles").GetInt32(),
                    e.TryGetProperty("automatica_cada_horas", out JsonElement a) && a.ValueKind == JsonValueKind.Number ? a.GetDouble() : null,
                    e.GetProperty("en_curso").GetBoolean(),
                    e.TryGetProperty("ultima_correcta", out JsonElement uc) && uc.ValueKind != JsonValueKind.Null ? uc.GetDateTimeOffset() : null,
                    ultimo,
                    e.GetProperty("carpetas").EnumerateArray().Select(x => x.GetString() ?? "").ToList(),
                    e.GetProperty("sin_copia").EnumerateArray().Select(x => (x.GetProperty("carpeta").GetString() ?? "") + ": " + (x.GetProperty("motivo").GetString() ?? "")).ToList(),
                    Texto(e, "aviso"), nota,
                    e.TryGetProperty("sospechosas_guardadas", out JsonElement sg) && sg.ValueKind == JsonValueKind.Number ? sg.GetInt32() : null,
                    Texto(e, "aviso_proteccion")));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<EstadoDeCopiaVista>.Mal("respuesta del servicio no reconocida");
            }
        }

        public static Consulta<ResultadoDeHacerCopia> Hacer(RespuestaCruda r)
        {
            if (!r.Exito) return Consulta<ResultadoDeHacerCopia>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<ResultadoDeHacerCopia>.Mal("respuesta vacía del servicio");
            try
            {
                bool exito = e.GetProperty("exito").GetBoolean();
                if (!exito) return Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(false, Texto(e, "error") ?? "no se pudo hacer la copia", 0, 0, 0, false, null));
                return Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(true, null, e.GetProperty("archivos").GetInt32(), e.GetProperty("nuevos").GetInt32(),
                    e.GetProperty("omitidos").GetInt32(), e.GetProperty("sospechosa").GetBoolean(), Texto(e, "motivo_sospecha"), Texto(e, "aviso_proteccion")));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<ResultadoDeHacerCopia>.Mal("respuesta del servicio no reconocida");
            }
        }

        public static Consulta<ResultadoDeDescartar> Descartar(RespuestaCruda r)
        {
            if (!r.Exito)
                return Consulta<ResultadoDeDescartar>.Mal(r.Error is { Length: > 0 } err && err.Contains("desconocido", StringComparison.OrdinalIgnoreCase)
                    ? "este servicio es de una versión que no sabe dar por buena una copia sospechosa: actualízalo" : string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<ResultadoDeDescartar>.Mal("respuesta vacía del servicio");
            try
            {
                bool exito = e.GetProperty("exito").GetBoolean();
                return Consulta<ResultadoDeDescartar>.Bien(new ResultadoDeDescartar(exito, exito ? null : Texto(e, "error") ?? "no se pudo dar por buena la copia"));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<ResultadoDeDescartar>.Mal("respuesta del servicio no reconocida");
            }
        }

        private static string? Texto(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

#if WINDOWS
    public sealed class ServicioDeCopiaPorPipe : IServicioDeCopia
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public ServicioDeCopiaPorPipe(string pipe, TimeSpan espera) { _pipe = pipe; _espera = espera; }

        public async Task<Consulta<EstadoDeCopiaVista>> EstadoAsync(CancellationToken ct)
            => LectorDeCopia.Estado(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "copia.estado", null, ct).ConfigureAwait(false));

        // «espera» es solo para conectar; la llamada puede tardar minutos (el servicio lee y hashea todo) y no tiene tope propio.
        public async Task<Consulta<ResultadoDeHacerCopia>> HacerAsync(CancellationToken ct)
            => LectorDeCopia.Hacer(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "copia.hacer", null, ct).ConfigureAwait(false));

        public async Task<Consulta<ResultadoDeDescartar>> DescartarAsync(string id, CancellationToken ct)
            => LectorDeCopia.Descartar(await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "copia.descartar", new { id }, ct).ConfigureAwait(false));
    }
#endif
}
