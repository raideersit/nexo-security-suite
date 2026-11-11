using System;
using System.Collections.Generic;
using System.Text.Json;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Lo que la sección «Criptominería» saca de «mineria.estado». <c>Nota</c>: si está apagada (un hecho, no un hallazgo).</summary>
    public sealed record RevisionDeMineria(ResultadoDeAnalisis Analisis, int Muestras, string? Nota);

    /// <summary>
    /// Lee la respuesta de «mineria.estado» (§2aw) y la pasa a hallazgos de la pestaña Seguridad. Reglas:
    ///  - Una respuesta con otra forma, o una gravedad desconocida, invalida la respuesta ENTERA (nunca «sin sospechas» por no entenderla).
    ///  - Lo que el servicio no pudo leer, el fallo de la última muestra y el tiempo de observación que falta van a «no evaluado»:
    ///    la sección nunca sale en verde si Nexo no ha mirado lo suficiente.
    ///  - Los hallazgos son del propio núcleo (§2au): aquí no se inventa ni se cambia ninguno.
    /// </summary>
    public static class LectorDeMineriaDelServicio
    {
        public const string SinServicio = "la vigilancia de criptominería la hace el servicio de Nexo, y la ventana no tiene conexión con él";
        public const string Apagada = "La vigilancia de criptominería está apagada (es opcional). Se activa en el archivo appsettings.json del servicio: Nexo:Mineria:Activo.";

        public static Consulta<RevisionDeMineria> Leer(RespuestaCruda r)
        {
            if (!r.Exito)
                return Consulta<RevisionDeMineria>.Mal(r.Error is { Length: > 0 } err && err.Contains("desconocido", StringComparison.OrdinalIgnoreCase)
                    ? "el servicio instalado es de una versión sin vigilancia de criptominería"
                    : string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<RevisionDeMineria>.Mal("respuesta vacía del servicio");
            try
            {
                if (!e.GetProperty("activo").GetBoolean())
                    return Consulta<RevisionDeMineria>.Bien(new RevisionDeMineria(new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), 0, Apagada));

                var hs = new List<HallazgoDeSistema>();
                var no = new List<string>();
                foreach (JsonElement h in e.GetProperty("hallazgos").EnumerateArray())
                {
                    if (!Enum.TryParse(h.GetProperty("severidad").GetString(), ignoreCase: false, out Severidad sev) || !Enum.IsDefined(sev)) throw new FormatException();
                    string? sujeto = h.GetProperty("sujeto").ValueKind == JsonValueKind.String ? h.GetProperty("sujeto").GetString() : null;
                    hs.Add(new HallazgoDeSistema(
                        h.GetProperty("id").GetString() ?? throw new FormatException(), sev,
                        h.GetProperty("titulo").GetString() ?? throw new FormatException(),
                        h.GetProperty("detalle").GetString() ?? throw new FormatException(),
                        h.GetProperty("recomendacion").GetString() ?? throw new FormatException(), sujeto));
                }
                foreach (JsonElement x in e.GetProperty("no_evaluado").EnumerateArray()) no.Add(x.GetString() ?? throw new FormatException());

                int muestras = e.GetProperty("muestras").GetInt32();
                int necesarias = e.GetProperty("muestras_necesarias").GetInt32();
                if (muestras < 0 || necesarias <= 0) throw new FormatException();
                if (e.GetProperty("ultima_muestra").ValueKind == JsonValueKind.Null) no.Add("el servicio aún no ha tomado ninguna muestra");
                else if (e.GetProperty("observando").GetBoolean())
                    no.Add("Nexo aún está observando (" + muestras + " de " + necesarias + " muestras): una racha de CPU alta necesita ese tiempo para verse");
                if (e.TryGetProperty("aviso", out JsonElement av) && av.ValueKind == JsonValueKind.String) no.Add("aviso del servicio: " + av.GetString());

                return Consulta<RevisionDeMineria>.Bien(new RevisionDeMineria(new ResultadoDeAnalisis(hs, no), muestras, null));
            }
            catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return Consulta<RevisionDeMineria>.Mal("respuesta del servicio no reconocida");
            }
        }
    }
}
