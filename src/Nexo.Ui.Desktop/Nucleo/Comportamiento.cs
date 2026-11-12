using System;
using System.Collections.Generic;
using System.Text.Json;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Lo que la sección «Comportamiento» saca de «comportamiento.estado». <c>Eventos</c>: cuántos eventos vio la sesión.</summary>
    public sealed record RevisionDeComportamiento(ResultadoDeAnalisis Analisis, int Eventos, string? Nota);

    /// <summary>
    /// Lee la respuesta de «comportamiento.estado» (§2bc) y la pasa a hallazgos de la pestaña Seguridad. Reglas:
    ///  - Otra forma de respuesta, o una gravedad desconocida, invalida la respuesta ENTERA (nunca «sin sospechas» por no entenderla).
    ///  - Sesión de eventos parada, eventos perdidos y firmas sin comprobar van a «no evaluado»: no sale verde si Nexo no vio.
    ///  - Los hallazgos son del puntuador del servicio: aquí no se inventa ni se cambia ninguno.
    /// </summary>
    public static class LectorDeComportamientoDelServicio
    {
        public const string SinServicio = "el análisis de comportamiento lo hace el servicio de Nexo, y la ventana no tiene conexión con él";
        public const string Apagada = "El análisis de comportamiento está apagado (es opcional). Se activa en el archivo appsettings.json del servicio: Nexo:Comportamiento:Activo, y el servicio debe correr como administrador.";

        public static Consulta<RevisionDeComportamiento> Leer(RespuestaCruda r)
        {
            if (!r.Exito)
                return Consulta<RevisionDeComportamiento>.Mal(r.Error is { Length: > 0 } err && err.Contains("desconocido", StringComparison.OrdinalIgnoreCase)
                    ? "el servicio instalado es de una versión sin análisis de comportamiento"
                    : string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<RevisionDeComportamiento>.Mal("respuesta vacía del servicio");
            try
            {
                if (!e.GetProperty("activo").GetBoolean())
                    return Consulta<RevisionDeComportamiento>.Bien(new RevisionDeComportamiento(new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), 0, Apagada));

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

                bool activa = e.GetProperty("sesion_activa").GetBoolean();
                long eventos = e.GetProperty("eventos_recibidos").GetInt64();
                if (eventos < 0 || e.GetProperty("eventos_perdidos").GetInt64() < 0) throw new FormatException();
                // Si el servicio dice que la sesión no corre pero no lo puso en «no evaluado», se añade: nunca verde sin vigilar.
                if (!activa && !no.Exists(x => x.Contains("sesión de eventos"))) no.Insert(0, "la sesión de eventos (ETW) no está en marcha");
                if (e.TryGetProperty("aviso", out JsonElement av) && av.ValueKind == JsonValueKind.String) no.Add("aviso del servicio: " + av.GetString());

                return Consulta<RevisionDeComportamiento>.Bien(new RevisionDeComportamiento(new ResultadoDeAnalisis(hs, no), (int)Math.Min(eventos, int.MaxValue), null));
            }
            catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return Consulta<RevisionDeComportamiento>.Mal("respuesta del servicio no reconocida");
            }
        }
    }
}
