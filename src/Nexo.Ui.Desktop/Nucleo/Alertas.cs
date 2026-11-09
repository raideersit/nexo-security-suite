using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// Lee la respuesta de «alertas.revisar». Una respuesta con otra forma, o una gravedad que no se reconoce, invalida la respuesta ENTERA:
    /// nunca se muestra una revision a medias como si fuera completa.
    /// </summary>
    public sealed record RevisionDeAlertas(ResultadoDeAnalisis Analisis, int Eventos);

    public static class LectorDeAlertasDelServicio
    {
        public const int Dias = 7;
        public const string SinServicio = "esta revisión la hace el servicio de Nexo (leer el registro de Seguridad exige administrador), y la ventana no tiene conexión con él";

        public static Consulta<RevisionDeAlertas> Leer(RespuestaCruda r)
        {
            if (!r.Exito) return Consulta<RevisionDeAlertas>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<RevisionDeAlertas>.Mal("respuesta vacía del servicio");
            try
            {
                var hs = new List<HallazgoDeSistema>();
                foreach (JsonElement h in e.GetProperty("hallazgos").EnumerateArray())
                {
                    if (!Enum.TryParse(h.GetProperty("severidad").GetString(), ignoreCase: false, out Severidad sev) || !Enum.IsDefined(sev)) throw new FormatException();
                    hs.Add(new HallazgoDeSistema(
                        h.GetProperty("id").GetString() ?? throw new FormatException(), sev,
                        h.GetProperty("titulo").GetString() ?? "", h.GetProperty("detalle").GetString() ?? "", h.GetProperty("recomendacion").GetString() ?? "",
                        h.TryGetProperty("sujeto", out JsonElement s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null));
                }
                List<string> no = e.GetProperty("no_evaluado").EnumerateArray().Select(x => x.GetString() ?? throw new FormatException()).ToList();
                int eventos = e.GetProperty("eventos").GetInt32();
                return Consulta<RevisionDeAlertas>.Bien(new RevisionDeAlertas(new ResultadoDeAnalisis(hs, no), eventos));
            }
            catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return Consulta<RevisionDeAlertas>.Mal("respuesta del servicio no reconocida");
            }
        }
    }
}
