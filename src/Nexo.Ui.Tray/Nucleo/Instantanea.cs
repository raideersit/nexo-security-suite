using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ui.Tray.Nucleo
{
    /// <summary>Consulta al servicio por el pipe. Solo LECTURA (ping, tiempo-real.estado, tiempo-real.detecciones).</summary>
    public static class ConsultorDelServicio
    {
        public static async Task<InstantaneaDelServicio> ConsultarAsync(string pipe, TimeSpan espera, CancellationToken ct = default)
        {
            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);

                Respuesta ping = await c.LlamarAsync("ping", ct: ct).ConfigureAwait(false);
                if (!ping.Exito) return InstantaneaDelServicio.SinConexion("el servicio no contesta al ping");

                Respuesta estado = await c.LlamarAsync("tiempo-real.estado", ct: ct).ConfigureAwait(false);
                Respuesta detec = await c.LlamarAsync("tiempo-real.detecciones", ct: ct).ConfigureAwait(false);
                if (!estado.Exito || !detec.Exito) return InstantaneaDelServicio.SinConexion("el servicio no pudo dar su estado");

                JsonElement e = estado.Resultado!.Value;
                var lista = new List<DeteccionVista>();
                foreach (JsonElement d in detec.Resultado!.Value.GetProperty("detecciones").EnumerateArray())
                    lista.Add(new DeteccionVista(
                        d.GetProperty("ruta").GetString() ?? "", d.GetProperty("firma").GetString() ?? "",
                        d.GetProperty("bytes").GetInt64(), d.TryGetProperty("sha256", out JsonElement sh) ? sh.GetString() : null));

                return new InstantaneaDelServicio(
                    Conectado: true,
                    Version: ping.Resultado!.Value.TryGetProperty("version", out JsonElement v) ? v.GetString() : null,
                    TiempoRealActivo: e.GetProperty("activo").GetBoolean(),
                    CoberturaCompleta: e.GetProperty("cobertura_completa").GetBoolean(),
                    MotorCaido: e.TryGetProperty("motor_caido", out JsonElement mc) && mc.GetBoolean(),
                    Perdidos: e.TryGetProperty("perdidos", out JsonElement pe) ? pe.GetInt64() : 0,
                    NoAnalizados: e.TryGetProperty("no_analizados", out JsonElement na) ? na.GetInt64() : 0,
                    Detecciones: lista,
                    UltimoAviso: e.TryGetProperty("ultimo_aviso", out JsonElement ua) ? ua.GetString() : null,
                    Error: null,
                    PorRevisar: e.TryGetProperty("por_revisar", out JsonElement pr) && pr.ValueKind == JsonValueKind.Array
                        ? pr.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                        : null,
                    DesbordesDeFuente: e.TryGetProperty("desbordes_de_fuente", out JsonElement de) ? de.GetInt64() : 0);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException
                                       || ex is JsonException || ex is KeyNotFoundException || ex is InvalidOperationException)
            {
                // Sin servicio no se aparenta nada: la bandeja lo muestra como desconectado.
                return InstantaneaDelServicio.SinConexion(ex is TimeoutException ? "el servicio no esta en marcha" : ex.GetType().Name);
            }
        }
    }
}
