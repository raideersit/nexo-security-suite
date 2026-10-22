using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ui.Tray.Nucleo
{
    public sealed record DeteccionVista(string Ruta, string Firma, long Bytes, string? Sha256)
    {
        /// <summary>Identifica una deteccion entre consultas: la misma ruta con otro contenido es otra deteccion.</summary>
        public string Clave => Ruta + "|" + Sha256;
    }

    /// <summary>Lo que se sabe del servicio en un momento dado. Si no se pudo hablar con el, <see cref="Conectado"/> es false.</summary>
    public sealed record InstantaneaDelServicio(
        bool Conectado,
        string? Version,
        bool TiempoRealActivo,
        bool CoberturaCompleta,
        bool MotorCaido,
        long Perdidos,
        long NoAnalizados,
        IReadOnlyList<DeteccionVista> Detecciones,
        string? UltimoAviso,
        string? Error)
    {
        public static InstantaneaDelServicio SinConexion(string motivo)
            => new InstantaneaDelServicio(false, null, false, false, false, 0, 0, Array.Empty<DeteccionVista>(), null, motivo);
    }

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
                    Error: null);
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
