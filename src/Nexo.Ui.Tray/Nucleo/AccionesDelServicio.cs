using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ui.Tray.Nucleo
{
    public enum TipoDeAccion
    {
        Cuarentena,
        Restauracion,
        Purga,
        Limpieza,
        Firewall
    }

    public sealed record PlanPropuesto(string Descripcion, bool HayCambios, string? Token, IReadOnlyList<string> Avisos);

    /// <summary>
    /// Resultado de pedir que se aplique un plan. <see cref="NecesitaElevacion"/> significa que el servicio exige una aprobacion
    /// con UAC: el plan sigue vigente y hay que volver a pedirlo desde un proceso elevado.
    /// </summary>
    public sealed record ResultadoDeAplicar(bool Exito, bool NecesitaElevacion, string Mensaje);

    /// <summary>Quien abre el proceso elevado que aplica un plan. Se abstrae para probar sin mostrar un aviso de UAC.</summary>
    public interface ILanzadorElevado
    {
        /// <returns>false si el usuario no acepto el UAC o no se pudo lanzar (el motivo, en <see cref="UltimoMotivo"/>).</returns>
        bool Lanzar(TipoDeAccion tipo, string token);

        /// <summary>Por que no se lanzo la ultima vez (null si se lanzo).</summary>
        string? UltimoMotivo { get; }
    }

    /// <summary>
    /// Las acciones que cambian algo, vistas desde la bandeja: previsualizar (siempre permitido) y aplicar. La bandeja NO decide
    /// que se aplica: el plan vive en el servicio y aqui solo viaja un token.
    /// </summary>
    public static class AccionesDelServicio
    {
        private static readonly Regex TokenValido = new Regex("^[0-9a-f]{64}$", RegexOptions.Compiled);

        public static bool EsTokenValido(string? token) => token is not null && TokenValido.IsMatch(token);

        public static string MetodoDeAplicar(TipoDeAccion t) => t switch
        {
            TipoDeAccion.Cuarentena => "cuarentena.aplicar",
            TipoDeAccion.Restauracion => "cuarentena.restaurar",
            TipoDeAccion.Purga => "cuarentena.purgar",
            TipoDeAccion.Limpieza => "limpieza.aplicar",
            TipoDeAccion.Firewall => "firewall.aplicar",
            _ => throw new ArgumentOutOfRangeException(nameof(t))
        };

        public static async Task<PlanPropuesto> PrevisualizarCuarentenaAsync(
            string pipe, string idDeEscaneo, TimeSpan espera, CancellationToken ct = default)
        {
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = idDeEscaneo }, ct).ConfigureAwait(false);
            if (!r.Exito) return new PlanPropuesto("No se pudo preparar: " + r.Error!.Mensaje, false, null, Array.Empty<string>());

            JsonElement e = r.Resultado!.Value;
            return new PlanPropuesto(
                e.GetProperty("descripcion").GetString() ?? "", e.GetProperty("hay_cambios").GetBoolean(),
                e.TryGetProperty("token", out JsonElement t) ? t.GetString() : null,
                e.TryGetProperty("avisos", out JsonElement a) ? a.EnumerateArray().Select(x => x.GetString() ?? "").ToList() : new List<string>());
        }

        public static async Task<PlanPropuesto> PrevisualizarLimpiezaAsync(string pipe, TimeSpan espera, CancellationToken ct = default)
        {
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync("limpieza.previsualizar", ct: ct).ConfigureAwait(false);
            if (!r.Exito) return new PlanPropuesto("No se pudo preparar: " + r.Error!.Mensaje, false, null, Array.Empty<string>());

            JsonElement e = r.Resultado!.Value;
            var sb = new StringBuilder();
            sb.Append("Se borrarian ").Append(e.GetProperty("total_archivos").GetInt32()).Append(" archivos (")
              .Append(FormatearBytes(e.GetProperty("total_bytes").GetInt64())).Append(").\n\n");
            foreach (JsonElement c2 in e.GetProperty("categorias").EnumerateArray())
                sb.Append("  ").Append(c2.GetProperty("categoria").GetString()).Append(": ").Append(c2.GetProperty("archivos").GetInt32())
                  .Append(" archivos, ").Append(FormatearBytes(c2.GetProperty("bytes").GetInt64())).Append('\n');

            bool reversible = e.GetProperty("reversible").GetBoolean();
            var avisos = new List<string> { reversible ? "Van a la Papelera: se pueden recuperar." : "Se borran de forma PERMANENTE." };
            foreach (JsonElement s in e.GetProperty("reglas_sin_permisos").EnumerateArray())
                avisos.Add("Sin permisos para evaluar: " + s.GetString());

            return new PlanPropuesto(sb.ToString(), e.GetProperty("total_archivos").GetInt32() > 0,
                                     e.TryGetProperty("token", out JsonElement t) ? t.GetString() : null, avisos);
        }

        /// <summary>Pide al servicio que aplique el plan de ese token. Un rechazo por falta de aprobacion se distingue de un fallo.</summary>
        public static async Task<ResultadoDeAplicar> AplicarAsync(
            string pipe, TipoDeAccion tipo, string token, TimeSpan espera, CancellationToken ct = default)
        {
            if (!EsTokenValido(token)) return new ResultadoDeAplicar(false, false, "token no valido");

            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync(MetodoDeAplicar(tipo), new { token }, ct).ConfigureAwait(false);

            if (r.Exito) return new ResultadoDeAplicar(true, false, Resumir(tipo, r.Resultado!.Value));
            if (r.Error!.Codigo == AprobacionRequerida) return new ResultadoDeAplicar(false, true, r.Error.Mensaje);
            return new ResultadoDeAplicar(false, false, r.Error.Mensaje);
        }

        /// <summary>El codigo que usa el servicio cuando exige UAC (PoliticaDeAprobacion.AprobacionRequerida).</summary>
        public const int AprobacionRequerida = -32040;

        private static string Resumir(TipoDeAccion tipo, JsonElement e)
        {
            switch (tipo)
            {
                case TipoDeAccion.Cuarentena: return e.GetProperty("movidos").GetArrayLength() + " archivos en cuarentena. " + Omitidos(e);
                case TipoDeAccion.Restauracion: return e.GetProperty("exito").GetBoolean() ? "Archivo restaurado." : "No se restauro: " + e.GetProperty("motivo").GetString();
                case TipoDeAccion.Purga: return e.GetProperty("purgados").GetInt32() + " entradas purgadas. " + Omitidos(e);
                case TipoDeAccion.Limpieza: return e.GetProperty("eliminados").GetInt32() + " archivos limpiados (" + FormatearBytes(e.GetProperty("bytes_liberados").GetInt64()) + "). " + Omitidos(e);
                case TipoDeAccion.Firewall: return e.GetProperty("aplicados").GetInt32() + " cambios aplicados. " + Omitidos(e);
                default: return "";
            }
        }

        private static string Omitidos(JsonElement e)
            => e.TryGetProperty("omitidos", out JsonElement o) && o.GetArrayLength() > 0 ? o.GetArrayLength() + " omitidos." : "";

        public static string FormatearBytes(long b)
            => b >= 1L << 30 ? (b / (double)(1L << 30)).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " GB"
             : b >= 1L << 20 ? (b / (double)(1L << 20)).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " MB"
             : b >= 1L << 10 ? (b / (double)(1L << 10)).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " KB"
             : b + " B";

        /// <summary>
        /// Aplica por el camino normal y, si el servicio exige UAC, abre el proceso elevado con el MISMO token (sigue vigente: el
        /// servicio comprueba la aprobacion antes de gastarlo). Devuelve lo ocurrido en cada caso.
        /// </summary>
        public static async Task<ResultadoDeAplicar> AplicarConAprobacionAsync(
            string pipe, TipoDeAccion tipo, string token, ILanzadorElevado lanzador, TimeSpan espera, CancellationToken ct = default)
        {
            ResultadoDeAplicar r = await AplicarAsync(pipe, tipo, token, espera, ct).ConfigureAwait(false);
            if (!r.NecesitaElevacion) return r;

            bool lanzado = lanzador.Lanzar(tipo, token);
            return lanzado
                ? new ResultadoDeAplicar(true, true, "Se abrio el aviso de aprobacion (UAC). El resultado lo muestra el proceso elevado.")
                : new ResultadoDeAplicar(false, true, "No se aprobo: " + (lanzador.UltimoMotivo ?? "el aviso de UAC se cancelo o no se pudo abrir") +
                                                      ". No se ha cambiado nada."); 
        }
    }
}
