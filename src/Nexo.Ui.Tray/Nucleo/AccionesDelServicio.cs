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
        Firewall,
        Vpn,
        /// <summary>Activar las carpetas protegidas contra ransomware de Defender.</summary>
        CarpetasProtegidas,
        /// <summary>Reponer los señuelos contra ransomware tocados (pone uno nuevo; el tocado no se borra).</summary>
        Senuelos
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
            TipoDeAccion.Vpn => "vpn.aplicar",
            TipoDeAccion.CarpetasProtegidas => "cfa.aplicar",
            TipoDeAccion.Senuelos => "senuelos.reponer",
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

        /// <summary>Plan para reponer los señuelos tocados (no cambia nada).</summary>
        public static async Task<PlanPropuesto> PrevisualizarSenuelosAsync(string pipe, TimeSpan espera, CancellationToken ct = default)
        {
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync("senuelos.previsualizar", ct: ct).ConfigureAwait(false);
            if (!r.Exito) return new PlanPropuesto("No se pudo preparar: " + r.Error!.Mensaje, false, null, Array.Empty<string>());
            JsonElement e = r.Resultado!.Value;
            return new PlanPropuesto(e.GetProperty("descripcion").GetString() ?? "", e.GetProperty("hay_cambios").GetBoolean(),
                e.TryGetProperty("token", out JsonElement t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null, Array.Empty<string>());
        }

        /// <summary>El texto del aviso de señuelos tocados, para la bandeja. Sin interfaz: se prueba en Nexo.Tray.Demo.</summary>
        public static (string Titulo, string Texto) AvisoDeSenuelos(IReadOnlyList<SenueloTocadoVista> nuevos, bool rafaga)
        {
            string titulo = rafaga ? "Nexo: ¡posible ransomware en marcha!" : "Nexo: señuelo contra ransomware tocado";
            SenueloTocadoVista p = nuevos[0];
            string donde = System.IO.Path.GetDirectoryName(p.Ruta) ?? p.Ruta;
            string que = p.Tipo switch { "modificado" => "se modificó", "renombrado" => "se renombró", "borrado" => "se borró", _ => "desapareció" };
            string texto = (nuevos.Count == 1 ? "Un archivo cebo de Nexo en " + donde + " " + que + "." : nuevos.Count + " archivos cebo de Nexo cambiaron (" + donde + "...).")
                         + (p.Severidad == "Media" && nuevos.Count == 1 ? " Se envió a la papelera: si fuiste tú, repónlo." : " Si no fuiste tú, desconecta el equipo de la red.")
                         + " Pulsa para ver.";
            return (titulo, texto);
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

            // En la VPN, las carpetas protegidas y los señuelos la llamada puede ir bien y el cambio no hacerse (o no entero): manda el «exito» del servicio.
            if (r.Exito) return new ResultadoDeAplicar(tipo is not (TipoDeAccion.Vpn or TipoDeAccion.CarpetasProtegidas or TipoDeAccion.Senuelos) || r.Resultado!.Value.GetProperty("exito").GetBoolean(), false, Resumir(tipo, r.Resultado!.Value));
            if (r.Error!.Codigo == AprobacionRequerida) return new ResultadoDeAplicar(false, true, r.Error.Mensaje);
            return new ResultadoDeAplicar(false, false, r.Error.Mensaje);
        }

        /// <summary>Lo que acepta escaneo.iniciar por peticion (ModuloEscaneo.MaxRutas).</summary>
        public const int MaxRutasPorEscaneo = RevisionDeLoNoVisto.MaxRutasPorEscaneo;

        /// <summary>Ver <see cref="RevisionDeLoNoVisto.RutasParaRevisar"/> (portable: la ventana tambien lo usa).</summary>
        public static IReadOnlyList<string> RutasParaRevisar(IEnumerable<string> carpetas) => RevisionDeLoNoVisto.RutasParaRevisar(carpetas);

        /// <summary>Lanza un escaneo bajo demanda (solo lee). Devuelve su id, o null y el motivo.</summary>
        public static async Task<(string? Id, string? Motivo)> IniciarRevisionAsync(
            string pipe, IReadOnlyList<string> rutas, TimeSpan espera, CancellationToken ct = default)
        {
            if (rutas.Count == 0) return (null, "no hay nada por revisar");
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync("escaneo.iniciar", new { rutas }, ct).ConfigureAwait(false);
            return r.Exito ? (r.Resultado!.Value.GetProperty("id").GetString(), null) : (null, r.Error!.Mensaje);
        }

        /// <summary>Resumen del escaneo si ya termino; null si sigue en marcha.</summary>
        public static async Task<string?> ResultadoDeRevisionAsync(string pipe, string id, TimeSpan espera, CancellationToken ct = default)
        {
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, espera, ct).ConfigureAwait(false);
            Respuesta r = await c.LlamarAsync("escaneo.resultado", new { id }, ct).ConfigureAwait(false);
            if (!r.Exito) return "No se pudo consultar la revision: " + r.Error!.Mensaje;
            JsonElement e = r.Resultado!.Value;
            if (!e.GetProperty("listo").GetBoolean())
                return e.GetProperty("estado").GetString() == "corriendo" ? null
                     : "La revision no termino (" + e.GetProperty("estado").GetString() + "): sigue habiendo carpetas por revisar.";
            return ResumirRevision(e.GetProperty("detecciones").GetArrayLength(), e.GetProperty("omitidos_total").GetInt32(),
                                   e.GetProperty("incompleto").GetBoolean());
        }

        /// <summary>Nunca dice «limpio» si algo no se analizo o el escaneo quedo a medias.</summary>
        public static string ResumirRevision(int detecciones, int omitidos, bool incompleto)
        {
            if (incompleto) return "La revision quedo INCOMPLETA: lo que faltaba sigue por revisar." + (detecciones > 0 ? " Ya hay " + detecciones + " detecciones." : "");
            if (detecciones > 0) return detecciones + (detecciones == 1 ? " deteccion" : " detecciones") + " en la revision. Estan en el vault; los archivos no se han tocado.";
            if (omitidos > 0) return "Sin detecciones, pero " + omitidos + " archivos no se pudieron analizar (ver el vault).";
            return "Revision terminada: sin detecciones y se pudo analizar todo.";
        }

        /// <summary>El codigo que usa el servicio cuando exige UAC (PoliticaDeAprobacion.AprobacionRequerida).</summary>
        public const int AprobacionRequerida = -32040;

        internal static string Resumir(TipoDeAccion tipo, JsonElement e)
        {
            switch (tipo)
            {
                case TipoDeAccion.Cuarentena: { int n = e.GetProperty("movidos").GetArrayLength(); return n + (n == 1 ? " archivo" : " archivos") + " en cuarentena. " + Omitidos(e); }
                case TipoDeAccion.Restauracion: return e.GetProperty("exito").GetBoolean() ? "Archivo restaurado." : "No se restauro: " + e.GetProperty("motivo").GetString();
                case TipoDeAccion.Purga: { int n = e.GetProperty("purgados").GetInt32(); return n + (n == 1 ? " entrada purgada. " : " entradas purgadas. ") + Omitidos(e); }
                case TipoDeAccion.Limpieza:
                {
                    int n = e.GetProperty("eliminados").GetInt32();
                    string peso = FormatearBytes(e.GetProperty("bytes_liberados").GetInt64());
                    // En modo simulado no se borro nada: decir «limpiados» seria mentir (el servicio dice el modo en la respuesta).
                    if (e.TryGetProperty("modo", out JsonElement modo) && modo.GetString() == "simulado")
                        return "SIMULACION: " + n + (n == 1 ? " archivo se habria limpiado" : " archivos se habrian limpiado") + " (" + peso + "). No se borro nada. " + Omitidos(e);
                    return n + (n == 1 ? " archivo limpiado" : " archivos limpiados") + " (" + peso + "). " + Omitidos(e);
                }
                case TipoDeAccion.Senuelos:
                {
                    int n = e.GetProperty("repuestos").GetInt32();
                    List<string> p = e.GetProperty("problemas").EnumerateArray().Select(x => x.GetString() ?? "").ToList();
                    string texto = n == 0 ? "No se repuso ningún señuelo." : n == 1 ? "1 señuelo repuesto." : n + " señuelos repuestos.";
                    if (p.Count > 0) texto += " " + (p.Count == 1 ? "Problema: " : "Problemas (" + p.Count + "), el primero: ") + (p[0].Length > 200 ? p[0][..200] + "..." : p[0]);
                    return texto;
                }
                case TipoDeAccion.CarpetasProtegidas: return (e.GetProperty("exito").GetBoolean() ? "" : "No se pudo: ") + e.GetProperty("mensaje").GetString();
                case TipoDeAccion.Vpn: return (e.GetProperty("exito").GetBoolean() ? "" : "No se pudo: ") + e.GetProperty("mensaje").GetString();
                case TipoDeAccion.Firewall: { int n = e.GetProperty("aplicados").GetInt32(); return n + (n == 1 ? " cambio aplicado. " : " cambios aplicados. ") + Omitidos(e); }
                default: return "";
            }
        }

        /// <summary>«2 omitidos», y el primer motivo si el servicio lo da (una cadena): sin motivo, quien lo lee no sabe que hacer.</summary>
        private static string Omitidos(JsonElement e)
        {
            if (!e.TryGetProperty("omitidos", out JsonElement o) || o.ValueKind != JsonValueKind.Array || o.GetArrayLength() == 0) return "";
            int n = o.GetArrayLength();
            string cuenta = n == 1 ? "1 omitido" : n + " omitidos";
            JsonElement primero = o[0];
            string? motivo = primero.ValueKind == JsonValueKind.String ? primero.GetString() : null;
            if (string.IsNullOrWhiteSpace(motivo)) return cuenta + ".";
            motivo = motivo.Trim();
            if (motivo.Length > 160) motivo = motivo[..160] + "...";
            return cuenta + ". " + (n == 1 ? "Motivo: " : "El primero: ") + motivo;
        }

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
