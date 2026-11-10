using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Lo que la sección «Señuelos» saca de «senuelos.estado». <c>Nota</c>: si están apagados (un hecho, no un hallazgo).</summary>
    public sealed record RevisionDeSenuelos(ResultadoDeAnalisis Analisis, int Senuelos, int Tocados, string? Nota);

    /// <summary>
    /// Lee la respuesta de «senuelos.estado» (§2am) y la pasa a hallazgos de la pestaña Seguridad. Reglas:
    ///  - Una respuesta con otra forma, o una gravedad desconocida, invalida la respuesta ENTERA (nunca «ninguno tocado» por no entenderla).
    ///  - Lo que el servicio no pudo comprobar, o si aún no revisó nunca, va a «no evaluado»: la sección no sale en verde.
    ///  - Una carpeta sin señuelo (OneDrive, nombre ocupado...) es una nota informativa, con su motivo.
    /// </summary>
    public static class LectorDeSenuelosDelServicio
    {
        public const string SinServicio = "los señuelos los pone y vigila el servicio de Nexo, y la ventana no tiene conexión con él";
        public const string Apagados = "Los señuelos contra ransomware están apagados (son opcionales). Se activan en el archivo appsettings.json del servicio: Nexo:Senuelos:Activo.";

        public static Consulta<RevisionDeSenuelos> Leer(RespuestaCruda r)
        {
            if (!r.Exito)
                return Consulta<RevisionDeSenuelos>.Mal(r.Error is { Length: > 0 } err && err.Contains("desconocido", StringComparison.OrdinalIgnoreCase)
                    ? "el servicio instalado es de una versión sin señuelos"
                    : string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<RevisionDeSenuelos>.Mal("respuesta vacía del servicio");
            try
            {
                if (!e.GetProperty("activo").GetBoolean())
                    return Consulta<RevisionDeSenuelos>.Bien(new RevisionDeSenuelos(new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), 0, 0, Apagados));

                var hs = new List<HallazgoDeSistema>();
                var no = new List<string>();
                int total = 0, tocados = 0;
                foreach (JsonElement s in e.GetProperty("senuelos").EnumerateArray())
                {
                    total++;
                    string ruta = s.GetProperty("ruta").GetString() ?? throw new FormatException();
                    if (s.GetProperty("tocado").GetBoolean())
                    {
                        tocados++;
                        JsonElement h = s.GetProperty("hallazgo");
                        if (!Enum.TryParse(h.GetProperty("severidad").GetString(), ignoreCase: false, out Severidad sev) || !Enum.IsDefined(sev)) throw new FormatException();
                        string tipo = h.GetProperty("tipo").GetString() ?? throw new FormatException();
                        string cuando = h.GetProperty("cuando").GetDateTimeOffset().ToLocalTime().ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture);
                        bool aMano = sev == Severidad.Media;
                        hs.Add(new HallazgoDeSistema("SENUELO-" + tipo.ToUpperInvariant(), sev,
                            "Un señuelo contra ransomware " + Verbo(tipo),
                            (h.GetProperty("detalle").GetString() ?? "") + " Visto el " + cuando + ". Nexo no sabe qué programa fue ni puede detenerlo.",
                            aMano
                                ? "Se envió a la papelera, cosa que un programa de cifrado no suele hacer. Si fuiste tú, pulsa «Reponer señuelos...»."
                                : "Si no fuiste tú: desconecta el equipo de la red y de los discos externos y busca qué programa está en marcha (no apagues sin mirarlo). Después, «Reponer señuelos...».",
                            ruta));
                    }
                    if (s.TryGetProperty("no_comprobado", out JsonElement nc) && nc.ValueKind == JsonValueKind.String)
                        no.Add(ruta + ": no se pudo comprobar (" + nc.GetString() + ")");
                }
                if (e.GetProperty("rafaga").GetBoolean())
                    hs.Insert(0, new HallazgoDeSistema("SENUELOS-RAFAGA", Severidad.Critica, "Varios señuelos tocados en pocos minutos: puede haber un ransomware en marcha",
                        "Dos o más archivos cebo de Nexo cambiaron en los últimos 10 minutos. Es lo que hace un programa que cifra carpeta por carpeta.",
                        "Desconecta ya el equipo de la red (cable y Wi-Fi) y los discos externos. No abras más archivos. Busca el programa sospechoso antes de apagar."));

                foreach (JsonElement x in e.GetProperty("sin_senuelo").EnumerateArray())
                    hs.Add(new HallazgoDeSistema("SENUELO-SIN-PONER", Severidad.Info, "Carpeta sin señuelo",
                        x.GetProperty("motivo").GetString() ?? throw new FormatException(), "Nada que hacer si es intencionado (por ejemplo, OneDrive).",
                        x.GetProperty("carpeta").GetString() ?? throw new FormatException()));

                if (e.GetProperty("ultima_revision").ValueKind == JsonValueKind.Null) no.Add("el servicio aún no ha revisado los señuelos ni una vez");
                if (e.TryGetProperty("aviso", out JsonElement av) && av.ValueKind == JsonValueKind.String) no.Add("aviso del servicio: " + av.GetString());
                if (total == 0) no.Add("no hay ningún señuelo puesto (mira las carpetas sin señuelo)");

                return Consulta<RevisionDeSenuelos>.Bien(new RevisionDeSenuelos(new ResultadoDeAnalisis(hs, no), total, tocados, null));
            }
            catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
            {
                return Consulta<RevisionDeSenuelos>.Mal("respuesta del servicio no reconocida");
            }
        }

        private static string Verbo(string tipo) => tipo switch
        {
            "modificado" => "cambió de contenido",
            "renombrado" => "se renombró",
            "borrado" => "se borró",
            _ => "desapareció"
        };
    }
}
