using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    public sealed record DeteccionDeTiempoReal(string Ruta, string Firma, long Bytes, string? Sha256, DateTimeOffset? Modificado);

    /// <summary>
    /// tiempo-real.estado y tiempo-real.detecciones juntos. Con el tiempo real apagado el servicio solo manda «activo», «cobertura»
    /// y una nota: el resto queda vacio, y <see cref="Activo"/> = false lo explica.
    /// </summary>
    public sealed record DetalleDeTiempoReal(
        bool Activo,
        bool CoberturaCompleta,
        IReadOnlyList<string> Raices,
        IReadOnlyList<string> RaicesNoVigiladas,
        string? Motor,
        bool MotorCaido,
        long CambiosVistos,
        long Analizados,
        long NoAnalizados,
        long Perdidos,
        bool PerdidosEsMinimo,
        long DesbordesDeFuente,
        long Pendientes,
        IReadOnlyList<string> PorRevisar,
        string? UltimoAviso,
        string? Nota,
        IReadOnlyList<DeteccionDeTiempoReal> Detecciones);

    /// <summary>
    /// El tiempo real visto desde la ventana. SOLO LEE: el servicio no ofrece encenderlo, apagarlo ni cambiar sus carpetas por el
    /// pipe (un proceso malicioso lo usaria para quitar la proteccion), y la ventana tampoco. Poner en cuarentena lo detectado va
    /// por el escaneo (id «tiempo-real»), y revisar lo que no se vio es un escaneo bajo demanda normal.
    /// </summary>
    public interface IServicioDeTiempoReal
    {
        Task<Consulta<DetalleDeTiempoReal>> ConsultarAsync(CancellationToken ct);
    }

    public sealed class ServicioDeTiempoRealNoDisponible : IServicioDeTiempoReal
    {
        private readonly string _motivo;

        public ServicioDeTiempoRealNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<DetalleDeTiempoReal>> ConsultarAsync(CancellationToken ct) => Task.FromResult(Consulta<DetalleDeTiempoReal>.Mal(_motivo));
    }

    public static class LectorDeTiempoReal
    {
        /// <summary>El id «de escaneo» con el que la cuarentena ve las detecciones del tiempo real (ModuloTiempoReal.IdDeEscaneo).</summary>
        public const string IdDeEscaneo = "tiempo-real";

        /// <summary>
        /// Las dos respuestas. Si cualquiera falla o tiene otra forma, no se interpreta a medias: no se sabe. Con el tiempo real
        /// activo, los campos de cobertura son obligatorios (si faltan, no se puede decir que este bien).
        /// </summary>
        public static Consulta<DetalleDeTiempoReal> Leer(RespuestaCruda estado, RespuestaCruda detecciones)
        {
            if (Error(estado) is string e1) return Consulta<DetalleDeTiempoReal>.Mal(e1);
            if (Error(detecciones) is string e2) return Consulta<DetalleDeTiempoReal>.Mal(e2);
            JsonElement e = estado.Resultado!.Value;
            JsonElement d = detecciones.Resultado!.Value;
            try
            {
                bool activo = e.GetProperty("activo").GetBoolean();
                bool cobertura = e.GetProperty("cobertura_completa").GetBoolean();
                var lista = d.GetProperty("detecciones").EnumerateArray().Select(x => new DeteccionDeTiempoReal(
                    x.GetProperty("ruta").GetString() ?? throw new InvalidOperationException(),
                    x.GetProperty("firma").GetString() ?? "",
                    x.GetProperty("bytes").GetInt64(),
                    Texto(x, "sha256"),
                    x.TryGetProperty("modificado", out JsonElement m) && m.ValueKind == JsonValueKind.String ? m.GetDateTimeOffset() : null)).ToList();

                if (!activo)
                    return Consulta<DetalleDeTiempoReal>.Bien(new DetalleDeTiempoReal(
                        false, false, Array.Empty<string>(), Array.Empty<string>(), null, false, 0, 0, 0, 0, false, 0, 0,
                        Array.Empty<string>(), null, Texto(e, "nota"), lista));

                IReadOnlyList<string> noVigiladas = Rutas(e.GetProperty("raices_no_vigiladas"));
                IReadOnlyList<string> porRevisar = Rutas(e.GetProperty("por_revisar"));
                bool motorCaido = e.GetProperty("motor_caido").GetBoolean();
                return Consulta<DetalleDeTiempoReal>.Bien(new DetalleDeTiempoReal(
                    Activo: true,
                    // Solo completa si el servicio lo dice Y nada de lo que manda lo contradice.
                    CoberturaCompleta: cobertura && !motorCaido && noVigiladas.Count == 0 && porRevisar.Count == 0,
                    Raices: Rutas(e.GetProperty("raices")),
                    RaicesNoVigiladas: noVigiladas,
                    Motor: Texto(e, "motor"),
                    MotorCaido: motorCaido,
                    CambiosVistos: e.GetProperty("cambios_vistos").GetInt64(),
                    Analizados: e.GetProperty("analizados").GetInt64(),
                    NoAnalizados: e.GetProperty("no_analizados").GetInt64(),
                    Perdidos: e.GetProperty("perdidos").GetInt64(),
                    PerdidosEsMinimo: e.TryGetProperty("perdidos_es_minimo", out JsonElement pm) && pm.ValueKind == JsonValueKind.True,
                    DesbordesDeFuente: e.TryGetProperty("desbordes_de_fuente", out JsonElement de) ? de.GetInt64() : 0,
                    Pendientes: e.TryGetProperty("pendientes", out JsonElement pe) ? pe.GetInt64() : 0,
                    PorRevisar: porRevisar,
                    UltimoAviso: Texto(e, "ultimo_aviso"),
                    Nota: Texto(e, "nota"),
                    Detecciones: lista));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<DetalleDeTiempoReal>.Mal("respuesta del servicio no reconocida");
            }
        }

        private static string? Error(RespuestaCruda r)
        {
            if (!r.Exito) return string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error;
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return "respuesta vacía del servicio";
            return null;
        }

        private static IReadOnlyList<string> Rutas(JsonElement a)
            => a.EnumerateArray().Select(x => x.GetString() ?? throw new InvalidOperationException()).Where(x => x.Length > 0).ToList();

        private static string? Texto(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    /// <summary>
    /// La cabecera de la pestaña «Tiempo real». Mismo orden que la bandeja: una deteccion manda sobre todo; despues apagado, motor
    /// caido y cobertura incompleta. «Vigilando» solo con cobertura completa, y aun asi recuerda que avisa despues de escribir.
    /// </summary>
    public static class ResumirTiempoReal
    {
        public static (Indicador Indicador, string Titulo, string Detalle) Desde(Consulta<DetalleDeTiempoReal>? c)
        {
            if (c is null) return (Indicador.SinDatos, "Sin consultar todavía.", "");
            if (c.Valor is not DetalleDeTiempoReal t)
                return (Indicador.SinDatos, "No se pudo consultar el tiempo real.", "Motivo: " + c.Error + ". No se sabe si está vigilando.");

            int d = t.Detecciones.Count;
            if (d > 0)
                return (Indicador.Alerta, (d == 1 ? "1 detección" : d + " detecciones") + " del tiempo real.",
                    "Los archivos no se han tocado: revíselos y póngalos en cuarentena." + (t.Activo ? "" : " (El tiempo real está apagado ahora.)"));
            if (!t.Activo)
                return (Indicador.Atencion, "El análisis en tiempo real está apagado.",
                    "No se vigila ninguna carpeta. Lo activa un administrador en appsettings.json del servicio (Nexo:TiempoReal:Activo).");
            if (t.MotorCaido)
                return (Indicador.Atencion, "El motor de análisis no responde.",
                    "Lo que cambie mientras tanto queda sin analizar y por revisar. Nada se da por limpio.");
            if (!t.CoberturaCompleta)
            {
                var partes = new List<string>();
                if (t.RaicesNoVigiladas.Count > 0) partes.Add(Carpetas(t.RaicesNoVigiladas.Count) + " sin vigilar");
                if (t.PorRevisar.Count > 0) partes.Add(Carpetas(t.PorRevisar.Count) + " por revisar");
                return (Indicador.Atencion, "Cobertura incompleta" + (partes.Count > 0 ? ": " + string.Join(", ", partes) + "." : "."),
                    t.PorRevisar.Count > 0 ? "Hubo cambios que no se pudieron analizar. «Revisar lo que no se vio» los escanea."
                                           : "El servicio no confirma que lo haya visto todo.");
            }
            return (Indicador.Correcto, "Vigilando " + Carpetas(t.Raices.Count) + ", sin nada pendiente de revisar.",
                "Detecta y avisa después de que el archivo se escribe; Microsoft Defender sigue siendo su protección principal.");
        }

        /// <summary>Los contadores en una linea. Son historicos: lo ya revisado con un escaneo completo deja de contar para la cobertura.</summary>
        public static string Contadores(DetalleDeTiempoReal t)
        {
            if (!t.Activo) return "";
            string perdidos = Numero(t.Perdidos) + (t.PerdidosEsMinimo ? " (al menos)" : "");
            return "Cambios vistos: " + Numero(t.CambiosVistos) + " · Analizados: " + Numero(t.Analizados)
                   + " · Sin analizar: " + Numero(t.NoAnalizados) + " · Perdidos: " + perdidos
                   + " · En cola: " + Numero(t.Pendientes)
                   + (t.DesbordesDeFuente > 0 ? " · Desbordes: " + Numero(t.DesbordesDeFuente) : "");
        }

        private static string Carpetas(int n) => n == 1 ? "1 carpeta" : n + " carpetas";

        private static string Numero(long n) => n.ToString("#,0", CultureInfo.InvariantCulture).Replace(",", " ");
    }
}
