using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    public enum EstadoDeWinget
    {
        Correcta,
        NoInstalado,
        TiempoAgotado,
        Error
    }

    /// <summary>Lo que devolvio <c>winget upgrade</c>. Solo se interpreta en espanol (decision del proyecto): cualquier otra cosa es «no evaluado».</summary>
    public sealed record SalidaDeWinget(EstadoDeWinget Estado, string Texto, int CodigoDeSalida);

    public sealed record AplicacionDesactualizada(string Nombre, string Id, string VersionInstalada, string VersionDisponible, string Origen);

    /// <summary>
    /// Resultado de leer la tabla de winget. <see cref="Reconocido"/> false = no se pudo interpretar (otro idioma, un error de
    /// winget, salida truncada...): NUNCA equivale a «sin actualizaciones». <see cref="Avisos"/> son cosas que no cuadraron
    /// aunque el resto se haya leido (filas ilegibles, recuento distinto...) y hacen que la revision no sea completa.
    /// </summary>
    public sealed record ResultadoDeParseo(bool Reconocido, bool SinActualizaciones, IReadOnlyList<AplicacionDesactualizada> Aplicaciones, IReadOnlyList<string> Avisos);

    /// <summary>
    /// Lee la salida en ESPANOL de <c>winget upgrade</c>. Exige el encabezado exacto «Nombre Id Version Disponible Origen»; las
    /// columnas se cortan por la posicion de cada titulo (los nombres llevan espacios). Una fila con el Id truncado («…») o con
    /// campos vacios no se adivina: se cuenta como ilegible. El recuento final («N actualizaciones disponibles.») debe coincidir
    /// con las filas leidas; si falta o no coincide, la revision no se da por completa.
    /// </summary>
    public static class ParserDeActualizacionesWinget
    {
        private static readonly Regex Encabezado = new Regex(@"^Nombre(\s+)Id(\s+)Versi\p{L}\p{M}*n(\s+)Disponible(\s+)Origen\s*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex Recuento = new Regex(@"^\s*(\d+)\s+actualizaci\S+\s+disponible", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private static readonly Regex SinNovedades = new Regex(@"^\s*No se encontr\S*\b.*actualizaci", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        public const int MaximoDeCaracteres = 2 * 1024 * 1024;

        public static ResultadoDeParseo Parsear(string? salida)
        {
            if (string.IsNullOrWhiteSpace(salida)) return NoReconocido("la salida de winget llego vacia");
            if (salida.Length > MaximoDeCaracteres) return NoReconocido("la salida de winget es demasiado grande");

            string[] lineas = salida.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            int h = Array.FindIndex(lineas, l => Encabezado.IsMatch(l.TrimEnd()));
            if (h < 0)
            {
                if (lineas.Any(l => SinNovedades.IsMatch(l)))
                    return new ResultadoDeParseo(true, true, Array.Empty<AplicacionDesactualizada>(), Array.Empty<string>());
                return NoReconocido("winget no devolvio la tabla en espanol (¿otro idioma, o un error de winget como no poder abrir el origen?)");
            }

            Match m = Encabezado.Match(lineas[h].TrimEnd());
            int iId = "Nombre".Length + m.Groups[1].Length;
            int iVer = iId + "Id".Length + m.Groups[2].Length;
            int iDisp = iVer + (lineas[h].IndexOf("Disponible", StringComparison.Ordinal) - iVer);
            int iOri = lineas[h].IndexOf("Origen", StringComparison.Ordinal);

            // Las cuatro posiciones deben ir estrictamente en orden y dentro del encabezado: si no, cortar las filas lanzaria.
            if (!(0 < iId && iId < iVer && iVer < iDisp && iDisp < iOri && iOri < lineas[h].Length))
                return NoReconocido("las columnas del encabezado de winget no tienen la forma esperada");

            if (h + 1 >= lineas.Length || !EsLineaDeGuiones(lineas[h + 1]))
                return NoReconocido("a la tabla de winget le falta la linea de guiones bajo el encabezado");

            var apps = new List<AplicacionDesactualizada>();
            var avisos = new List<string>();
            int ilegibles = 0, indice = h + 2;
            long? esperadas = null;

            for (; indice < lineas.Length; indice++)
            {
                string l = lineas[indice];
                if (string.IsNullOrWhiteSpace(l)) continue;
                Match r = Recuento.Match(l);
                if (r.Success) { esperadas = long.Parse(r.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture); indice++; break; }

                if (l.Length <= iOri) { ilegibles++; continue; }
                string nombre = l.Substring(0, iId).Trim(), id = l.Substring(iId, iVer - iId).Trim(),
                       ver = l.Substring(iVer, iDisp - iVer).Trim(), disp = l.Substring(iDisp, iOri - iDisp).Trim(), ori = l.Substring(iOri).Trim();
                if (nombre.Length == 0 || id.Length == 0 || ver.Length == 0 || disp.Length == 0 || ori.Length == 0
                    || id.Contains(' ') || id.Contains('…') || ver.Contains('…') || disp.Contains('…')) { ilegibles++; continue; }
                apps.Add(new AplicacionDesactualizada(nombre, id, ver, disp, ori));
            }

            if (ilegibles > 0) avisos.Add(ilegibles + " fila(s) de la tabla de winget no se pudieron interpretar (campos truncados o vacios).");
            if (esperadas is null)
                avisos.Add("La salida de winget no trae el recuento final («N actualizaciones disponibles»): no se puede comprobar que este completa.");
            else if (esperadas != apps.Count + ilegibles)
                avisos.Add("winget dice " + esperadas + " actualizacion(es) pero se leyeron " + (apps.Count + ilegibles) + ": la tabla no cuadra.");

            // Cualquier texto despues del recuento (una segunda tabla de paquetes que winget no pudo comparar, avisos...) no se interpreta.
            if (esperadas is not null && lineas.Skip(indice).Any(l => !string.IsNullOrWhiteSpace(l)))
                avisos.Add("winget agrego mas informacion despues del recuento (por ejemplo paquetes cuya version no pudo comparar) que Nexo no interpreta.");

            return new ResultadoDeParseo(true, false, apps, avisos);
        }

        private static ResultadoDeParseo NoReconocido(string motivo)
            => new(false, false, Array.Empty<AplicacionDesactualizada>(), new[] { motivo });

        private static bool EsLineaDeGuiones(string l) => l.Trim().Length >= 10 && l.Trim().All(c => c == '-');
    }

    public sealed record ResultadoDeAplicaciones(ResultadoDeAnalisis Analisis, IReadOnlyList<AplicacionDesactualizada> Aplicaciones);

    /// <summary>
    /// Reglas sobre las aplicaciones con actualizacion pendiente. Una version mas nueva NO significa «vulnerable»: sin cruzar
    /// con una base de CVE Nexo no puede decirlo, y el texto lo dice asi. Solo un programa de una lista corta y publica de los
    /// mas atacados (navegadores, Java, compresores, lectores de PDF, videollamadas) sube a Media. winget solo conoce las
    /// aplicaciones que sabe identificar: esta revision NO cubre todo el software instalado, y el evento lo declara.
    /// </summary>
    public static class AnalizadorDeAplicaciones
    {
        /// <summary>Ids de winget (prefijo, sin distinguir mayusculas) de programas muy atacados. Es una heuristica, no una lista de vulnerabilidades.</summary>
        public static readonly string[] IdsDeRiesgo =
        {
            "Oracle.JavaRuntimeEnvironment", "Oracle.JDK", "RARLab.WinRAR", "7zip.7zip", "Google.Chrome", "Mozilla.Firefox", "Microsoft.Edge",
            "Adobe.Acrobat", "Zoom.Zoom", "VideoLAN.VLC"
        };

        public static ResultadoDeAplicaciones Analizar(SalidaDeWinget s)
        {
            if (s is null) throw new ArgumentNullException(nameof(s));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();

            switch (s.Estado)
            {
                case EstadoDeWinget.NoInstalado:
                    noEvaluado.Add("winget no esta instalado o no se pudo ejecutar: no se pudo comprobar si hay aplicaciones desactualizadas.");
                    return Resultado(hallazgos, noEvaluado, Array.Empty<AplicacionDesactualizada>());
                case EstadoDeWinget.TiempoAgotado:
                    noEvaluado.Add("winget tardo demasiado y se detuvo: no se pudo comprobar si hay aplicaciones desactualizadas.");
                    return Resultado(hallazgos, noEvaluado, Array.Empty<AplicacionDesactualizada>());
                case EstadoDeWinget.Error:
                    noEvaluado.Add("winget fallo (codigo " + s.CodigoDeSalida + "): no se pudo comprobar si hay aplicaciones desactualizadas.");
                    return Resultado(hallazgos, noEvaluado, Array.Empty<AplicacionDesactualizada>());
            }

            ResultadoDeParseo p = ParserDeActualizacionesWinget.Parsear(s.Texto);
            noEvaluado.AddRange(p.Avisos);
            if (!p.Reconocido || p.SinActualizaciones) return Resultado(hallazgos, noEvaluado, p.Aplicaciones);

            var riesgo = p.Aplicaciones.Where(a => IdsDeRiesgo.Any(i => a.Id.StartsWith(i, StringComparison.OrdinalIgnoreCase))).ToList();
            foreach (AplicacionDesactualizada a in riesgo)
                hallazgos.Add(new HallazgoDeSistema("APP-RIESGO-DESACTUALIZADA", Severidad.Media, "Un programa muy atacado esta desactualizado",
                    a.Nombre + " esta en la version " + a.VersionInstalada + " y hay una mas nueva (" + a.VersionDisponible + "). Es de los programas que mas atacan; una version nueva suele incluir correcciones de seguridad. Nexo no sabe si la tuya tiene un fallo concreto.",
                    "Actualizalo: winget upgrade --id " + a.Id, a.Nombre));

            var resto = p.Aplicaciones.Except(riesgo).ToList();
            if (resto.Count > 0)
                hallazgos.Add(new HallazgoDeSistema("APPS-DESACTUALIZADAS", Severidad.Baja, resto.Count + " aplicacion(es) tienen una version mas nueva",
                    string.Join(", ", resto.Take(15).Select(a => a.Nombre)) + (resto.Count > 15 ? " y " + (resto.Count - 15) + " mas" : "") +
                    ". Una version mas nueva no significa que la tuya sea vulnerable; mantener el software al dia reduce el riesgo.",
                    "Actualizalas cuando puedas (winget upgrade --all, o desde cada programa)."));

            return Resultado(hallazgos, noEvaluado, p.Aplicaciones);
        }

        private static ResultadoDeAplicaciones Resultado(List<HallazgoDeSistema> h, List<string> n, IReadOnlyList<AplicacionDesactualizada> apps)
            => new(new ResultadoDeAnalisis(h.OrderByDescending(x => x.Severidad).ThenBy(x => x.Id, StringComparer.Ordinal).ThenBy(x => x.Sujeto, StringComparer.Ordinal).ToList(), n), apps);
    }
}
