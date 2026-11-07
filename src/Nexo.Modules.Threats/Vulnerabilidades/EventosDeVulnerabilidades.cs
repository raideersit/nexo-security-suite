using System.Linq;
using System.Text;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    public static class EventosDeVulnerabilidades
    {
        /// <summary>
        /// Un evento por revision de cuentas, con una tabla de hallazgos. Nunca contiene contrasenas ni hashes (no se leen);
        /// lleva los nombres de cuenta local porque son lo accionable. Lo que no se pudo leer se dice en el cuerpo y baja la
        /// confianza: una revision incompleta nunca se presenta como «sin problemas».
        /// </summary>
        public static NexoEvent RevisionDeCuentas(ResultadoDeAnalisis r)
            => Construir("Revisión de cuentas y contraseñas", "No se encontró nada en las cuentas, la política de contraseñas ni el inicio automático.", r);

        /// <summary>
        /// Un evento por revision de Wi-Fi. Lleva los nombres de las redes guardadas (es lo accionable) y NUNCA claves. Sin
        /// adaptador Wi-Fi es un hecho (Info), no una revision incompleta.
        /// </summary>
        public static NexoEvent RevisionDeWifi(ResultadoDeAnalisis r, EstadoDeLecturaWifi estado)
        {
            if (estado == EstadoDeLecturaWifi.SinAdaptador)
            {
                return new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, "Revisión de Wi-Fi: este equipo no tiene adaptador Wi-Fi")
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = "No hay ningún adaptador Wi-Fi: no hay redes que revisar."
                };
            }
            return Construir("Revisión de Wi-Fi", "No se encontró nada en las redes Wi-Fi guardadas ni en la conexión actual.", r);
        }

        /// <summary>
        /// Un evento por revision de aplicaciones desactualizadas (winget, en espanol). Declara su alcance: winget solo conoce
        /// las aplicaciones que sabe identificar, asi que NO es una revision de todo el software instalado, y una version nueva
        /// no significa «vulnerable».
        /// </summary>
        public static NexoEvent RevisionDeAplicaciones(ResultadoDeAplicaciones r)
        {
            var sb = new StringBuilder();
            if (r.Aplicaciones.Count > 0)
            {
                sb.AppendLine("| Aplicación | Id | Instalada | Disponible |");
                sb.AppendLine("|---|---|---|---|");
                foreach (AplicacionDesactualizada a in r.Aplicaciones.Take(100))
                    sb.AppendLine("| " + Celda(a.Nombre) + " | " + Celda(a.Id) + " | " + Celda(a.VersionInstalada) + " | " + Celda(a.VersionDisponible) + " |");
                if (r.Aplicaciones.Count > 100) sb.AppendLine("| ... y " + (r.Aplicaciones.Count - 100) + " más | | | |");
                sb.AppendLine();
            }
            sb.AppendLine("*Alcance:* winget solo comprueba las aplicaciones que sabe identificar; no es una revisión de todo el software instalado. Una versión más nueva no significa que la instalada sea vulnerable.");
            return Construir("Revisión de aplicaciones desactualizadas", "winget no encontró aplicaciones con una versión más nueva.", r.Analisis, sb.ToString());
        }

        private static NexoEvent Construir(string area, string textoLimpio, ResultadoDeAnalisis r, string? extra = null)
        {
            // Incompleta sin hallazgos: severidad Media (lo desconocido no es «bien»); completa y limpia: Info.
            Severidad sev = r.Hallazgos.Count > 0 ? r.Maxima : r.Completo ? Severidad.Info : Severidad.Media;
            string titulo = r.Hallazgos.Count > 0
                ? area + ": " + r.Hallazgos.Count + " hallazgo(s)"
                : r.Completo ? area + ": sin hallazgos" : area + ": incompleta";

            var sb = new StringBuilder();
            if (r.Hallazgos.Count > 0)
            {
                sb.AppendLine("| Gravedad | Hallazgo | Qué hacer |");
                sb.AppendLine("|---|---|---|");
                foreach (HallazgoDeSistema h in r.Hallazgos)
                    sb.AppendLine("| " + h.Severidad + " | " + Celda(h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")")) + " | " + Celda(h.Recomendacion) + " |");
                sb.AppendLine();
            }
            if (!r.Completo)
            {
                sb.AppendLine("**No se pudo revisar todo** (esto NO significa que esté bien):");
                foreach (string n in r.NoEvaluado) sb.AppendLine("- " + n);
            }
            else if (r.Hallazgos.Count == 0)
            {
                sb.AppendLine(textoLimpio);
            }
            if (extra is not null) { sb.AppendLine(); sb.Append(extra); }

            var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, titulo)
            {
                Severidad = sev,
                Accion = Accion.Registrada,
                Cuerpo = sb.ToString()
            };
            e.Campos["hallazgos"] = r.Hallazgos.Count;
            e.Campos["completa"] = r.Completo;
            e.Campos["no_evaluado"] = r.NoEvaluado.Count;
            return e;
        }

        private static string Celda(string t) => t.Replace("|", "/").Replace("\r", " ").Replace("\n", " ");
    }
}
