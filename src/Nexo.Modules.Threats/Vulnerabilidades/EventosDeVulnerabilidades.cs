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
        {
            // Incompleta sin hallazgos: severidad Media (lo desconocido no es «bien»); completa y limpia: Info.
            Severidad sev = r.Hallazgos.Count > 0 ? r.Maxima : r.Completo ? Severidad.Info : Severidad.Media;
            string titulo = r.Hallazgos.Count > 0
                ? "Revision de cuentas y contrasenas: " + r.Hallazgos.Count + " hallazgo(s)"
                : r.Completo ? "Revision de cuentas y contrasenas: sin hallazgos" : "Revision de cuentas y contrasenas: incompleta";

            var sb = new StringBuilder();
            if (r.Hallazgos.Count > 0)
            {
                sb.AppendLine("| Gravedad | Hallazgo | Que hacer |");
                sb.AppendLine("|---|---|---|");
                foreach (HallazgoDeSistema h in r.Hallazgos)
                    sb.AppendLine("| " + h.Severidad + " | " + Celda(h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")")) + " | " + Celda(h.Recomendacion) + " |");
                sb.AppendLine();
            }
            if (!r.Completo)
            {
                sb.AppendLine("**No se pudo revisar todo** (esto NO significa que este bien):");
                foreach (string n in r.NoEvaluado) sb.AppendLine("- " + n);
            }
            else if (r.Hallazgos.Count == 0)
            {
                sb.AppendLine("No se encontro nada en las cuentas, la politica de contrasenas ni el inicio automatico.");
            }

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
