using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Nexo.Reports.Model;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Mantiene la nota-resumen diaria: el "dashboard" del MVP.
    ///
    /// Diseno: los contadores viven en el front matter y son la fuente de verdad;
    /// la tabla de resumen del cuerpo se regenera a partir de ellos en cada
    /// escritura. Asi el resumen nunca se desincroniza aunque el servicio se
    /// reinicie, y ademas los contadores quedan disponibles para Dataview sin
    /// que nosotros construyamos un motor de agregacion.
    /// </summary>
    internal sealed class DailyNoteWriter
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        private static readonly ModuloOrigen[] Modulos =
        {
            ModuloOrigen.Amenazas,
            ModuloOrigen.Privacidad,
            ModuloOrigen.Identidad,
            ModuloOrigen.Limpieza,
            ModuloOrigen.Sistema
        };

        private readonly VaultLayout _layout;

        public DailyNoteWriter(VaultLayout layout) => _layout = layout;

        /// <summary>
        /// Anade el enlace al evento en la seccion de su modulo y actualiza los
        /// contadores. El llamador debe serializar las llamadas (ReportWriter lo
        /// hace con un semaforo): esto es leer-modificar-escribir sobre un archivo.
        /// </summary>
        public string AgregarEvento(NexoEvent ev, string nombreNotaEvento)
        {
            string ruta = _layout.RutaNotaDiaria(ev.Fecha);
            string nombreDiaria = VaultLayout.NombreNotaDiaria(ev.Fecha);

            string? actual = AtomicFile.LeerTextoSiExiste(ruta);
            var estado = actual is null
                ? EstadoDiario.Nuevo(ev.Fecha)
                : EstadoDiario.Parsear(actual, ev.Fecha);

            estado.Incrementar(ev.Modulo, ev.Severidad);
            estado.AgregarLinea(
                ev.Modulo,
                "- `" + ev.Fecha.ToString("HH:mm", Inv) + "` [[" + nombreNotaEvento + "]] — " +
                Minuscula(ev.Severidad.ToString()) + " · " + Minuscula(ev.Accion.ToString()));

            AtomicFile.EscribirTexto(ruta, estado.Render(nombreDiaria));
            return nombreDiaria;
        }

        private static string Minuscula(string s) => s.ToLowerInvariant();

        /// <summary>Modelo en memoria de la nota diaria: contadores + lineas por seccion.</summary>
        private sealed class EstadoDiario
        {
            private readonly Dictionary<ModuloOrigen, int> _contadores = new Dictionary<ModuloOrigen, int>();
            private readonly Dictionary<ModuloOrigen, List<string>> _lineas = new Dictionary<ModuloOrigen, List<string>>();
            private DateTimeOffset _fecha;
            private Severidad _maxSeveridad = Severidad.Info;

            private EstadoDiario()
            {
                foreach (var m in Modulos)
                {
                    _contadores[m] = 0;
                    _lineas[m] = new List<string>();
                }
            }

            public static EstadoDiario Nuevo(DateTimeOffset fecha) => new EstadoDiario { _fecha = fecha };

            /// <summary>
            /// Relee la nota existente para no perder los eventos ya registrados
            /// tras un reinicio del servicio. Solo se interpretan las lineas que
            /// empiezan con "- " dentro de cada seccion "## Modulo".
            ///
            /// Limitacion conocida y deliberada: la nota diaria se REGENERA en cada
            /// escritura, asi que el texto que el usuario escriba a mano en ella se
            /// pierde. Las anotaciones manuales van en las notas de entidad
            /// (03 Entidades), que la libreria nunca reescribe.
            /// </summary>
            public static EstadoDiario Parsear(string contenido, DateTimeOffset fecha)
            {
                var e = new EstadoDiario { _fecha = fecha };
                ModuloOrigen? seccion = null;

                foreach (string lineaCruda in contenido.Replace("\r\n", "\n").Split('\n'))
                {
                    string linea = lineaCruda;

                    if (linea.StartsWith("## ", StringComparison.Ordinal))
                    {
                        string titulo = linea.Substring(3).Trim();
                        seccion = BuscarModulo(titulo);
                        continue;
                    }

                    if (seccion.HasValue && linea.StartsWith("- ", StringComparison.Ordinal))
                    {
                        e._lineas[seccion.Value].Add(linea);
                        e._contadores[seccion.Value]++;
                        var sev = InferirSeveridad(linea);
                        if (sev > e._maxSeveridad) e._maxSeveridad = sev;
                    }
                }

                return e;
            }

            private static ModuloOrigen? BuscarModulo(string titulo)
            {
                foreach (var m in Modulos)
                    if (string.Equals(VaultLayout.CarpetaDeModulo(m), titulo, StringComparison.OrdinalIgnoreCase))
                        return m;
                return null;
            }

            private static Severidad InferirSeveridad(string linea)
            {
                if (linea.IndexOf("critica", StringComparison.OrdinalIgnoreCase) >= 0) return Severidad.Critica;
                if (linea.IndexOf("alta", StringComparison.OrdinalIgnoreCase) >= 0) return Severidad.Alta;
                if (linea.IndexOf("media", StringComparison.OrdinalIgnoreCase) >= 0) return Severidad.Media;
                if (linea.IndexOf("baja", StringComparison.OrdinalIgnoreCase) >= 0) return Severidad.Baja;
                return Severidad.Info;
            }

            public void Incrementar(ModuloOrigen modulo, Severidad severidad)
            {
                _contadores[modulo]++;
                if (severidad > _maxSeveridad) _maxSeveridad = severidad;
            }

            public void AgregarLinea(ModuloOrigen modulo, string linea) => _lineas[modulo].Add(linea);

            private int Total()
            {
                int t = 0;
                foreach (var kv in _contadores) t += kv.Value;
                return t;
            }

            public string Render(string nombreDiaria)
            {
                var sb = new StringBuilder();

                sb.Append("---\n");
                YamlWriter.EscribirCampo(sb, "tipo", TipoEvento.ResumenDiario);
                YamlWriter.EscribirCampo(sb, "fecha", _fecha.ToString("yyyy-MM-dd", Inv));
                YamlWriter.EscribirCampo(sb, "eventos_total", Total());
                foreach (var m in Modulos)
                    YamlWriter.EscribirCampo(sb, "eventos_" + m.ToString().ToLowerInvariant(), _contadores[m]);
                YamlWriter.EscribirCampo(sb, "severidad_maxima", _maxSeveridad.ToString().ToLowerInvariant());
                YamlWriter.EscribirCampo(sb, "tags", new[]
                {
                    "nexo/diario",
                    "nexo/severidad/" + _maxSeveridad.ToString().ToLowerInvariant()
                });
                sb.Append("---\n\n");

                sb.Append("# ").Append(nombreDiaria).Append("\n\n");

                // Navegacion entre dias. Los enlaces a dias sin eventos quedan sin
                // resolver, y eso es correcto: Obsidian los muestra en gris y crea
                // la nota si algun dia hay algo que registrar.
                sb.Append("`< ` [[").Append(VaultLayout.NombreNotaDiaria(_fecha.AddDays(-1))).Append("]]")
                  .Append("  ·  [[Panel]]  ·  ")
                  .Append("[[").Append(VaultLayout.NombreNotaDiaria(_fecha.AddDays(1))).Append("]] ` >`\n\n");

                sb.Append("## Resumen\n\n");
                sb.Append("| Modulo | Eventos |\n|---|---:|\n");
                foreach (var m in Modulos)
                    sb.Append("| ").Append(VaultLayout.CarpetaDeModulo(m)).Append(" | ")
                      .Append(_contadores[m].ToString(Inv)).Append(" |\n");
                sb.Append("| **Total** | **").Append(Total().ToString(Inv)).Append("** |\n\n");

                if (_maxSeveridad >= Severidad.Alta)
                {
                    sb.Append("> [!warning] Severidad maxima del dia: ")
                      .Append(_maxSeveridad.ToString().ToLowerInvariant()).Append("\n")
                      .Append("> Revisa los eventos marcados antes de cerrar el dia.\n\n");
                }

                foreach (var m in Modulos)
                {
                    sb.Append("## ").Append(VaultLayout.CarpetaDeModulo(m)).Append('\n');
                    if (_lineas[m].Count == 0)
                    {
                        sb.Append("\n*Sin eventos.*\n\n");
                        continue;
                    }
                    sb.Append('\n');
                    foreach (string l in _lineas[m]) sb.Append(l).Append('\n');
                    sb.Append('\n');
                }

                return sb.ToString();
            }
        }
    }
}
