using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports.Model;
using Nexo.Reports.Seguridad;
using Nexo.Reports.Vault;

namespace Nexo.Reports
{
    /// <summary>
    /// Implementacion unica de <see cref="IReportWriter"/>.
    /// Registrarla como singleton: mantiene el semaforo que serializa la escritura
    /// de la nota diaria y el conjunto de ids ya escritos.
    /// </summary>
    public sealed class ReportWriter : IReportWriter, IDisposable
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        private readonly VaultOptions _opciones;
        private readonly VaultLayout _layout;
        private readonly Redactor _redactor;
        private readonly DailyNoteWriter _diaria;
        private readonly EntityNoteWriter _entidades;

        /// <summary>
        /// Un unico semaforo para toda la escritura. Podria ser mas fino (uno por
        /// archivo), pero el volumen esperado son decenas de eventos por hora, no
        /// miles por segundo: la simplicidad vale mas que la concurrencia aqui.
        /// </summary>
        private readonly SemaphoreSlim _candado = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Ids ya escritos en esta ejecucion, para que un reintento de un modulo
        /// tras un fallo parcial no genere una nota duplicada.
        /// Limitacion: es memoria del proceso. Si el servicio se reinicia entre el
        /// fallo y el reintento, si habra duplicado. Se acepta: el costo de un
        /// indice persistente no lo justifica para este volumen.
        /// </summary>
        private readonly Dictionary<Guid, NoteRef> _yaEscritos = new Dictionary<Guid, NoteRef>();

        public ReportWriter(VaultOptions opciones)
        {
            _opciones = opciones ?? throw new ArgumentNullException(nameof(opciones));

            if (string.IsNullOrWhiteSpace(_opciones.RutaVault))
            {
                _opciones.RutaVault = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Nexo", "Vault");
            }

            _layout = new VaultLayout(_opciones.RutaVault);
            _redactor = new Redactor(_opciones.Redaccion);
            _diaria = new DailyNoteWriter(_layout);
            _entidades = new EntityNoteWriter(_layout, _redactor, _opciones.MaxLargoNombreArchivo);
        }

        public VaultLayout Layout => _layout;

        public async Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
        {
            if (evento is null) throw new ArgumentNullException(nameof(evento));

            // El semaforo se toma de forma asincrona; la E/S de dentro es sincrona
            // a proposito: son unos pocos KB y meter Task.Run por nota solo anade
            // saltos de hilo sin ganar nada.
            // Validacion ANTES de tomar el candado y antes de tocar el disco.
            // Si un modulo intenta escribir un secreto, la escritura debe abortar
            // sin efectos: sin nota de entidad huerfana y, sobre todo, sin una
            // linea en la nota diaria enlazando a una nota que nunca existira.
            foreach (string clave in evento.Campos.Keys)
                _redactor.VerificarNombreDeCampo(clave);

            await _candado.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_yaEscritos.TryGetValue(evento.Id, out NoteRef? previa))
                    return new NoteRef(previa.Id, previa.RutaAbsoluta, previa.NombreNota, yaExistia: true);

                // 1. Notas de entidad primero: necesitamos sus nombres para los wikilinks.
                var wikilinks = new List<string>();
                foreach (EntidadRef entidad in evento.Entidades)
                    wikilinks.Add(_entidades.AsegurarNota(entidad, evento.Fecha));

                // 2. Nombre y ruta de la nota del evento.
                string carpeta = _layout.CarpetaDeEvento(evento.Modulo, evento.Fecha);
                Directory.CreateDirectory(carpeta);
                string nombreBase = NoteNaming.NombreBase(evento, _opciones.MaxLargoNombreArchivo);
                string nombreNota = NoteNaming.ResolverColision(carpeta, nombreBase);
                string ruta = Path.Combine(carpeta, nombreNota + ".md");

                // 3. Enlace a la nota diaria y actualizacion del resumen del dia.
                string nombreDiaria = _diaria.AgregarEvento(evento, nombreNota);

                // 4. La nota del evento.
                AtomicFile.EscribirTexto(ruta, Renderizar(evento, wikilinks, nombreDiaria));

                var refNota = new NoteRef(evento.Id, ruta, nombreNota, yaExistia: false);
                _yaEscritos[evento.Id] = refNota;
                return refNota;
            }
            finally
            {
                _candado.Release();
            }
        }

        private string Renderizar(NexoEvent ev, IReadOnlyList<string> wikilinks, string nombreDiaria)
        {
            var sb = new StringBuilder(1024);

            // ---------- Front matter ----------
            sb.Append("---\n");
            YamlWriter.EscribirCampo(sb, "id", ev.Id.ToString("D", Inv));
            YamlWriter.EscribirCampo(sb, "fecha", ev.Fecha);
            YamlWriter.EscribirCampo(sb, "zona", ev.Fecha.ToString("zzz", Inv));
            YamlWriter.EscribirCampo(sb, "modulo", ev.Modulo.ToString().ToLowerInvariant());
            YamlWriter.EscribirCampo(sb, "tipo", ev.Tipo);
            YamlWriter.EscribirCampo(sb, "severidad", ev.Severidad.ToString().ToLowerInvariant());
            YamlWriter.EscribirCampo(sb, "accion", ev.Accion.ToString().ToLowerInvariant());
            YamlWriter.EscribirCampo(sb, "equipo", _opciones.Equipo);

            // Campos propios del modulo. Cada nombre pasa por el cortafuegos de
            // secretos y cada valor por la politica de redaccion antes de tocar el
            // disco (ver riesgo L7). Se materializa una sola vez porque se usa dos
            // veces: en el front matter y en la tabla de datos del cuerpo.
            var campos = new List<KeyValuePair<string, object?>>(_redactor.Campos(ev.Campos));
            foreach (KeyValuePair<string, object?> campo in campos)
                YamlWriter.EscribirCampo(sb, campo.Key, campo.Value);

            YamlWriter.EscribirCampo(sb, "tags", ConstruirEtiquetas(ev));
            sb.Append("---\n\n");

            // ---------- Cuerpo ----------
            sb.Append("# ").Append(ev.Titulo).Append("\n\n");

            sb.Append("> [!").Append(CalloutDe(ev.Severidad)).Append("] ")
              .Append(NoteNaming.EtiquetaDeTipo(ev.Tipo))
              .Append(" · severidad ").Append(ev.Severidad.ToString().ToLowerInvariant()).Append('\n');
            sb.Append("> **Accion:** ").Append(DescribirAccion(ev.Accion)).Append("  \n");
            sb.Append("> **Cuando:** ").Append(ev.Fecha.ToString("dddd d 'de' MMMM 'de' yyyy, HH:mm:ss",
                          new CultureInfo("es-CL"))).Append("  \n");
            sb.Append("> **Equipo:** ").Append(_opciones.Equipo).Append('\n');
            sb.Append('\n');

            if (!string.IsNullOrWhiteSpace(ev.Cuerpo))
            {
                sb.Append("## Detalle\n\n").Append(ev.Cuerpo!.TrimEnd()).Append("\n\n");
            }

            if (campos.Count > 0)
            {
                sb.Append("## Datos\n\n| Campo | Valor |\n|---|---|\n");
                foreach (KeyValuePair<string, object?> campo in campos)
                {
                    sb.Append("| ").Append(EscaparTabla(campo.Key)).Append(" | ")
                      .Append(EscaparTabla(FormatearValor(campo.Value))).Append(" |\n");
                }
                sb.Append('\n');
            }

            if (wikilinks.Count > 0)
            {
                sb.Append("## Entidades relacionadas\n\n");
                foreach (string w in wikilinks) sb.Append("- [[").Append(w).Append("]]\n");
                sb.Append('\n');
            }

            sb.Append("## Contexto\n\n");
            sb.Append("- Dia: [[").Append(nombreDiaria).Append("]]\n");
            sb.Append("- Modulo: ").Append(VaultLayout.CarpetaDeModulo(ev.Modulo)).Append('\n');
            sb.Append("- Panel: [[Panel]]\n");

            return sb.ToString();
        }

        private static IEnumerable<string> ConstruirEtiquetas(NexoEvent ev)
        {
            // Las etiquetas de Obsidian no admiten espacios ni acentos fiables.
            // El formato jerarquico (nexo/amenazas/...) permite plegar el arbol de
            // etiquetas y filtrar por rama, sin instalar ningun plugin.
            yield return "nexo/evento";
            yield return "nexo/" + ev.Modulo.ToString().ToLowerInvariant();
            yield return "nexo/tipo/" + ev.Tipo;
            yield return "nexo/severidad/" + ev.Severidad.ToString().ToLowerInvariant();
            if (ev.Accion != Accion.Ninguna)
                yield return "nexo/accion/" + ev.Accion.ToString().ToLowerInvariant();
        }

        /// <summary>Tipos de callout nativos de Obsidian; no requieren plugin.</summary>
        private static string CalloutDe(Severidad s) => s switch
        {
            Severidad.Critica => "danger",
            Severidad.Alta => "warning",
            Severidad.Media => "attention",
            Severidad.Baja => "note",
            _ => "info"
        };

        private static string DescribirAccion(Accion a) => a switch
        {
            Accion.Ninguna => "ninguna (solo registro)",
            Accion.Registrada => "registrada",
            Accion.Bloqueada => "bloqueada",
            Accion.Cuarentena => "archivo movido a cuarentena",
            Accion.Eliminada => "eliminada",
            Accion.Restaurada => "restaurada",
            Accion.Omitida => "omitida por exclusion",
            Accion.PendienteConfirmacion => "**pendiente de confirmacion del usuario**",
            _ => a.ToString()
        };

        private static string FormatearValor(object? valor)
        {
            switch (valor)
            {
                case null:
                    return "";
                case bool b:
                    return b ? "si" : "no";
                case string s:
                    return s;
                case DateTimeOffset d:
                    return d.ToString("yyyy-MM-dd HH:mm:ss", Inv);
                case DateTime dt:
                    return dt.ToString("yyyy-MM-dd HH:mm:ss", Inv);
                case System.Collections.IEnumerable lista:
                    // Sin este caso una lista sale como "System.String[]" en la tabla.
                    var partes = new List<string>();
                    foreach (object? x in lista) partes.Add(FormatearValor(x));
                    return string.Join(", ", partes);
                case IFormattable f:
                    return f.ToString(null, Inv);
                default:
                    return valor.ToString() ?? "";
            }
        }

        /// <summary>Una barra vertical sin escapar parte la tabla markdown en dos.</summary>
        private static string EscaparTabla(string s)
            => s.Replace("|", "\\|").Replace("\r", "").Replace("\n", " ");

        public Task InicializarVaultAsync(CancellationToken ct = default)
        {
            VaultBootstrapper.Inicializar(_layout, _opciones, _redactor);
            return Task.CompletedTask;
        }

        public void Dispose() => _candado.Dispose();
    }
}
