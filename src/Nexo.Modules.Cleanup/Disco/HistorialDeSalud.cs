using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>
    /// Guarda la ultima lectura S.M.A.R.T. de cada disco entre ejecuciones.
    ///
    /// Sin esto el evaluador nunca ve "creciendo": 197 en aumento se queda en
    /// alta en vez de critica, y 188 no alerta nunca. Solo se guardan los
    /// atributos, que es lo unico que compara el evaluador, y la serie ya
    /// redactada: el archivo no identifica el equipo.
    ///
    /// Una lectura sin atributos (sin permisos, NVMe, puente USB) NO reemplaza a
    /// una anterior que si los tenia: borraria el historial que se necesita para
    /// detectar el crecimiento la proxima vez que si se pueda leer.
    /// </summary>
    public sealed class HistorialDeSalud
    {
        private const int VersionActual = 1;

        private static readonly JsonSerializerOptions Opciones = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true
        };

        private static readonly UTF8Encoding Utf8SinBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        private readonly string _ruta;

        public HistorialDeSalud(string ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta)) throw new ArgumentException("Ruta vacia.", nameof(ruta));
            _ruta = ruta;
        }

        /// <summary>
        /// Por que el historial no se pudo usar en la ultima operacion, o null.
        /// Un historial ilegible significa "no se evaluo el crecimiento", y eso
        /// hay que decirlo: no es lo mismo que "no crecio".
        /// </summary>
        public string? Advertencia { get; private set; }

        private sealed class Documento
        {
            [JsonPropertyName("version")] public int Version { get; set; }
            [JsonPropertyName("discos")] public List<Registro> Discos { get; set; } = new List<Registro>();
        }

        private sealed class Registro
        {
            [JsonPropertyName("modelo")] public string Modelo { get; set; } = "";
            [JsonPropertyName("serie")] public string Serie { get; set; } = "";
            [JsonPropertyName("fecha")] public DateTimeOffset Fecha { get; set; }
            [JsonPropertyName("atributos")] public List<Atributo> Atributos { get; set; } = new List<Atributo>();
        }

        private sealed class Atributo
        {
            [JsonPropertyName("id")] public byte Id { get; set; }
            [JsonPropertyName("flags")] public ushort Flags { get; set; }
            [JsonPropertyName("valor")] public byte Valor { get; set; }
            [JsonPropertyName("peor")] public byte Peor { get; set; }
            [JsonPropertyName("crudo")] public ulong Crudo { get; set; }
        }

        /// <summary>
        /// Lecturas anteriores por <see cref="MonitorDeSalud.Clave"/>. Si el archivo
        /// no existe devuelve vacio (primera ejecucion). Si esta corrupto lo aparta
        /// como ".corrupto", devuelve vacio y deja una <see cref="Advertencia"/>.
        /// </summary>
        public IReadOnlyDictionary<string, LecturaDeDisco> Cargar()
        {
            var resultado = new Dictionary<string, LecturaDeDisco>(StringComparer.Ordinal);

            Documento? doc = LeerDocumento(out string? problema);
            Advertencia = problema;
            if (doc is null) return resultado;

            foreach (Registro r in doc.Discos)
            {
                if (string.IsNullOrWhiteSpace(r.Modelo)) continue;
                var lectura = new LecturaDeDisco(r.Modelo, r.Serie)
                {
                    Atributos = r.Atributos.Select(a => new AtributoSmart(a.Id, a.Flags, a.Valor, a.Peor, a.Crudo)).ToList()
                };
                resultado[MonitorDeSalud.Clave(lectura)] = lectura;
            }
            return resultado;
        }

        /// <summary>
        /// Guarda las lecturas con atributos. Conserva los discos que hoy no
        /// aparecen (un USB desconectado) y los que hoy no se pudieron leer.
        /// No lanza por errores de E/S: la evaluacion ya se hizo, y perder el
        /// historial solo se anota en <see cref="Advertencia"/>.
        /// </summary>
        public void Guardar(IEnumerable<LecturaDeDisco> lecturas, DateTimeOffset? ahora = null)
        {
            if (lecturas is null) throw new ArgumentNullException(nameof(lecturas));
            DateTimeOffset fecha = ahora ?? DateTimeOffset.Now;

            Documento doc = LeerDocumento(out string? problemaDeLectura) ?? new Documento();

            var porClave = new Dictionary<string, Registro>(StringComparer.Ordinal);
            foreach (Registro r in doc.Discos)
                porClave[r.Modelo.Trim() + "|" + r.Serie] = r;

            foreach (LecturaDeDisco l in lecturas)
            {
                if (l.Atributos.Count == 0) continue;
                porClave[MonitorDeSalud.Clave(l)] = new Registro
                {
                    Modelo = l.Modelo,
                    Serie = l.SerieRedactada,
                    Fecha = fecha,
                    Atributos = l.Atributos
                        .Select(a => new Atributo { Id = a.Id, Flags = a.Flags, Valor = a.Valor, Peor = a.Peor, Crudo = a.Crudo })
                        .ToList()
                };
            }

            var nuevo = new Documento
            {
                Version = VersionActual,
                Discos = porClave.Values.OrderBy(r => r.Modelo, StringComparer.Ordinal).ThenBy(r => r.Serie, StringComparer.Ordinal).ToList()
            };

            try
            {
                EscribirAtomico(JsonSerializer.Serialize(nuevo, Opciones));
                Advertencia = problemaDeLectura;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                Advertencia = "No se pudo guardar el historial de salud (" + ex.GetType().Name +
                              "): la proxima ejecucion no podra detectar crecimiento.";
            }
        }

        /// <summary>null si no hay archivo o si no se pudo leer (con el motivo en <paramref name="problema"/>).</summary>
        private Documento? LeerDocumento(out string? problema)
        {
            problema = null;
            if (!File.Exists(_ruta)) return null;

            try
            {
                Documento? doc = JsonSerializer.Deserialize<Documento>(File.ReadAllText(_ruta, Utf8SinBom), Opciones);
                if (doc is null || doc.Version != VersionActual)
                    throw new InvalidDataException("version " + (doc?.Version.ToString() ?? "desconocida"));
                return doc;
            }
            catch (Exception ex) when (ex is JsonException || ex is InvalidDataException)
            {
                // Se aparta en vez de borrarlo: si el problema es nuestro, es la evidencia.
                string apartado = _ruta + ".corrupto";
                try { File.Copy(_ruta, apartado, overwrite: true); File.Delete(_ruta); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }

                problema = "El historial de salud estaba danado y se aparto como '" +
                              Path.GetFileName(apartado) + "': esta vez no se evalua el crecimiento.";
                return null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                problema = "No se pudo leer el historial de salud (" + ex.GetType().Name +
                              "): esta vez no se evalua el crecimiento.";
                return null;
            }
        }

        // Misma tecnica que Nexo.Reports.Vault.AtomicFile (que es interno a Reports):
        // temporal en la misma carpeta y reemplazo, para no dejar un JSON a medias.
        private void EscribirAtomico(string contenido)
        {
            string carpeta = Path.GetDirectoryName(Path.GetFullPath(_ruta))
                             ?? throw new ArgumentException("Ruta sin carpeta.");
            Directory.CreateDirectory(carpeta);

            string temporal = Path.Combine(carpeta,
                "~" + Path.GetFileNameWithoutExtension(_ruta) + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
            try
            {
                using (var fs = new FileStream(temporal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var sw = new StreamWriter(fs, Utf8SinBom))
                {
                    sw.Write(contenido);
                    sw.Flush();
                    fs.Flush(flushToDisk: true);
                }

                if (File.Exists(_ruta)) File.Replace(temporal, _ruta, destinationBackupFileName: null);
                else File.Move(temporal, _ruta);
            }
            catch
            {
                try { if (File.Exists(temporal)) File.Delete(temporal); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
                throw;
            }
        }
    }
}
