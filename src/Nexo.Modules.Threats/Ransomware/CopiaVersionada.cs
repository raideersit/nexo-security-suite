using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Nexo.Modules.Threats.Ransomware
{
    // =====================================================================================================
    //  COPIA VERSIONADA (Salida 0, fila 2: «respaldo versionado»). Núcleo portable: solo System.IO.
    //
    //  Qué hace: cada vez que se ejecuta guarda una «instantánea» de las carpetas elegidas en una carpeta de
    //  destino. El contenido se guarda por su SHA-256 (un archivo que no cambió no se copia otra vez) y cada
    //  instantánea es una lista (ruta -> hash). Así se conservan varias versiones sin multiplicar el espacio.
    //
    //  Reglas, y por qué:
    //   - Nunca toca los originales (solo los lee) y nunca sobrescribe al restaurar: restaura a una carpeta NUEVA.
    //   - El destino no puede estar dentro de un origen ni al revés (se copiaría a sí mismo sin fin).
    //   - Lo que no se pudo copiar (abierto, sin permiso, demasiado grande, enlace) queda en «Omitidos» con motivo:
    //     una copia que calla lo que no copió es peor que ninguna.
    //   - Cada archivo se verifica al copiarlo (el hash sale de lo que se escribió, no de lo que se leyó antes).
    //   - Si de golpe cambian muchísimos archivos (lo que haría un ransomware) la instantánea se marca
    //     «sospechosa» y NO se podan las versiones viejas: justo entonces son las únicas buenas.
    //   - Podar solo borra dentro de la carpeta de copias de Nexo, y no poda si no pudo leer algún manifiesto
    //     (no puede saber qué contenido sigue en uso).
    //
    //  Lo que NO hace: no cifra la copia (quien lea el destino lee tus archivos: usa un disco que guardes) y no
    //  protege el destino de un ransomware que pueda escribir en él: lo ideal es un disco externo que solo se
    //  conecta para copiar. Se dice en la ventana.
    // =====================================================================================================

    public sealed record ConfiguracionDeCopia(IReadOnlyList<string> Origenes, string Destino, int VersionesAConservar = 7, long TopePorArchivoBytes = 4L * 1024 * 1024 * 1024);

    public sealed record EntradaDeCopia(string Origen, string Relativa, string Sha256, long Bytes, DateTimeOffset Modificado);

    public sealed record OmitidoEnCopia(string Ruta, string Motivo);

    public sealed record Instantanea(string Id, DateTimeOffset Creada, IReadOnlyList<EntradaDeCopia> Entradas, IReadOnlyList<OmitidoEnCopia> Omitidos, bool Sospechosa, string? MotivoSospecha);

    public sealed record ResultadoDeCopia(bool Correcto, string? Error, Instantanea? Instantanea, int ArchivosNuevos, int ArchivosReutilizados,
                                          int Podadas, bool PodaSuspendida, string? MotivoDePoda);

    public sealed record ResultadoDeRestauracion(bool Correcto, string? Error, int Restaurados, IReadOnlyList<OmitidoEnCopia> NoRestaurados);

    public sealed record ResultadoDeVerificacion(bool Correcto, int Comprobados, IReadOnlyList<OmitidoEnCopia> Problemas);

    public static class CopiaVersionada
    {
        public const string CarpetaDeCopias = "NexoCopias";
        private const int MinimoParaSospechar = 20;
        private const double FraccionSospechosa = 0.5;

        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

        private static string Blobs(string destino) => Path.Combine(destino, CarpetaDeCopias, "contenido");
        private static string Manifiestos(string destino) => Path.Combine(destino, CarpetaDeCopias, "instantaneas");

        private static string RutaDeBlob(string destino, string sha) => Path.Combine(Blobs(destino), sha.Substring(0, 2), sha);

        private static string Normalizar(string ruta)
        {
            string completa = Path.GetFullPath(ruta);
            return completa.EndsWith(Path.DirectorySeparatorChar) ? completa : completa + Path.DirectorySeparatorChar;
        }

        private static bool Dentro(string hija, string madre) => Normalizar(hija).StartsWith(Normalizar(madre), StringComparison.OrdinalIgnoreCase);

        /// <summary>Texto de por qué la configuración no sirve, o null si está bien.</summary>
        public static string? Validar(ConfiguracionDeCopia c)
        {
            if (c.Origenes is null || c.Origenes.Count == 0) return "No hay ninguna carpeta que copiar.";
            if (string.IsNullOrWhiteSpace(c.Destino)) return "No se indicó dónde guardar la copia.";
            if (c.VersionesAConservar < 1) return "Hay que conservar al menos una versión.";
            string destino;
            try { destino = Path.GetFullPath(c.Destino); } catch (Exception e) { return "El destino no es una ruta válida: " + e.Message; }
            foreach (string o in c.Origenes)
            {
                if (string.IsNullOrWhiteSpace(o)) return "Hay una carpeta de origen vacía.";
                if (!Directory.Exists(o)) return "La carpeta «" + o + "» no existe.";
                if (Dentro(destino, o)) return "El destino está dentro de «" + o + "»: la copia se copiaría a sí misma.";
                if (Dentro(o, destino)) return "«" + o + "» está dentro del destino: elige otro destino.";
            }
            return null;
        }

        /// <summary>Hace una instantánea nueva. Nunca modifica los originales.</summary>
        public static ResultadoDeCopia Copiar(ConfiguracionDeCopia c, DateTimeOffset ahora, CancellationToken ct = default)
        {
            string? mal = Validar(c);
            if (mal is not null) return new ResultadoDeCopia(false, mal, null, 0, 0, 0, false, null);

            string destino = Path.GetFullPath(c.Destino);
            try
            {
                Directory.CreateDirectory(Blobs(destino));
                Directory.CreateDirectory(Manifiestos(destino));
            }
            catch (Exception e) { return new ResultadoDeCopia(false, "No se pudo preparar el destino: " + e.Message, null, 0, 0, 0, false, null); }

            var entradas = new List<EntradaDeCopia>();
            var omitidos = new List<OmitidoEnCopia>();
            int nuevos = 0, reutilizados = 0;

            foreach (string origen in c.Origenes.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                foreach (string archivo in Recorrer(origen, omitidos, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    FileInfo fi;
                    try { fi = new FileInfo(archivo); }
                    catch (Exception e) { omitidos.Add(new OmitidoEnCopia(archivo, "No se pudo leer: " + e.Message)); continue; }
                    if (fi.Length > c.TopePorArchivoBytes) { omitidos.Add(new OmitidoEnCopia(archivo, "Demasiado grande (" + fi.Length + " bytes)")); continue; }

                    (string? sha, bool nuevo, string? motivo) = Guardar(destino, archivo, ct);
                    if (sha is null) { omitidos.Add(new OmitidoEnCopia(archivo, motivo ?? "No se pudo copiar")); continue; }
                    if (nuevo) nuevos++; else reutilizados++;
                    entradas.Add(new EntradaDeCopia(origen, Path.GetRelativePath(origen, archivo), sha, fi.Length, fi.LastWriteTimeUtc));
                }
            }

            Instantanea? anterior = Listar(destino, out _).LastOrDefault();
            (bool sospechosa, string? motivoSospecha) = Sospechar(anterior, entradas);
            string id = ahora.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'");
            // Si ya hay una del mismo segundo no se pisa: se le añade un sufijo.
            string baseId = id; int n = 1;
            while (File.Exists(Path.Combine(Manifiestos(destino), id + ".json"))) id = baseId + "-" + (++n);
            var inst = new Instantanea(id, ahora, entradas, omitidos, sospechosa, motivoSospecha);
            try
            {
                string tmp = Path.Combine(Manifiestos(destino), id + ".json.tmp");
                File.WriteAllText(tmp, JsonSerializer.Serialize(inst, Json), new UTF8Encoding(false));
                File.Move(tmp, Path.Combine(Manifiestos(destino), id + ".json"));
            }
            catch (Exception e) { return new ResultadoDeCopia(false, "No se pudo guardar la lista de la copia: " + e.Message, null, nuevos, reutilizados, 0, false, null); }

            int podadas = 0; bool suspendida = false; string? motivoPoda = null;
            if (sospechosa) { suspendida = true; motivoPoda = "No se borró ninguna versión vieja: " + motivoSospecha; }
            else
            {
                (podadas, motivoPoda) = Podar(destino, c.VersionesAConservar);
                if (motivoPoda is not null) suspendida = true;
            }
            return new ResultadoDeCopia(true, null, inst, nuevos, reutilizados, podadas, suspendida, motivoPoda);
        }

        private static (bool, string?) Sospechar(Instantanea? anterior, List<EntradaDeCopia> nuevas)
        {
            if (anterior is null || anterior.Entradas.Count < MinimoParaSospechar) return (false, null);
            var antes = anterior.Entradas.ToDictionary(e => e.Origen + "|" + e.Relativa, e => e.Sha256, StringComparer.OrdinalIgnoreCase);
            int cambiados = 0, desaparecidos = 0;
            var ahora = nuevas.ToDictionary(e => e.Origen + "|" + e.Relativa, e => e.Sha256, StringComparer.OrdinalIgnoreCase);
            foreach (var (clave, sha) in antes)
            {
                if (!ahora.TryGetValue(clave, out string? s)) desaparecidos++;
                else if (!string.Equals(s, sha, StringComparison.OrdinalIgnoreCase)) cambiados++;
            }
            int tocados = cambiados + desaparecidos;
            if (tocados >= antes.Count * FraccionSospechosa)
                return (true, tocados + " de " + antes.Count + " archivos cambiaron o desaparecieron desde la copia anterior (" + cambiados + " cambiados, " + desaparecidos
                              + " ya no están). Puede ser normal (una limpieza grande) o un cifrado: revisa antes de seguir.");
            return (false, null);
        }

        private static IEnumerable<string> Recorrer(string carpeta, List<OmitidoEnCopia> omitidos, CancellationToken ct)
        {
            var pendientes = new Stack<string>();
            pendientes.Push(carpeta);
            while (pendientes.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string actual = pendientes.Pop();
                string[] archivos, subcarpetas;
                try
                {
                    archivos = Directory.GetFiles(actual);
                    subcarpetas = Directory.GetDirectories(actual);
                }
                catch (Exception e) { omitidos.Add(new OmitidoEnCopia(actual, "No se pudo abrir la carpeta: " + e.Message)); continue; }
                foreach (string a in archivos)
                {
                    if (EsEnlace(a)) { omitidos.Add(new OmitidoEnCopia(a, "Es un enlace, no se sigue")); continue; }
                    yield return a;
                }
                foreach (string d in subcarpetas)
                {
                    if (EsEnlace(d)) { omitidos.Add(new OmitidoEnCopia(d, "Es un enlace a otra carpeta, no se sigue")); continue; }
                    pendientes.Push(d);
                }
            }
        }

        private static bool EsEnlace(string ruta)
        {
            try { return (File.GetAttributes(ruta) & FileAttributes.ReparsePoint) != 0; }
            catch { return true; } // si no se puede ni mirar, mejor no seguirlo
        }

        /// <summary>Copia el archivo al almacén por su hash. Devuelve (hash, era nuevo, motivo si falló).</summary>
        private static (string?, bool, string?) Guardar(string destino, string archivo, CancellationToken ct)
        {
            string tmp = Path.Combine(Blobs(destino), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                string sha;
                using (var origen = new FileStream(archivo, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var salida = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var h = SHA256.Create())
                {
                    var buffer = new byte[81920];
                    int leidos;
                    while ((leidos = origen.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        ct.ThrowIfCancellationRequested();
                        h.TransformBlock(buffer, 0, leidos, null, 0);
                        salida.Write(buffer, 0, leidos);
                    }
                    h.TransformFinalBlock(buffer, 0, 0);
                    sha = Convert.ToHexString(h.Hash!).ToLowerInvariant();
                }
                string final = RutaDeBlob(destino, sha);
                if (File.Exists(final)) { File.Delete(tmp); return (sha, false, null); }
                Directory.CreateDirectory(Path.GetDirectoryName(final)!);
                File.Move(tmp, final);
                return (sha, true, null);
            }
            catch (OperationCanceledException) { TryBorrar(tmp); throw; }
            catch (Exception e) { TryBorrar(tmp); return (null, false, e is IOException ? "Está en uso o no se puede leer: " + e.Message : e.Message); }
        }

        private static void TryBorrar(string ruta) { try { File.Delete(ruta); } catch { /* ya no importa */ } }

        /// <summary>Las instantáneas que se pueden leer, de la más vieja a la más nueva. <paramref name="ilegibles"/> = cuántos manifiestos no se pudieron leer.</summary>
        public static List<Instantanea> Listar(string destino, out int ilegibles)
        {
            ilegibles = 0;
            var lista = new List<Instantanea>();
            string carpeta = Manifiestos(Path.GetFullPath(destino));
            if (!Directory.Exists(carpeta)) return lista;
            foreach (string f in Directory.GetFiles(carpeta, "*.json").OrderBy(x => x, StringComparer.Ordinal))
            {
                try
                {
                    Instantanea? i = JsonSerializer.Deserialize<Instantanea>(File.ReadAllText(f, Encoding.UTF8), Json);
                    if (i is null || i.Entradas is null || string.IsNullOrEmpty(i.Id) || !string.Equals(i.Id, Path.GetFileNameWithoutExtension(f), StringComparison.Ordinal)) ilegibles++;
                    else lista.Add(i);
                }
                catch { ilegibles++; }
            }
            return lista;
        }

        private static (int, string?) Podar(string destino, int conservar)
        {
            List<Instantanea> todas = Listar(destino, out int ilegibles);
            if (ilegibles > 0) return (0, "No se borró nada: " + ilegibles + " lista(s) de copias no se pudieron leer, y sin ellas no se sabe qué contenido sigue en uso.");
            int podadas = 0;
            // Protegidas: las sospechosas y, de cada una, la última buena anterior. Sin esto, la copia siguiente a una sospechosa se compara
            // con la ya cifrada, sale «normal», poda y se llevaría por delante la única versión buena.
            var protegidas = ProtegidasDeLaPoda(todas);
            foreach (Instantanea vieja in todas.Take(Math.Max(0, todas.Count - conservar)).Where(v => !protegidas.Contains(v.Id)))
            {
                try { File.Delete(Path.Combine(Manifiestos(destino), vieja.Id + ".json")); podadas++; }
                catch (Exception e) { return (podadas, "No se pudo borrar una versión vieja: " + e.Message); }
            }
            if (podadas == 0) return (0, null);

            var enUso = new HashSet<string>(Listar(destino, out int ilegibles2).SelectMany(i => i.Entradas.Select(e => e.Sha256)), StringComparer.OrdinalIgnoreCase);
            if (ilegibles2 > 0) return (podadas, "Se borraron versiones viejas pero no se limpió el contenido sobrante: no se pudo releer la lista.");
            string raiz = Blobs(destino);
            if (Directory.Exists(raiz))
                foreach (string f in Directory.GetFiles(raiz, "*", SearchOption.AllDirectories))
                {
                    string nombre = Path.GetFileName(f);
                    // Solo se borra lo que tiene forma de contenido de Nexo (64 hex) y no está en uso.
                    if (nombre.Length == 64 && nombre.All(Uri.IsHexDigit) && !enUso.Contains(nombre)) TryBorrar(f);
                }
            return (podadas, null);
        }

        /// <summary>
        /// La persona revisó una copia sospechosa y la da por buena: deja de estar marcada y la poda vuelve a poder borrarla (y la última buena
        /// anterior, si toca). Solo reescribe la lista de esa instantánea (no toca el contenido) y deja constancia en el motivo.
        /// </summary>
        public static (bool Correcto, string? Error) DescartarSospecha(string destino, string id)
        {
            destino = Path.GetFullPath(destino);
            Instantanea? inst = Listar(destino, out _).FirstOrDefault(i => string.Equals(i.Id, id, StringComparison.Ordinal));
            if (inst is null) return (false, "No existe esa copia.");
            if (!inst.Sospechosa) return (false, "Esa copia no está marcada como sospechosa.");
            string final = Path.Combine(Manifiestos(destino), inst.Id + ".json"), tmp = final + ".tmp";
            try
            {
                var nueva = inst with { Sospechosa = false, MotivoSospecha = "Revisada y dada por buena por la persona. Antes: " + inst.MotivoSospecha };
                File.WriteAllText(tmp, JsonSerializer.Serialize(nueva, Json), new UTF8Encoding(false));
                File.Move(tmp, final, overwrite: true);
                return (true, null);
            }
            catch (Exception e)
            {
                TryBorrar(tmp);
                return (false, e is UnauthorizedAccessException
                    ? "No tienes permiso para cambiar la lista de esa copia en el disco (la escribió el servicio de Nexo). " + e.Message
                    : e.Message);
            }
        }

        /// <summary>Una firma barata de las listas del destino (cuántas y la última modificación): cambia si se añade, borra o reescribe alguna.</summary>
        public static string FirmaDeLasListas(string destino)
        {
            try
            {
                string carpeta = Manifiestos(Path.GetFullPath(destino));
                if (!Directory.Exists(carpeta)) return "-";
                var fi = new DirectoryInfo(carpeta).GetFiles("*.json");
                return fi.Length + "|" + (fi.Length == 0 ? 0 : fi.Max(f => f.LastWriteTimeUtc.Ticks));
            }
            catch { return "?"; }
        }

        /// <summary>Los id que la poda nunca borra: cada instantánea sospechosa y la última buena que la precede.</summary>
        public static HashSet<string> ProtegidasDeLaPoda(IReadOnlyList<Instantanea> deMasVieja)
        {
            var protegidas = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < deMasVieja.Count; i++)
            {
                if (!deMasVieja[i].Sospechosa) continue;
                protegidas.Add(deMasVieja[i].Id);
                for (int j = i - 1; j >= 0; j--)
                    if (!deMasVieja[j].Sospechosa) { protegidas.Add(deMasVieja[j].Id); break; }
            }
            return protegidas;
        }

        /// <summary>Comprueba que todo el contenido que usan las instantáneas está y no cambió.</summary>
        public static ResultadoDeVerificacion Verificar(string destino, CancellationToken ct = default)
        {
            destino = Path.GetFullPath(destino);
            List<Instantanea> todas = Listar(destino, out int ilegibles);
            var problemas = new List<OmitidoEnCopia>();
            if (ilegibles > 0) problemas.Add(new OmitidoEnCopia(Manifiestos(destino), ilegibles + " lista(s) de copias no se pueden leer"));
            int comprobados = 0;
            foreach (string sha in todas.SelectMany(i => i.Entradas.Select(e => e.Sha256)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                ct.ThrowIfCancellationRequested();
                if (!EsHash(sha)) { problemas.Add(new OmitidoEnCopia(sha, "Un código de contenido no es válido")); continue; }
                string ruta = RutaDeBlob(destino, sha);
                comprobados++;
                if (!File.Exists(ruta)) { problemas.Add(new OmitidoEnCopia(ruta, "Falta el contenido")); continue; }
                string? real = HashDe(ruta, out string? motivo);
                if (real is null) problemas.Add(new OmitidoEnCopia(ruta, "No se pudo leer: " + motivo));
                else if (!string.Equals(real, sha, StringComparison.OrdinalIgnoreCase)) problemas.Add(new OmitidoEnCopia(ruta, "El contenido cambió (está dañado o alguien lo tocó)"));
            }
            return new ResultadoDeVerificacion(problemas.Count == 0, comprobados, problemas);
        }

        private static bool EsHash(string s) => s is { Length: 64 } && s.All(Uri.IsHexDigit);

        private static string? HashDe(string ruta, out string? motivo)
        {
            motivo = null;
            try
            {
                using var f = File.OpenRead(ruta);
                return Convert.ToHexString(SHA256.HashData(f)).ToLowerInvariant();
            }
            catch (Exception e) { motivo = e.Message; return null; }
        }

        /// <summary>
        /// Restaura una instantánea a una carpeta que NO exista todavía (o esté vacía). Nunca pisa nada. Cada archivo se
        /// comprueba contra su hash antes de entregarlo; uno dañado queda en «NoRestaurados».
        /// </summary>
        public static ResultadoDeRestauracion Restaurar(string destino, string idInstantanea, string carpetaNueva, CancellationToken ct = default)
        {
            destino = Path.GetFullPath(destino);
            Instantanea? inst = Listar(destino, out _).FirstOrDefault(i => string.Equals(i.Id, idInstantanea, StringComparison.Ordinal));
            if (inst is null) return new ResultadoDeRestauracion(false, "No existe esa copia.", 0, Array.Empty<OmitidoEnCopia>());
            string salida;
            try { salida = Path.GetFullPath(carpetaNueva); } catch (Exception e) { return new ResultadoDeRestauracion(false, "La carpeta no es válida: " + e.Message, 0, Array.Empty<OmitidoEnCopia>()); }
            if (Dentro(salida, destino)) return new ResultadoDeRestauracion(false, "No se puede restaurar dentro de la carpeta de copias.", 0, Array.Empty<OmitidoEnCopia>());
            try
            {
                if (Directory.Exists(salida) && Directory.EnumerateFileSystemEntries(salida).Any())
                    return new ResultadoDeRestauracion(false, "La carpeta de restauración ya tiene cosas: Nexo no pisa nada. Elige una vacía o nueva.", 0, Array.Empty<OmitidoEnCopia>());
                Directory.CreateDirectory(salida);
            }
            catch (Exception e) { return new ResultadoDeRestauracion(false, "No se pudo preparar la carpeta: " + e.Message, 0, Array.Empty<OmitidoEnCopia>()); }

            var fallos = new List<OmitidoEnCopia>();
            int hechos = 0;
            // Con varios orígenes se separa cada uno en su subcarpeta (nombre + número si se repite).
            var carpetaDeOrigen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var usados = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string o in inst.Entradas.Select(e => e.Origen).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string nombre = Limpio(Path.GetFileName(o.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)));
                if (nombre.Length == 0) nombre = "origen";
                string unico = nombre; int k = 1;
                while (!usados.Add(unico)) unico = nombre + "-" + (++k);
                carpetaDeOrigen[o] = unico;
            }

            foreach (EntradaDeCopia e in inst.Entradas)
            {
                ct.ThrowIfCancellationRequested();
                if (!EsHash(e.Sha256)) { fallos.Add(new OmitidoEnCopia(e.Relativa, "Código de contenido no válido")); continue; }
                string blob = RutaDeBlob(destino, e.Sha256);
                string final = Path.GetFullPath(Path.Combine(salida, carpetaDeOrigen[e.Origen], e.Relativa));
                // Una lista manipulada no puede sacar archivos fuera de la carpeta de restauración (por ejemplo con «..»).
                if (!Dentro(final, Path.Combine(salida, carpetaDeOrigen[e.Origen]))) { fallos.Add(new OmitidoEnCopia(e.Relativa, "La ruta sale de la carpeta de restauración (lista manipulada)")); continue; }
                if (!File.Exists(blob)) { fallos.Add(new OmitidoEnCopia(e.Relativa, "Falta el contenido en la copia")); continue; }
                string tmp = final + ".nexo-tmp";
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(final)!);
                    File.Copy(blob, tmp, overwrite: false);
                    string? real = HashDe(tmp, out string? motivo);
                    if (real is null || !string.Equals(real, e.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        TryBorrar(tmp);
                        fallos.Add(new OmitidoEnCopia(e.Relativa, real is null ? "No se pudo leer: " + motivo : "El contenido guardado está dañado: no se restaura"));
                        continue;
                    }
                    File.Move(tmp, final);
                    try { File.SetLastWriteTimeUtc(final, e.Modificado.UtcDateTime); } catch { /* la fecha es un detalle */ }
                    hechos++;
                }
                catch (Exception ex) { TryBorrar(tmp); fallos.Add(new OmitidoEnCopia(e.Relativa, ex.Message)); }
            }
            return new ResultadoDeRestauracion(fallos.Count == 0, fallos.Count == 0 ? null : fallos.Count + " archivo(s) no se pudieron restaurar.", hechos, fallos);
        }

        private static string Limpio(string nombre)
        {
            var malos = Path.GetInvalidFileNameChars();
            return new string(nombre.Select(c => malos.Contains(c) ? '_' : c).ToArray()).Trim();
        }
    }
}
