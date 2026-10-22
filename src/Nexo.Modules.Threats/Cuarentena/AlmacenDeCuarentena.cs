using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Firewall;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Cuarentena
{
    public sealed record ElementoDeCuarentena(
        string Id, string RutaOriginal, long Bytes, string Sha256, string? Firma, DateTimeOffset Fecha);

    /// <summary>Plan de cuarentena propuesto, todavia sin aplicar.</summary>
    public sealed class VistaPreviaCuarentena
    {
        public VistaPreviaCuarentena(
            IReadOnlyList<Deteccion> elementos, IReadOnlyList<string> rechazos, TokenDeCambio token)
        {
            Elementos = elementos;
            Rechazos = rechazos;
            Token = token;
        }

        public IReadOnlyList<Deteccion> Elementos { get; }

        /// <summary>Lo que se pidio y NO se hara, con el motivo.</summary>
        public IReadOnlyList<string> Rechazos { get; }

        public TokenDeCambio Token { get; }
        public bool HayCambios => Elementos.Count > 0;

        public string Describir()
        {
            var sb = new StringBuilder("Cuarentena\n");
            if (Elementos.Count == 0) sb.Append("  (nada que poner en cuarentena)\n");
            foreach (Deteccion d in Elementos)
                sb.Append("  ").Append(d.Firma).Append("  ").Append(Eventos.FormatearBytes(d.Bytes)).Append("  ").Append(d.Ruta).Append('\n');
            foreach (string r in Rechazos) sb.Append("  RECHAZADO: ").Append(r).Append('\n');
            if (Elementos.Count > 0)
                sb.Append("  Los archivos se cifran en la carpeta de cuarentena y se retiran de su sitio. No se eliminan.\n");
            return sb.ToString();
        }

        public static IEnumerable<string> Lineas(IEnumerable<Deteccion> elementos)
            => elementos.Select(d => string.Create(CultureInfo.InvariantCulture,
                   $"{d.Ruta}|{d.Bytes}|{d.Modificado.UtcTicks}|{d.Sha256}"));
    }

    public sealed class ResultadoCuarentena
    {
        public ResultadoCuarentena(IReadOnlyList<ElementoDeCuarentena> movidos, IReadOnlyList<string> omitidos)
        {
            Movidos = movidos;
            Omitidos = omitidos;
        }

        public IReadOnlyList<ElementoDeCuarentena> Movidos { get; }
        public IReadOnlyList<string> Omitidos { get; }
    }

    public sealed record ResultadoRestauracion(bool Exito, string? Ruta, string? Motivo);

    /// <summary>Plan de purga: las entradas cuyo plazo de retencion ya vencio. Todavia sin aplicar.</summary>
    public sealed class VistaPreviaPurga
    {
        public VistaPreviaPurga(IReadOnlyList<ElementoDeCuarentena> elementos, TokenDeCambio token)
        {
            Elementos = elementos;
            Token = token;
        }

        public IReadOnlyList<ElementoDeCuarentena> Elementos { get; }
        public TokenDeCambio Token { get; }
        public bool HayCambios => Elementos.Count > 0;

        public string Describir()
        {
            var sb = new StringBuilder("Purga de cuarentena" + Environment.NewLine);
            if (Elementos.Count == 0) sb.Append("  (ninguna entrada ha superado el plazo de retencion)").Append(Environment.NewLine);
            foreach (ElementoDeCuarentena e in Elementos)
                sb.Append("  ").Append(e.Firma).Append("  ").Append(Eventos.FormatearBytes(e.Bytes)).Append("  ").Append(e.RutaOriginal)
                  .Append("  (en cuarentena desde ").Append(e.Fecha.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Append(")").Append(Environment.NewLine);
            if (Elementos.Count > 0)
                sb.Append("  Se eliminan de forma DEFINITIVA: despues de esto ya no se podran restaurar.").Append(Environment.NewLine);
            return sb.ToString();
        }

        public static IEnumerable<string> Lineas(IEnumerable<ElementoDeCuarentena> elementos)
            => elementos.Select(e => string.Create(CultureInfo.InvariantCulture,
                   $"{e.Id}|{e.Sha256}|{e.Fecha.UtcTicks}"));
    }

    public sealed class ResultadoPurga
    {
        public ResultadoPurga(IReadOnlyList<ElementoDeCuarentena> purgados, IReadOnlyList<string> omitidos)
        {
            Purgados = purgados;
            Omitidos = omitidos;
        }

        public IReadOnlyList<ElementoDeCuarentena> Purgados { get; }
        public IReadOnlyList<string> Omitidos { get; }
    }

    /// <summary>
    /// Cuarentena de archivos: los cifra en una carpeta propia y los retira de su
    /// sitio, de forma reversible.
    ///
    /// El cifrado (AES-GCM) NO es para ocultar el contenido a un atacante: la clave
    /// vive junto al archivo. Existe para que el archivo cuarentenado deje de ser un
    /// ejecutable reconocible y ningun antivirus (incluido Windows Defender) lo
    /// vuelva a detectar y se pelee con Nexo por el mismo archivo (Salida 0, §0.3).
    /// La integridad si importa: el GCM y el SHA-256 garantizan que lo restaurado es
    /// byte a byte lo que se retiro.
    ///
    /// Reglas:
    ///   - Dos fases: Preparar no cambia nada; AplicarAsync solo ejecuta ese plan.
    ///   - El original solo se borra DESPUES de verificar que la copia cifrada se
    ///     descifra a lo mismo. Si no se puede borrar, se deshace la copia.
    ///   - No se mueven archivos del directorio de Windows: una deteccion ahi es un
    ///     incidente para revisar a mano, y quitar un archivo del sistema puede
    ///     dejar el equipo sin arrancar.
    /// </summary>
    public sealed class AlmacenDeCuarentena
    {
        public static readonly TimeSpan Retencion = TimeSpan.FromDays(30);

        private const long MaxBytesPorArchivo = 200L * 1024 * 1024;
        private static readonly byte[] Magia = Encoding.ASCII.GetBytes("NXQ1");
        private static readonly Regex IdValido = new Regex("^[0-9a-f]{32}$", RegexOptions.Compiled);
        private static readonly JsonSerializerOptions Json = new JsonSerializerOptions { WriteIndented = true };

        private readonly string _carpeta;
        private readonly IReportWriter _reportes;
        private readonly IReadOnlyList<string> _protegidas;
        private readonly Func<DateTimeOffset> _reloj;

        public AlmacenDeCuarentena(
            string carpeta,
            IReportWriter reportes,
            IEnumerable<string>? rutasProtegidas = null,
            Func<DateTimeOffset>? reloj = null)
        {
            if (string.IsNullOrWhiteSpace(carpeta)) throw new ArgumentException("Carpeta vacia.", nameof(carpeta));
            _carpeta = Path.GetFullPath(carpeta);
            _reportes = reportes;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _protegidas = (rutasProtegidas ?? RutasProtegidasPorDefecto()).Where(p => !string.IsNullOrWhiteSpace(p))
                              .Select(p => p.TrimEnd('\\', '/')).ToList();
        }

        public string Carpeta => _carpeta;

        public static IReadOnlyList<string> RutasProtegidasPorDefecto()
            => new[] { Environment.GetFolderPath(Environment.SpecialFolder.Windows) };

        // ============================================================
        //  FASE 1: PLAN
        // ============================================================
        public VistaPreviaCuarentena Preparar(IEnumerable<Deteccion> detecciones)
        {
            var elegidos = new List<Deteccion>();
            var rechazos = new List<string>();
            var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Deteccion d in detecciones)
            {
                if (!vistos.Add(d.Ruta)) continue;

                string? motivo = MotivoDeRechazo(d.Ruta);
                if (motivo is not null) rechazos.Add(d.Ruta + " — " + motivo);
                else elegidos.Add(d);
            }

            return new VistaPreviaCuarentena(elegidos, rechazos,
                TokenDeCambio.Emitir(VistaPreviaCuarentena.Lineas(elegidos), _reloj()));
        }

        private string? MotivoDeRechazo(string ruta)
        {
            if (EstaDentro(ruta, _carpeta)) return "ya esta dentro de la carpeta de cuarentena";

            foreach (string p in _protegidas)
                if (EstaDentro(ruta, p))
                    return "esta en una carpeta del sistema (" + p + "): revisalo a mano, Nexo no lo mueve";
            return null;
        }

        // ============================================================
        //  FASE 2: APLICAR
        // ============================================================
        /// <param name="acceso">
        /// En nombre de quien se lee y se retira el ORIGINAL. El servicio pasa la identidad del llamador:
        /// asi solo se puede poner en cuarentena lo que ese usuario podria leer y borrar por si mismo
        /// (si no, un usuario haria borrar a SYSTEM archivos que a el no le dejan).
        /// </param>
        public async Task<ResultadoCuarentena> AplicarAsync(
            VistaPreviaCuarentena vista, TokenDeCambio token, CancellationToken ct = default, IAccesoAArchivos? acceso = null)
        {
            IAccesoAArchivos a = acceso ?? AccesoDirecto.Instancia;
            if (vista is null) throw new ArgumentNullException(nameof(vista));
            if (token is null) throw new ArgumentNullException(nameof(token));

            if (!token.EsValidoPara(VistaPreviaCuarentena.Lineas(vista.Elementos), _reloj()))
                throw new InvalidOperationException(
                    "El token no corresponde a esta vista previa, o caduco. Hay que volver a previsualizar.");

            Directory.CreateDirectory(_carpeta);

            var movidos = new List<ElementoDeCuarentena>();
            var omitidos = new List<string>();

            foreach (Deteccion d in vista.Elementos)
            {
                ct.ThrowIfCancellationRequested();

                // El estado pudo cambiar desde la vista previa: se reverifica todo.
                string? motivo = MotivoDeRechazo(d.Ruta);
                if (motivo is not null) { omitidos.Add(d.Ruta + " — " + motivo); continue; }

                (ElementoDeCuarentena? item, string? error) = Mover(d, a);
                if (item is null) { omitidos.Add(d.Ruta + " — " + error); continue; }

                movidos.Add(item);
                await _reportes.EscribirAsync(Eventos.Amenazas.Cuarentena(
                    item.RutaOriginal, item.Id, item.Bytes, item.Fecha + Retencion, item.Firma), ct).ConfigureAwait(false);
            }

            return new ResultadoCuarentena(movidos, omitidos);
        }

        private (ElementoDeCuarentena?, string?) Mover(Deteccion d, IAccesoAArchivos a)
        {
            byte[] contenido;
            DateTimeOffset modificado;
            try
            {
                // Todo lo que toca el original va con la identidad del llamador (ver AplicarAsync).
                (byte[]? leido, DateTimeOffset mod, string? rechazo) = a.Ejecutar<(byte[]?, DateTimeOffset, string?)>(() =>
                {
                    var info = new FileInfo(d.Ruta);
                    if (!info.Exists) return ((byte[]?)null, default(DateTimeOffset), "ya no existe");
                    if (info.Length > MaxBytesPorArchivo) return (null, default, "demasiado grande para la cuarentena");
                    var m = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);

                    if (info.Length != d.Bytes || m != d.Modificado)
                        return (null, default, "el archivo cambio despues de la vista previa; no se mueve");

                    using var fs = new FileStream(d.Ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    byte[] buf = new byte[fs.Length];
                    fs.ReadExactly(buf);
                    return (buf, m, null);
                });
                if (rechazo is not null) return (null, rechazo);
                contenido = leido!;
                modificado = mod;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return (null, "no se pudo leer (" + ex.GetType().Name + ")");
            }

            string sha = Convert.ToHexString(SHA256.HashData(contenido)).ToLowerInvariant();
            if (d.Sha256 is not null && !string.Equals(d.Sha256, sha, StringComparison.OrdinalIgnoreCase))
                return (null, "el contenido no coincide con el que se analizo; no se mueve");

            string id = Guid.NewGuid().ToString("N");
            string rutaDatos = Path.Combine(_carpeta, id + ".nxq");
            string rutaMeta = Path.Combine(_carpeta, id + ".json");

            try
            {
                byte[] clave = RandomNumberGenerator.GetBytes(32);
                File.WriteAllBytes(rutaDatos + ".tmp", Cifrar(contenido, clave));
                File.Move(rutaDatos + ".tmp", rutaDatos);

                var meta = new Metadatos
                {
                    Id = id, RutaOriginal = d.Ruta, Bytes = contenido.Length, Sha256 = sha,
                    Firma = d.Firma, Fecha = _reloj(), Clave = Convert.ToBase64String(clave)
                };
                File.WriteAllText(rutaMeta, JsonSerializer.Serialize(meta, Json), new UTF8Encoding(false));

                // Antes de tocar el original: la copia cifrada debe descifrar a lo mismo.
                byte[]? vuelta = Descifrar(File.ReadAllBytes(rutaDatos), clave);
                if (vuelta is null || !string.Equals(
                        Convert.ToHexString(SHA256.HashData(vuelta)).ToLowerInvariant(), sha, StringComparison.Ordinal))
                {
                    Descartar(rutaDatos, rutaMeta);
                    return (null, "la verificacion de la copia cifrada fallo; el original no se toco");
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                Descartar(rutaDatos, rutaMeta);
                return (null, "no se pudo escribir en la cuarentena (" + ex.GetType().Name + ")");
            }

            if (!BorrarOriginal(d.Ruta, a))
            {
                Descartar(rutaDatos, rutaMeta);
                return (null, "no se pudo retirar el original (en uso o sin permisos); se deshizo la copia");
            }

            return (new ElementoDeCuarentena(id, d.Ruta, contenido.Length, sha, d.Firma, _reloj()), null);
        }

        // ============================================================
        //  LISTAR Y RESTAURAR
        // ============================================================
        public IReadOnlyList<ElementoDeCuarentena> Listar()
        {
            if (!Directory.Exists(_carpeta)) return Array.Empty<ElementoDeCuarentena>();

            var lista = new List<ElementoDeCuarentena>();
            foreach (string f in Directory.EnumerateFiles(_carpeta, "*.json"))
            {
                Metadatos? m = LeerMeta(f);
                if (m is not null && File.Exists(Path.Combine(_carpeta, m.Id + ".nxq")))
                    lista.Add(new ElementoDeCuarentena(m.Id, m.RutaOriginal, m.Bytes, m.Sha256, m.Firma, m.Fecha));
            }
            return lista.OrderBy(e => e.Fecha).ToList();
        }

        /// <summary>
        /// Devuelve el archivo a su sitio (o a <paramref name="destino"/>). Nunca
        /// pisa un archivo existente.
        /// </summary>
        public async Task<ResultadoRestauracion> RestaurarAsync(
            string id, string? destino = null, CancellationToken ct = default, IAccesoAArchivos? acceso = null)
        {
            // Escribir en la ruta original va con la identidad del llamador: no se escribe con SYSTEM donde el no podria.
            IAccesoAArchivos a = acceso ?? AccesoDirecto.Instancia;
            // El id llega de fuera: se valida antes de formar ninguna ruta con el.
            if (id is null || !IdValido.IsMatch(id))
                return new ResultadoRestauracion(false, null, "identificador de cuarentena no valido");

            string rutaMeta = Path.Combine(_carpeta, id + ".json");
            string rutaDatos = Path.Combine(_carpeta, id + ".nxq");
            Metadatos? m = File.Exists(rutaMeta) ? LeerMeta(rutaMeta) : null;
            if (m is null || !File.Exists(rutaDatos))
                return new ResultadoRestauracion(false, null, "no existe esa entrada de cuarentena");

            string ruta = destino ?? m.RutaOriginal;
            bool existe;
            try { existe = a.Ejecutar(() => File.Exists(ruta) || Directory.Exists(ruta)); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return new ResultadoRestauracion(false, ruta, "no se pudo comprobar el destino (" + ex.GetType().Name + ")");
            }
            if (existe)
                return new ResultadoRestauracion(false, ruta, "el destino ya existe; no se sobrescribe (usa otro destino)");

            try
            {
                byte[]? contenido = Descifrar(File.ReadAllBytes(rutaDatos), Convert.FromBase64String(m.Clave));
                if (contenido is null || !string.Equals(
                        Convert.ToHexString(SHA256.HashData(contenido)).ToLowerInvariant(), m.Sha256, StringComparison.Ordinal))
                    return new ResultadoRestauracion(false, ruta, "la copia cuarentenada esta danada (no pasa la verificacion)");

                a.Ejecutar(() =>
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(ruta))!);
                    using var fs = new FileStream(ruta, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    fs.Write(contenido);
                });

                Descartar(rutaDatos, rutaMeta);
                await _reportes.EscribirAsync(Eventos.Amenazas.Restaurado(ruta, id, contenido.Length), ct).ConfigureAwait(false);
                return new ResultadoRestauracion(true, ruta, null);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is FormatException)
            {
                return new ResultadoRestauracion(false, ruta, "no se pudo restaurar (" + ex.GetType().Name + ")");
            }
        }

        // ============================================================
        //  PURGA: elimina lo que supero el plazo de retencion
        // ============================================================
        public static bool HaVencido(ElementoDeCuarentena e, DateTimeOffset ahora) => e.Fecha + Retencion <= ahora;

        /// <summary>Lista las entradas vencidas. No elimina nada.</summary>
        public VistaPreviaPurga PrepararPurga()
        {
            DateTimeOffset ahora = _reloj();
            var vencidas = Listar().Where(e => HaVencido(e, ahora)).ToList();
            return new VistaPreviaPurga(vencidas, TokenDeCambio.Emitir(VistaPreviaPurga.Lineas(vencidas), ahora));
        }

        public async Task<ResultadoPurga> AplicarPurgaAsync(
            VistaPreviaPurga vista, TokenDeCambio token, CancellationToken ct = default)
        {
            if (vista is null) throw new ArgumentNullException(nameof(vista));
            if (token is null) throw new ArgumentNullException(nameof(token));

            if (!token.EsValidoPara(VistaPreviaPurga.Lineas(vista.Elementos), _reloj()))
                throw new InvalidOperationException(
                    "El token no corresponde a esta vista previa, o caduco. Hay que volver a previsualizar.");

            var purgados = new List<ElementoDeCuarentena>();
            var omitidos = new List<string>();

            foreach (ElementoDeCuarentena e in vista.Elementos)
            {
                ct.ThrowIfCancellationRequested();

                // El estado pudo cambiar desde la vista previa (p. ej. se restauro): se relee del disco.
                string rutaMeta = Path.Combine(_carpeta, e.Id + ".json");
                string rutaDatos = Path.Combine(_carpeta, e.Id + ".nxq");
                Metadatos? m = IdValido.IsMatch(e.Id) && File.Exists(rutaMeta) ? LeerMeta(rutaMeta) : null;
                if (m is null || !File.Exists(rutaDatos)) { omitidos.Add(e.RutaOriginal + " — ya no esta en la cuarentena"); continue; }
                if (m.Fecha + Retencion > _reloj()) { omitidos.Add(e.RutaOriginal + " — aun no vence el plazo"); continue; }

                // Primero los datos y despues los metadatos: si falla a medias, la entrada deja de
                // listarse (Listar exige ambos) en vez de quedar "restaurable" sin contenido.
                try
                {
                    File.Delete(rutaDatos);
                    File.Delete(rutaMeta);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    omitidos.Add(e.RutaOriginal + " — no se pudo eliminar (" + ex.GetType().Name + ")");
                    continue;
                }

                purgados.Add(e);
                await _reportes.EscribirAsync(Eventos.Amenazas.Purgado(e.RutaOriginal, e.Id, e.Bytes), ct).ConfigureAwait(false);
            }

            return new ResultadoPurga(purgados, omitidos);
        }

        // ============================================================
        //  CIFRADO: "NXQ1" | nonce(12) | etiqueta(16) | texto cifrado
        // ============================================================
        private static byte[] Cifrar(byte[] claro, byte[] clave)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] cifrado = new byte[claro.Length];
            byte[] etiqueta = new byte[16];
            using (var aes = new AesGcm(clave, 16)) aes.Encrypt(nonce, claro, cifrado, etiqueta, Magia);

            byte[] salida = new byte[Magia.Length + 12 + 16 + cifrado.Length];
            Buffer.BlockCopy(Magia, 0, salida, 0, 4);
            Buffer.BlockCopy(nonce, 0, salida, 4, 12);
            Buffer.BlockCopy(etiqueta, 0, salida, 16, 16);
            Buffer.BlockCopy(cifrado, 0, salida, 32, cifrado.Length);
            return salida;
        }

        private static byte[]? Descifrar(byte[] datos, byte[] clave)
        {
            if (datos.Length < 32 || !datos.AsSpan(0, 4).SequenceEqual(Magia)) return null;
            try
            {
                byte[] claro = new byte[datos.Length - 32];
                using var aes = new AesGcm(clave, 16);
                aes.Decrypt(datos.AsSpan(4, 12), datos.AsSpan(32), datos.AsSpan(16, 16), claro, Magia);
                return claro;
            }
            catch (CryptographicException) { return null; }
        }

        // ============================================================
        private static bool BorrarOriginal(string ruta, IAccesoAArchivos a)
            => a.Ejecutar(() =>
            {
                for (int intento = 0; intento < 2; intento++)
                {
                    try { File.Delete(ruta); return !File.Exists(ruta); }
                    catch (UnauthorizedAccessException) when (intento == 0)
                    {
                        // Un archivo de solo lectura no se puede borrar: se quita el atributo y se reintenta.
                        try { File.SetAttributes(ruta, FileAttributes.Normal); } catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { return false; }
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return false; }
                }
                return false;
            });

        private static void Descartar(params string[] rutas)
        {
            foreach (string r in rutas)
            {
                foreach (string f in new[] { r, r + ".tmp" })
                {
                    try { if (File.Exists(f)) File.Delete(f); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
            }
        }

        private static Metadatos? LeerMeta(string ruta)
        {
            try
            {
                Metadatos? m = JsonSerializer.Deserialize<Metadatos>(File.ReadAllText(ruta, Encoding.UTF8), Json);
                return m is not null && IdValido.IsMatch(m.Id ?? "") && !string.IsNullOrEmpty(m.Clave) ? m : null;
            }
            catch (Exception ex) when (ex is IOException || ex is JsonException || ex is UnauthorizedAccessException) { return null; }
        }

        private static bool EstaDentro(string ruta, string carpeta)
        {
            string c = carpeta.TrimEnd('\\', '/');
            return ruta.Equals(c, StringComparison.OrdinalIgnoreCase)
                   || ruta.StartsWith(c + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                   || ruta.StartsWith(c + '/', StringComparison.OrdinalIgnoreCase)
                   || ruta.StartsWith(c + '\\', StringComparison.OrdinalIgnoreCase);
        }

        private sealed class Metadatos
        {
            public string Id { get; set; } = "";
            public string RutaOriginal { get; set; } = "";
            public long Bytes { get; set; }
            public string Sha256 { get; set; } = "";
            public string? Firma { get; set; }
            public DateTimeOffset Fecha { get; set; }
            public string Clave { get; set; } = "";
        }
    }
}
