using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Identity.Boveda
{
    public enum EstadoDeApertura
    {
        Abierta,
        NoExiste,

        /// <summary>No es una boveda de Nexo, esta truncada o su estructura no cuadra.</summary>
        ArchivoIlegible,
        VersionNoSoportada,
        ParametrosFueraDeRango,

        /// <summary>
        /// AES-GCM no distingue una contrasena equivocada de un archivo alterado: las dos hacen fallar la etiqueta. Nexo no
        /// finge saber cual de las dos fue.
        /// </summary>
        ContrasenaIncorrectaOArchivoAlterado,
        ErrorDeLectura
    }

    public sealed record ResultadoDeApertura(EstadoDeApertura Estado, Boveda? Boveda, string? Detalle = null)
    {
        public bool Abierta => Estado == EstadoDeApertura.Abierta;
    }

    public enum EstadoDeRestauracion
    {
        Restaurada,
        CopiaNoExiste,
        CopiaIlegible,
        VersionNoSoportada,
        ParametrosFueraDeRango,
        ContrasenaIncorrectaOArchivoAlterado,

        /// <summary>El destino es el mismo archivo que la copia: no hay nada que restaurar.</summary>
        DestinoEsLaCopia,
        ErrorDeEscritura
    }

    /// <param name="ArchivoAnterior">Donde quedo la boveda que habia (apartada, no borrada), o null si no habia ninguna.</param>
    public sealed record ResultadoDeRestauracion(EstadoDeRestauracion Estado, string? ArchivoAnterior, string? Detalle = null)
    {
        public bool Restaurada => Estado == EstadoDeRestauracion.Restaurada;
    }

    /// <summary>
    /// Boveda de contrasenas: un archivo cifrado con AES-256-GCM, con la clave derivada de la contrasena maestra por Argon2id.
    ///
    ///  - La clave vive en memoria solo mientras la boveda esta abierta; <see cref="Bloquear"/> la sobrescribe con ceros.
    ///    Lo que NO se puede garantizar: las cadenas de .NET (sitio, usuario, contrasena de cada entrada) no se pueden borrar
    ///    a voluntad, asi que pueden sobrevivir en memoria hasta que el recolector las pise. Es un limite del lenguaje, no
    ///    una promesa que Nexo pueda cumplir.
    ///  - Cada guardado usa un nonce nuevo y aleatorio, escribe a un temporal, reemplaza el archivo y VERIFICA el resultado
    ///    antes de dar nada por guardado; si falla, restaura el anterior. No queda ninguna copia vieja: una entrada borrada
    ///    desaparece del disco.
    ///  - No hay forma de recuperar la contrasena maestra: sin ella los datos son irrecuperables, a proposito.
    ///  - Ningun evento que sale de aqui lleva sitio, usuario ni contrasena (las notas del vault son texto plano).
    /// </summary>
    public sealed class Boveda : IDisposable
    {
        public const int LongitudMinimaDeContrasenaMaestra = 10;
        public const int MaximoDeEntradas = 100_000;

        private readonly string _ruta;
        private readonly IReportWriter? _reportes;
        private readonly object _cerrojo = new object();
        private readonly SemaphoreSlim _escritura = new SemaphoreSlim(1, 1);
        private readonly List<EntradaDeBoveda> _entradas = new List<EntradaDeBoveda>();
        private byte[]? _clave;
        private byte[] _sal;
        private readonly ParametrosDeClave _parametros;

        private Boveda(string ruta, IReportWriter? reportes, byte[] clave, byte[] sal, ParametrosDeClave parametros)
        {
            _ruta = ruta;
            _reportes = reportes;
            _clave = clave;
            _sal = sal;
            _parametros = parametros;
        }

        public bool Bloqueada { get { lock (_cerrojo) return _clave is null; } }

        public IReadOnlyList<EntradaDeBoveda> Entradas
        {
            get { lock (_cerrojo) { ExigirAbierta(); return _entradas.ToList(); } }
        }

        // ---------------------------------------------------------------- crear y abrir

        public static async Task<Boveda> CrearAsync(string ruta, string contrasenaMaestra, IReportWriter? reportes = null,
                                                    ParametrosDeClave? parametros = null, bool permitirParametrosDebiles = false,
                                                    CancellationToken ct = default)
        {
            ValidarRuta(ruta);
            ValidarContrasenaMaestra(contrasenaMaestra);
            ParametrosDeClave p = parametros ?? ParametrosDeClave.Seguros;
            if (!p.EsLegible || (!permitirParametrosDebiles && !p.EsSeguro))
                throw new ArgumentException("Los parámetros de Argon2id son demasiado débiles para una bóveda real.", nameof(parametros));
            if (File.Exists(ruta)) throw new IOException("Ya existe un archivo en esa ruta: Nexo no sobrescribe una bóveda existente.");

            byte[] sal = RandomNumberGenerator.GetBytes(FormatoDeBoveda.TamSal);
            byte[] clave = await Task.Run(() => DerivarClave(contrasenaMaestra, sal, p), ct).ConfigureAwait(false);
            var b = new Boveda(ruta, reportes, clave, sal, p);
            try
            {
                await b.GuardarAsync().ConfigureAwait(false);
            }
            catch
            {
                b.Bloquear();
                throw;
            }
            await b.PublicarAsync(EventosDeBoveda.Creada()).ConfigureAwait(false);
            return b;
        }

        public static async Task<ResultadoDeApertura> AbrirAsync(string ruta, string contrasenaMaestra, IReportWriter? reportes = null,
                                                                 CancellationToken ct = default)
        {
            ValidarRuta(ruta);
            if (contrasenaMaestra is null) throw new ArgumentNullException(nameof(contrasenaMaestra));

            byte[] archivo;
            try
            {
                if (!File.Exists(ruta)) return new ResultadoDeApertura(EstadoDeApertura.NoExiste, null);
                if (new FileInfo(ruta).Length > FormatoDeBoveda.MaximoDeArchivo)
                    return new ResultadoDeApertura(EstadoDeApertura.ArchivoIlegible, null, "el archivo es demasiado grande para ser una bóveda");
                archivo = await File.ReadAllBytesAsync(ruta, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return new ResultadoDeApertura(EstadoDeApertura.ErrorDeLectura, null, e.GetType().Name);
            }

            EstadoDeFormato f = FormatoDeBoveda.Leer(archivo, out CabeceraDeBoveda? c);
            if (f != EstadoDeFormato.Correcto || c is null)
                return new ResultadoDeApertura(f switch
                {
                    EstadoDeFormato.VersionNoSoportada => EstadoDeApertura.VersionNoSoportada,
                    EstadoDeFormato.ParametrosFueraDeRango => EstadoDeApertura.ParametrosFueraDeRango,
                    _ => EstadoDeApertura.ArchivoIlegible
                }, null);

            byte[] clave = await Task.Run(() => DerivarClave(contrasenaMaestra, c.Sal, c.Parametros), ct).ConfigureAwait(false);
            byte[]? claro = Descifrar(clave, c);
            if (claro is null)
            {
                CryptographicOperations.ZeroMemory(clave);
                await PublicarSinInstanciaAsync(reportes, EventosDeBoveda.FalloDeDesbloqueo()).ConfigureAwait(false);
                return new ResultadoDeApertura(EstadoDeApertura.ContrasenaIncorrectaOArchivoAlterado, null);
            }

            List<EntradaDeBoveda>? entradas;
            try { entradas = JsonSerializer.Deserialize<ContenidoDeBoveda>(claro)?.Entradas; }
            catch (JsonException) { entradas = null; }
            finally { CryptographicOperations.ZeroMemory(claro); }

            if (entradas is null || entradas.Count > MaximoDeEntradas || entradas.Any(e => e is null || e.Sitio is null || e.Usuario is null || e.Contrasena is null || e.Notas is null))
            {
                CryptographicOperations.ZeroMemory(clave);
                return new ResultadoDeApertura(EstadoDeApertura.ArchivoIlegible, null, "se descifró, pero el contenido no tiene la forma esperada");
            }

            var b = new Boveda(ruta, reportes, clave, c.Sal, c.Parametros);
            b._entradas.AddRange(entradas);
            await b.PublicarAsync(EventosDeBoveda.Desbloqueada(entradas.Count)).ConfigureAwait(false);
            return new ResultadoDeApertura(EstadoDeApertura.Abierta, b);
        }

        // ---------------------------------------------------------------- entradas (cada cambio se guarda en el acto)

        public async Task<EntradaDeBoveda> AgregarAsync(string sitio, string usuario, string contrasena, string notas = "")
        {
            ValidarTexto(sitio, nameof(sitio), obligatorio: true);
            ValidarTexto(usuario, nameof(usuario), obligatorio: false);
            ValidarTexto(contrasena, nameof(contrasena), obligatorio: false);
            ValidarTexto(notas, nameof(notas), obligatorio: false, maximo: 10_000);

            var ahora = DateTimeOffset.Now;
            var e = new EntradaDeBoveda(Guid.NewGuid(), sitio.Trim(), usuario, contrasena, notas, ahora, ahora);
            lock (_cerrojo)
            {
                ExigirAbierta();
                if (_entradas.Count >= MaximoDeEntradas) throw new InvalidOperationException("La bóveda alcanzó el máximo de entradas.");
                _entradas.Add(e);
            }
            try { await GuardarAsync().ConfigureAwait(false); }
            catch { lock (_cerrojo) { _entradas.RemoveAll(x => x.Id == e.Id); } throw; }
            return e;
        }

        public async Task<EntradaDeBoveda> ActualizarAsync(Guid id, string sitio, string usuario, string contrasena, string notas)
        {
            ValidarTexto(sitio, nameof(sitio), obligatorio: true);
            ValidarTexto(usuario, nameof(usuario), obligatorio: false);
            ValidarTexto(contrasena, nameof(contrasena), obligatorio: false);
            ValidarTexto(notas, nameof(notas), obligatorio: false, maximo: 10_000);

            EntradaDeBoveda anterior, nueva;
            lock (_cerrojo)
            {
                ExigirAbierta();
                int i = _entradas.FindIndex(x => x.Id == id);
                if (i < 0) throw new KeyNotFoundException("No existe esa entrada.");
                anterior = _entradas[i];
                nueva = anterior with { Sitio = sitio.Trim(), Usuario = usuario, Contrasena = contrasena, Notas = notas, Modificada = DateTimeOffset.Now };
                _entradas[i] = nueva;
            }
            try { await GuardarAsync().ConfigureAwait(false); }
            catch { lock (_cerrojo) { int i = _entradas.FindIndex(x => x.Id == id); if (i >= 0) _entradas[i] = anterior; } throw; }
            return nueva;
        }

        public async Task<bool> EliminarAsync(Guid id)
        {
            EntradaDeBoveda quitada;
            int indice;
            lock (_cerrojo)
            {
                ExigirAbierta();
                indice = _entradas.FindIndex(x => x.Id == id);
                if (indice < 0) return false;
                quitada = _entradas[indice];
                _entradas.RemoveAt(indice);
            }
            try { await GuardarAsync().ConfigureAwait(false); }
            catch { lock (_cerrojo) { _entradas.Insert(Math.Min(indice, _entradas.Count), quitada); } throw; }
            return true;
        }

        // ---------------------------------------------------------------- contrasena maestra, bloqueo

        /// <summary>
        /// Cambia la contrasena maestra: sal nueva, clave nueva, archivo reescrito. Exige la contrasena actual (comparando la
        /// clave derivada en tiempo constante), para que alguien que encuentre la boveda abierta no pueda cambiarla.
        /// </summary>
        public async Task CambiarContrasenaMaestraAsync(string actual, string nueva, CancellationToken ct = default)
        {
            ValidarContrasenaMaestra(nueva);
            byte[] claveActual, salActual;
            lock (_cerrojo) { ExigirAbierta(); claveActual = (byte[])_clave!.Clone(); salActual = _sal; }

            byte[] probada = await Task.Run(() => DerivarClave(actual ?? "", salActual, _parametros), ct).ConfigureAwait(false);
            bool coincide = CryptographicOperations.FixedTimeEquals(probada, claveActual);
            CryptographicOperations.ZeroMemory(probada);
            CryptographicOperations.ZeroMemory(claveActual);
            if (!coincide) throw new UnauthorizedAccessException("La contraseña maestra actual no es correcta.");

            byte[] salNueva = RandomNumberGenerator.GetBytes(FormatoDeBoveda.TamSal);
            byte[] claveNueva = await Task.Run(() => DerivarClave(nueva, salNueva, _parametros), ct).ConfigureAwait(false);

            byte[] claveVieja, salVieja;
            lock (_cerrojo)
            {
                ExigirAbierta();
                claveVieja = _clave!; salVieja = _sal;
                _clave = claveNueva; _sal = salNueva;
            }
            try { await GuardarAsync().ConfigureAwait(false); }
            catch
            {
                lock (_cerrojo) { CryptographicOperations.ZeroMemory(claveNueva); _clave = claveVieja; _sal = salVieja; }
                throw;
            }
            CryptographicOperations.ZeroMemory(claveVieja);
        }

        /// <summary>Sobrescribe la clave con ceros y olvida las entradas. Despues de esto hay que volver a abrir con la contrasena.</summary>
        public void Bloquear()
        {
            lock (_cerrojo)
            {
                if (_clave is not null) CryptographicOperations.ZeroMemory(_clave);
                _clave = null;
                _entradas.Clear();
            }
        }

        public void Dispose() => Bloquear();

        // ---------------------------------------------------------------- guardar y cifrar

        private async Task GuardarAsync()
        {
            // Un guardado a la vez: dos escrituras simultaneas se pisarian el temporal y el reemplazo.
            await _escritura.WaitAsync().ConfigureAwait(false);
            try
            {
                byte[] clave, sal;
                List<EntradaDeBoveda> copia;
                lock (_cerrojo) { ExigirAbierta(); clave = (byte[])_clave!.Clone(); sal = _sal; copia = _entradas.ToList(); }

                byte[] archivo = ConstruirArchivo(clave, sal, copia);
                try
                {
                    await EscribirConVerificacionAsync(_ruta, archivo, clave).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(clave);
                }
            }
            finally
            {
                _escritura.Release();
            }
        }

        /// <summary>El archivo cifrado completo para un estado dado: nonce NUEVO cada vez, cabecera autenticada.</summary>
        private byte[] ConstruirArchivo(byte[] clave, byte[] sal, List<EntradaDeBoveda> entradas)
        {
            byte[] claro = JsonSerializer.SerializeToUtf8Bytes(new ContenidoDeBoveda { Version = 1, Entradas = entradas });
            byte[] nonce = RandomNumberGenerator.GetBytes(FormatoDeBoveda.TamNonce);
            byte[] cifrado = new byte[claro.Length];
            byte[] etiqueta = new byte[FormatoDeBoveda.TamEtiqueta];
            byte[] cabecera = FormatoDeBoveda.Cabecera(_parametros, sal, nonce, claro.Length);
            try
            {
                using var aes = new AesGcm(clave, FormatoDeBoveda.TamEtiqueta);
                aes.Encrypt(nonce, claro, cifrado, etiqueta, cabecera);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(claro);
            }
            return FormatoDeBoveda.Escribir(_parametros, sal, nonce, cifrado, etiqueta);
        }

        // ---------------------------------------------------------------- copia de seguridad

        /// <summary>
        /// Guarda una COPIA CIFRADA del estado actual en <paramref name="destino"/> (otro disco, un USB...). Se abre con la misma contraseña maestra.
        /// Se escribe con un nonce nuevo y se VERIFICA que descifra antes de darla por buena; nunca sobrescribe sin permiso y jamas sobre el propio archivo
        /// de la boveda. OJO: una copia conserva lo que habia en ese momento, incluso lo que se borre despues (es su razon de ser); las copias hay que
        /// cuidarlas como la boveda misma.
        /// </summary>
        public async Task ExportarCopiaAsync(string destino, bool sobrescribir = false)
        {
            ValidarRuta(destino);
            string completo = Path.GetFullPath(destino);
            if (string.Equals(completo, Path.GetFullPath(_ruta), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("La copia no puede ser el mismo archivo de la bóveda.", nameof(destino));
            if (File.Exists(completo) && !sobrescribir) throw new IOException("Ya existe un archivo en ese destino: Nexo no lo sobrescribe sin permiso.");

            await _escritura.WaitAsync().ConfigureAwait(false);
            try
            {
                byte[] clave, sal;
                List<EntradaDeBoveda> entradas;
                lock (_cerrojo) { ExigirAbierta(); clave = (byte[])_clave!.Clone(); sal = _sal; entradas = _entradas.ToList(); }
                byte[] archivo = ConstruirArchivo(clave, sal, entradas);
                try { await EscribirConVerificacionAsync(completo, archivo, clave).ConfigureAwait(false); }
                finally { CryptographicOperations.ZeroMemory(clave); }
            }
            finally
            {
                _escritura.Release();
            }
        }

        /// <summary>
        /// Instala una copia como bóveda en <paramref name="destino"/>. ANTES de tocar nada comprueba que la copia abre con su contraseña. Si ya hay
        /// una boveda en el destino NO se borra: se aparta con fecha y hora (<see cref="ResultadoDeRestauracion.ArchivoAnterior"/>). Despues de instalar se
        /// vuelve a abrir el resultado; si no abre, se deshace y se devuelve lo anterior a su sitio.
        /// </summary>
        public static async Task<ResultadoDeRestauracion> RestaurarAsync(string copia, string contrasenaDeLaCopia, string destino, CancellationToken ct = default)
        {
            ValidarRuta(copia);
            ValidarRuta(destino);
            string cCopia = Path.GetFullPath(copia), cDestino = Path.GetFullPath(destino);
            if (string.Equals(cCopia, cDestino, StringComparison.OrdinalIgnoreCase))
                return new ResultadoDeRestauracion(EstadoDeRestauracion.DestinoEsLaCopia, null, "la copia y el destino son el mismo archivo");

            // 1) La copia debe abrir con su contraseña: no se instala algo que no se puede usar.
            byte[] bytes;
            try
            {
                if (!File.Exists(cCopia)) return new ResultadoDeRestauracion(EstadoDeRestauracion.CopiaNoExiste, null);
                bytes = await File.ReadAllBytesAsync(cCopia, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return new ResultadoDeRestauracion(EstadoDeRestauracion.ErrorDeEscritura, null, "no se pudo leer la copia (" + e.GetType().Name + ")");
            }

            ResultadoDeApertura a = await AbrirAsync(cCopia, contrasenaDeLaCopia, null, ct).ConfigureAwait(false);
            if (!a.Abierta)
            {
                return new ResultadoDeRestauracion(a.Estado switch
                {
                    EstadoDeApertura.NoExiste => EstadoDeRestauracion.CopiaNoExiste,
                    EstadoDeApertura.ArchivoIlegible => EstadoDeRestauracion.CopiaIlegible,
                    EstadoDeApertura.VersionNoSoportada => EstadoDeRestauracion.VersionNoSoportada,
                    EstadoDeApertura.ParametrosFueraDeRango => EstadoDeRestauracion.ParametrosFueraDeRango,
                    EstadoDeApertura.ContrasenaIncorrectaOArchivoAlterado => EstadoDeRestauracion.ContrasenaIncorrectaOArchivoAlterado,
                    _ => EstadoDeRestauracion.ErrorDeEscritura
                }, null, a.Detalle);
            }
            a.Boveda?.Dispose();

            // 2) Instalar: lo que habia se aparta (nunca se borra), se escribe la copia y se comprueba que abre.
            string? anterior = null;
            string tmp = cDestino + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant() + ".tmp";
            try
            {
                string? dir = Path.GetDirectoryName(cDestino);
                if (dir is not null) Directory.CreateDirectory(dir);
                using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    await fs.WriteAsync(bytes.AsMemory(), ct).ConfigureAwait(false);
                    await fs.FlushAsync(ct).ConfigureAwait(false);
                    fs.Flush(true);
                }

                if (File.Exists(cDestino))
                {
                    anterior = cDestino + ".anterior-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
                    int n = 1;
                    while (File.Exists(anterior)) anterior = cDestino + ".anterior-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture) + "-" + n++;
                    File.Move(cDestino, anterior);
                }
                File.Move(tmp, cDestino);

                ResultadoDeApertura b = await AbrirAsync(cDestino, contrasenaDeLaCopia, null, ct).ConfigureAwait(false);
                if (!b.Abierta)
                {
                    File.Delete(cDestino);
                    if (anterior is not null) File.Move(anterior, cDestino);
                    return new ResultadoDeRestauracion(EstadoDeRestauracion.ErrorDeEscritura, null, "la copia instalada no abrió; se dejó todo como estaba");
                }
                b.Boveda?.Dispose();
                return new ResultadoDeRestauracion(EstadoDeRestauracion.Restaurada, anterior);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Si algo se movio y no se pudo terminar, se devuelve lo anterior a su sitio.
                try { if (anterior is not null && !File.Exists(cDestino)) File.Move(anterior, cDestino); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                return new ResultadoDeRestauracion(EstadoDeRestauracion.ErrorDeEscritura, null, "no se pudo instalar la copia (" + e.GetType().Name + "); se dejó todo como estaba");
            }
            finally
            {
                TryBorrar(tmp);
            }
        }

        private async Task EscribirConVerificacionAsync(string ruta, byte[] archivo, byte[] clave)
        {
            string? directorio = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (directorio is not null) Directory.CreateDirectory(directorio);

            string tmp = ruta + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant() + ".tmp";
            string bak = ruta + ".bak";
            try
            {
                using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    await fs.WriteAsync(archivo.AsMemory()).ConfigureAwait(false);
                    await fs.FlushAsync().ConfigureAwait(false);
                    fs.Flush(true);
                }

                bool habiaAnterior = File.Exists(ruta);
                if (habiaAnterior) File.Replace(tmp, ruta, bak, ignoreMetadataErrors: true);
                else File.Move(tmp, ruta);

                // Verificar lo escrito (solo AES, sin repetir Argon2): si no descifra, se restaura lo anterior.
                if (!ArchivoDescifraCon(ruta, clave))
                {
                    if (habiaAnterior && File.Exists(bak)) File.Copy(bak, ruta, overwrite: true);
                    else File.Delete(ruta);
                    throw new IOException("El archivo guardado no pasó la verificación; se restauró el anterior.");
                }
                if (habiaAnterior) TryBorrar(bak); // no dejar una copia vieja: lo que se borro debe desaparecer del disco
            }
            finally
            {
                TryBorrar(tmp);
            }
        }

        private static bool ArchivoDescifraCon(string ruta, byte[] clave)
        {
            try
            {
                byte[] a = File.ReadAllBytes(ruta);
                if (FormatoDeBoveda.Leer(a, out CabeceraDeBoveda? c) != EstadoDeFormato.Correcto || c is null) return false;
                byte[]? claro = Descifrar(clave, c);
                if (claro is null) return false;
                CryptographicOperations.ZeroMemory(claro);
                return true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
        }

        private static byte[]? Descifrar(byte[] clave, CabeceraDeBoveda c)
        {
            byte[] claro = new byte[c.Cifrado.Length];
            try
            {
                using var aes = new AesGcm(clave, FormatoDeBoveda.TamEtiqueta);
                aes.Decrypt(c.Nonce, c.Cifrado, c.Etiqueta, claro, c.DatosAutenticados);
                return claro;
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(claro);
                return null;
            }
        }

        /// <summary>Argon2id sobre la contrasena normalizada (NFKC) en UTF-8: la misma contrasena escrita con otra forma Unicode abre igual.</summary>
        internal static byte[] DerivarClave(string contrasena, byte[] sal, ParametrosDeClave p)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(contrasena.Normalize(NormalizationForm.FormKC));
            try
            {
                using var argon = new Argon2id(bytes)
                {
                    Salt = sal,
                    DegreeOfParallelism = p.Paralelismo,
                    Iterations = p.Iteraciones,
                    MemorySize = p.MemoriaKiB
                };
                return argon.GetBytes(32);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        // ---------------------------------------------------------------- utilidades

        private void ExigirAbierta()
        {
            if (_clave is null) throw new InvalidOperationException("La bóveda está bloqueada.");
        }

        private static void ValidarRuta(string ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta) || !Path.IsPathRooted(ruta)) throw new ArgumentException("La ruta de la bóveda debe ser absoluta.", nameof(ruta));
        }

        private static void ValidarContrasenaMaestra(string c)
        {
            if (c is null || c.Length < LongitudMinimaDeContrasenaMaestra)
                throw new ArgumentException("La contraseña maestra debe tener al menos " + LongitudMinimaDeContrasenaMaestra + " caracteres.", nameof(c));
        }

        private static void ValidarTexto(string? t, string nombre, bool obligatorio, int maximo = 1_000)
        {
            if (t is null) throw new ArgumentNullException(nombre);
            if (obligatorio && string.IsNullOrWhiteSpace(t)) throw new ArgumentException("No puede estar vacío.", nombre);
            if (t.Length > maximo) throw new ArgumentException("Es demasiado largo (máximo " + maximo + ").", nombre);
        }

        private static void TryBorrar(string ruta)
        {
            try { if (File.Exists(ruta)) File.Delete(ruta); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }

        private Task PublicarAsync(NexoEvent e) => PublicarSinInstanciaAsync(_reportes, e);

        /// <summary>Los reportes son de mejor esfuerzo: que no se pueda escribir una nota nunca impide abrir ni guardar la boveda.</summary>
        private static async Task PublicarSinInstanciaAsync(IReportWriter? reportes, NexoEvent e)
        {
            if (reportes is null) return;
            try { await reportes.EscribirAsync(e).ConfigureAwait(false); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException) { }
        }

        private sealed class ContenidoDeBoveda
        {
            public int Version { get; set; }
            public List<EntradaDeBoveda>? Entradas { get; set; }
        }
    }
}
