using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Seguridad;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Trituracion
{
    /// <summary>
    /// Triturador de archivos que el usuario elige a mano.
    ///
    /// Mismo contrato que <c>LimpiadorDeBasura</c>: dos fases y ningun camino que
    /// salte la primera. Aqui pesa mas, porque el borrado es irreversible.
    ///
    ///   1. PrepararVistaPrevia -> lista validada + limites reales + token.
    ///   2. EjecutarAsync       -> exige el token y revalida cada archivo.
    ///
    /// Que garantiza y que NO: ver las advertencias que genera la vista previa.
    /// En resumen, evita que las herramientas normales de recuperacion encuentren
    /// el archivo, pero en NTFS nunca es un borrado completo (Salida 4, §1.7).
    /// </summary>
    public sealed class Triturador
    {
        /// <summary>
        /// Por debajo de este tamano NTFS suele guardar el contenido dentro del
        /// propio registro de la $MFT, donde sobrescribir el archivo no llega.
        /// </summary>
        private const long UmbralResidente = 700;

        private const int Pasadas = 1;
        private const int RenombresAleatorios = 3;

        private readonly IReportWriter _reportes;
        private readonly IDetectorDeMedio _medio;
        private readonly string _carpetaDeWindows;

        public Triturador(IReportWriter reportes, IDetectorDeMedio? medio = null)
        {
            _reportes = reportes;
            _medio = medio ?? new MedioDesconocido();
            _carpetaDeWindows = SinSeparadorFinal(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        }

        // ============================================================
        //  FASE 1 — VISTA PREVIA
        // ============================================================
        public Task<VistaPreviaTrituracion> PrepararVistaPreviaAsync(
            IEnumerable<string> rutas,
            CancellationToken ct = default)
        {
            DateTimeOffset ahora = DateTimeOffset.Now;

            var elementos = new List<ElementoATriturar>();
            var omitidas = new List<string>();
            var vistas = new HashSet<string>(
                OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

            foreach (string ruta in rutas)
            {
                ct.ThrowIfCancellationRequested();

                string? motivo = Validar(ruta, ahora, out string canonica, out FileInfo? info);
                if (motivo is not null) { omitidas.Add(canonica + " — " + motivo); continue; }
                if (!vistas.Add(canonica)) continue;   // la misma ruta dos veces: una sola vez

                elementos.Add(new ElementoATriturar(
                    canonica, info!.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero)));
            }

            MedioDeAlmacenamiento medio = PeorMedio(elementos);
            var advertencias = ConstruirAdvertencias(elementos, medio);
            var token = TokenConfirmacion.Emitir(elementos.Select(e => e.Huella), ahora);

            return Task.FromResult(new VistaPreviaTrituracion(elementos, omitidas, advertencias, medio, token));
        }

        /// <summary>
        /// Devuelve null si la ruta es triturable, o el motivo del rechazo. El guardia
        /// se construye con la carpeta del propio archivo como raiz: el usuario eligio
        /// el archivo, asi que la lista blanca no aplica, pero el resto de capas
        /// (enlaces, uniones, sistema, lista negra) si.
        /// </summary>
        private string? Validar(string ruta, DateTimeOffset ahora, out string canonica, out FileInfo? info)
        {
            info = null;
            canonica = ruta ?? "";

            if (string.IsNullOrWhiteSpace(ruta)) return "ruta vacia";

            try { canonica = Path.GetFullPath(ruta); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            { return "ruta invalida"; }

            string? carpeta = Path.GetDirectoryName(canonica);
            if (string.IsNullOrEmpty(carpeta)) return "ruta sin carpeta";

            if (EstaDentroDe(canonica, _carpetaDeWindows))
                return "esta dentro de la carpeta de Windows";

            GuardiaDeRutas guardia;
            try
            {
                guardia = new GuardiaDeRutas(TimeSpan.Zero, permitirCarpetasDeUsuario: true)
                    .PermitirRaiz(carpeta);
            }
            catch (ArgumentException)
            {
                return "esta en la raiz de un volumen";
            }

            ResultadoValidacion v = guardia.Validar(canonica, ahora);
            if (!v.Aceptada) return v.Motivo.ToString();

            canonica = v.RutaCanonica;
            try { info = new FileInfo(canonica); _ = info.Length; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            { info = null; return ex.GetType().Name; }

            return null;
        }

        private MedioDeAlmacenamiento PeorMedio(List<ElementoATriturar> elementos)
        {
            if (elementos.Count == 0) return MedioDeAlmacenamiento.Desconocido;

            var medios = elementos.Select(e => _medio.Detectar(e.Ruta)).ToList();
            if (medios.All(m => m == MedioDeAlmacenamiento.Hdd)) return MedioDeAlmacenamiento.Hdd;
            if (medios.Any(m => m == MedioDeAlmacenamiento.Ssd)) return MedioDeAlmacenamiento.Ssd;
            return MedioDeAlmacenamiento.Desconocido;
        }

        private static List<string> ConstruirAdvertencias(List<ElementoATriturar> elementos, MedioDeAlmacenamiento medio)
        {
            var a = new List<string>();

            if (medio == MedioDeAlmacenamiento.Ssd)
                a.Add("El disco es un SSD: la sobrescritura NO garantiza el borrado. El controlador reparte " +
                      "las escrituras y los bloques originales pueden seguir intactos. La garantia real es " +
                      "BitLocker activado desde antes, o un Secure Erase del disco completo.");
            else if (medio == MedioDeAlmacenamiento.Desconocido)
                a.Add("No se pudo determinar si el disco es SSD o magnetico; se asume el caso peor. " +
                      "En un SSD la sobrescritura no garantiza el borrado.");

            int residentes = elementos.Count(e => e.Bytes < UmbralResidente);
            if (residentes > 0)
                a.Add(residentes.ToString(CultureInfo.InvariantCulture) + " archivo(s) de menos de ~700 bytes: " +
                      "NTFS suele guardarlos dentro de la $MFT y sobrescribir el archivo no llega a ese registro.");

            a.Add("Si hay puntos de restauracion (VSS), pueden existir copias anteriores del archivo; " +
                  "el $LogFile y el journal pueden conservar fragmentos de metadatos.");
            a.Add("Lo que si garantiza: que las herramientas normales de recuperacion no lo encuentren.");
            return a;
        }

        // ============================================================
        //  FASE 2 — EJECUCION
        // ============================================================
        /// <exception cref="InvalidOperationException">Token ajeno o caducado.</exception>
        public async Task<ResultadoBorrado> EjecutarAsync(
            VistaPreviaTrituracion vista,
            TokenConfirmacion token,
            CancellationToken ct = default)
        {
            if (vista is null) throw new ArgumentNullException(nameof(vista));
            if (token is null) throw new ArgumentNullException(nameof(token));

            DateTimeOffset ahora = DateTimeOffset.Now;

            if (!token.EsValidoPara(vista.Elementos.Select(e => e.Huella), ahora))
                throw new InvalidOperationException(
                    "El token de confirmacion no corresponde a esta vista previa o ya caduco " +
                    "(vigencia " + TokenConfirmacion.Vigencia.TotalMinutes + " min). " +
                    "El usuario debe aprobar exactamente la lista que se va a triturar.");

            int triturados = 0;
            long bytes = 0;
            var omitidos = new List<string>();

            foreach (ElementoATriturar e in vista.Elementos)
            {
                ct.ThrowIfCancellationRequested();

                // Segunda pasada: el disco pudo cambiar desde la vista previa.
                string? motivo = Validar(e.Ruta, ahora, out string canonica, out FileInfo? info);
                if (motivo is not null) { omitidos.Add(e.Ruta + " — " + motivo); continue; }

                if (info!.Length != e.Bytes
                    || new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero) != e.Modificado)
                {
                    omitidos.Add(e.Ruta + " — cambio desde la vista previa");
                    continue;
                }

                string? fallo = TriturarUno(canonica, e.Bytes);
                if (fallo is not null) { omitidos.Add(e.Ruta + " — " + fallo); continue; }

                triturados++;
                bytes += e.Bytes;

                MedioDeAlmacenamiento medio = _medio.Detectar(e.Ruta);
                // Desconocido se trata como SSD: ante la duda, la advertencia se muestra.
                NexoEvent ev = Eventos.Limpieza.Triturado(
                    e.Ruta, e.Bytes, Pasadas, esSsd: medio != MedioDeAlmacenamiento.Hdd);
                await _reportes.EscribirAsync(ev, ct).ConfigureAwait(false);
            }

            return new ResultadoBorrado(triturados, bytes, omitidos);
        }

        /// <summary>
        /// Devuelve null si el archivo quedo triturado, o el motivo. Distingue "no se
        /// toco" de "se sobrescribio pero sigue ahi": en el segundo caso el contenido
        /// original ya esta destruido, y el usuario debe saberlo.
        /// </summary>
        private static string? TriturarUno(string ruta, long bytesEsperados)
        {
            FileStream flujo;
            try
            {
                var info = new FileInfo(ruta);
                if (info.IsReadOnly) info.IsReadOnly = false;

                // FileShare.None: si otro proceso lo tiene abierto, falla aqui y el
                // archivo queda intacto. Es lo habitual en Windows, no una anomalia.
                flujo = new FileStream(ruta, FileMode.Open, FileAccess.Write, FileShare.None,
                                       bufferSize: 4096, FileOptions.WriteThrough);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return "no se pudo abrir en exclusiva (¿en uso?), no se modifico: " + ex.GetType().Name;
            }

            try
            {
                using (flujo)
                {
                    if (flujo.Length != bytesEsperados)
                        return "cambio de tamano al abrirlo, no se modifico";
                    Sobrescritor.Sobrescribir(flujo);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return "fallo durante la sobrescritura, el contenido puede estar a medias: " + ex.GetType().Name;
            }

            try
            {
                string renombrado = Sobrescritor.Renombrar(ruta, RenombresAleatorios);
                Sobrescritor.TruncarYBorrar(renombrado);
                return null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return "contenido SOBRESCRITO pero el archivo no se pudo borrar: " + ex.GetType().Name;
            }
        }

        private static string SinSeparadorFinal(string ruta)
            => string.IsNullOrEmpty(ruta) ? "" : Path.TrimEndingDirectorySeparator(ruta);

        private static bool EstaDentroDe(string ruta, string carpeta)
        {
            if (carpeta.Length == 0 || ruta.Length <= carpeta.Length) return false;
            var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return ruta.StartsWith(carpeta, cmp)
                   && (ruta[carpeta.Length] == Path.DirectorySeparatorChar
                       || ruta[carpeta.Length] == Path.AltDirectorySeparatorChar);
        }
    }
}
