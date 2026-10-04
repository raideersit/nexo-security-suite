using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Nexo.Modules.Cleanup.Seguridad
{
    /// <summary>
    /// Ultima linea de defensa antes de borrar. Responde al riesgo L11 del analisis
    /// de viabilidad: un fallo de canonicalizacion o una regla mal escrita en el
    /// catalogo pueden destruir datos del usuario de forma irreversible.
    ///
    /// El modelo es de lista BLANCA, no negra: una ruta solo se acepta si cae dentro
    /// de una raiz explicitamente permitida. La lista negra existe encima como
    /// segunda barrera, para el caso de una raiz permitida demasiado amplia.
    ///
    /// Ninguna comprobacion de aqui sustituye a la vista previa y la confirmacion
    /// del usuario: son capas independientes y las tres deben pasar.
    /// </summary>
    public sealed class GuardiaDeRutas
    {
        /// <summary>
        /// Fragmentos que nunca pueden aparecer en una ruta a borrar, sea cual sea
        /// la raiz permitida. Se comparan por segmento completo, no por subcadena:
        /// "C:\Users\alvaro\Documents" esta prohibido, pero un archivo llamado
        /// "Documents.log" dentro de Temp no lo esta.
        /// </summary>
        private static readonly string[] SegmentosProhibidos =
        {
            "WinSxS",          // borrar aqui rompe Windows Update de forma no reparable
            "System32",
            "SysWOW64",
            "Installer",       // $PatchCache$: rompe desinstalar y reparar MSI
            "Program Files",
            "Program Files (x86)",
            "System Volume Information",
            "$Recycle.Bin",    // se vacia con SHEmptyRecycleBin, nunca a mano
            "Boot",
            "EFI",
            "Recovery",
            "Windows.old",     // se quita con el Liberador de espacio, no borrando
            "Documents", "Documentos",
            "Desktop", "Escritorio",
            "Pictures", "Imagenes", "Imágenes",
            "Videos", "Vídeos",
            "Music", "Musica", "Música",
            "Downloads", "Descargas",
            "OneDrive", "Dropbox", "Google Drive", "iCloudDrive"
        };

        /// <summary>Archivos del sistema que jamas se tocan, por nombre exacto.</summary>
        private static readonly string[] ArchivosProhibidos =
        {
            "pagefile.sys", "hiberfil.sys", "swapfile.sys", "MEMORY.DMP",
            "ntuser.dat", "usrclass.dat", "bootmgr", "BOOTNXT"
        };

        private readonly List<string> _raicesPermitidas = new List<string>();
        private readonly StringComparison _comparacion;
        private readonly TimeSpan _antiguedadMinima;

        /// <param name="antiguedadMinima">
        /// Un archivo modificado hace menos que esto no se borra aunque encaje con
        /// una regla. Evita el caso clasico: borrar el temporal de un instalador
        /// que esta corriendo en ese momento.
        /// </param>
        public GuardiaDeRutas(TimeSpan antiguedadMinima)
        {
            // En Windows las rutas no distinguen mayusculas; en Linux (pruebas) si.
            _comparacion = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            _antiguedadMinima = antiguedadMinima;
        }

        public IReadOnlyList<string> RaicesPermitidas => _raicesPermitidas;

        /// <summary>Registra una raiz dentro de la cual se permite borrar.</summary>
        public GuardiaDeRutas PermitirRaiz(string raiz)
        {
            if (string.IsNullOrWhiteSpace(raiz)) return this;

            string canonica = Canonicalizar(raiz);
            if (canonica.Length == 0) return this;

            // Una raiz que sea la raiz de un volumen ("C:\" o "/") permitiria
            // borrar cualquier cosa: se rechaza de plano.
            string? padre = Path.GetDirectoryName(canonica);
            if (string.IsNullOrEmpty(padre))
                throw new ArgumentException(
                    "No se puede permitir la raiz de un volumen como raiz de limpieza: " + canonica,
                    nameof(raiz));

            if (!_raicesPermitidas.Any(r => string.Equals(r, canonica, StringComparison.Ordinal)))
                _raicesPermitidas.Add(canonica);
            return this;
        }

        /// <summary>
        /// Valida una ruta concreta. Se llama DOS veces por archivo: al construir la
        /// vista previa y otra vez justo antes de borrar (el estado del disco pudo
        /// cambiar entre ambos momentos).
        /// </summary>
        public ResultadoValidacion Validar(string ruta, DateTimeOffset ahora)
        {
            if (string.IsNullOrWhiteSpace(ruta))
                return ResultadoValidacion.Rechazo(MotivoRechazo.RutaVacia, ruta ?? "");

            string canonica;
            try
            {
                canonica = Canonicalizar(ruta);
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                return ResultadoValidacion.Rechazo(MotivoRechazo.RutaInvalida, ruta, ex.Message);
            }

            if (!DentroDeAlgunaRaiz(canonica))
                return ResultadoValidacion.Rechazo(MotivoRechazo.FueraDeRaicesPermitidas, canonica);

            // Un archivo alcanzado A TRAVES de una union o enlace de carpeta no lleva
            // ReparsePoint propio y su ruta textual parece estar dentro de la raiz,
            // pero vive en otro sitio. Se revisa cada carpeta del camino.
            if (CaminoAtraviesaEnlace(canonica))
                return ResultadoValidacion.Rechazo(MotivoRechazo.EsEnlaceSimbolico, canonica);

            if (ContieneSegmentoProhibido(canonica, out string? segmento))
                return ResultadoValidacion.Rechazo(MotivoRechazo.EnListaNegra, canonica, segmento);

            string nombre = Path.GetFileName(canonica);
            foreach (string prohibido in ArchivosProhibidos)
            {
                if (string.Equals(nombre, prohibido, _comparacion))
                    return ResultadoValidacion.Rechazo(MotivoRechazo.EnListaNegra, canonica, prohibido);
            }

            FileAttributes atributos;
            try
            {
                if (Directory.Exists(canonica))
                    return ResultadoValidacion.Rechazo(MotivoRechazo.EsDirectorio, canonica);
                if (!File.Exists(canonica))
                    return ResultadoValidacion.Rechazo(MotivoRechazo.NoExiste, canonica);

                atributos = File.GetAttributes(canonica);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return ResultadoValidacion.Rechazo(MotivoRechazo.RutaInvalida, canonica, ex.Message);
            }

            // Un enlace simbolico o una union (junction) puede apuntar fuera de la
            // raiz permitida. Es el vector clasico para convertir un limpiador en
            // una herramienta de borrado arbitrario.
            if ((atributos & FileAttributes.ReparsePoint) != 0)
                return ResultadoValidacion.Rechazo(MotivoRechazo.EsEnlaceSimbolico, canonica);

            // Sistema + oculto a la vez es la firma de los archivos que Windows
            // gestiona por su cuenta. Solo oculto (comun en caches) si se borra.
            if ((atributos & FileAttributes.System) != 0 && (atributos & FileAttributes.Hidden) != 0)
                return ResultadoValidacion.Rechazo(MotivoRechazo.EsArchivoDeSistema, canonica);

            try
            {
                var escritura = new DateTimeOffset(File.GetLastWriteTimeUtc(canonica), TimeSpan.Zero);
                if (ahora - escritura < _antiguedadMinima)
                    return ResultadoValidacion.Rechazo(MotivoRechazo.DemasiadoReciente, canonica);
            }
            catch (IOException ex)
            {
                return ResultadoValidacion.Rechazo(MotivoRechazo.RutaInvalida, canonica, ex.Message);
            }

            return ResultadoValidacion.Ok(canonica);
        }

        private static string Canonicalizar(string ruta)
            => Path.TrimEndingDirectorySeparator(Path.GetFullPath(ruta));

        /// <summary>
        /// Comparacion por frontera de separador. Sin esto, la raiz "C:\Temp"
        /// aceptaria "C:\Temporal\importante.docx" por simple prefijo de texto.
        /// </summary>
        private bool DentroDeAlgunaRaiz(string canonica)
        {
            foreach (string raiz in _raicesPermitidas)
            {
                if (canonica.Length <= raiz.Length) continue;
                if (!canonica.StartsWith(raiz, _comparacion)) continue;
                char siguiente = canonica[raiz.Length];
                if (siguiente == Path.DirectorySeparatorChar || siguiente == Path.AltDirectorySeparatorChar)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// True si alguna carpeta entre la raiz permitida (excluida: la raiz la
        /// eligio el llamador) y el archivo es un punto de reanalisis. Ante un
        /// error de E/S se responde True: ante la duda, no se borra.
        /// </summary>
        private bool CaminoAtraviesaEnlace(string canonica)
        {
            string raizCoincidente = _raicesPermitidas
                .Where(r => canonica.Length > r.Length
                            && canonica.StartsWith(r, _comparacion)
                            && (canonica[r.Length] == Path.DirectorySeparatorChar
                                || canonica[r.Length] == Path.AltDirectorySeparatorChar))
                .OrderByDescending(r => r.Length)
                .FirstOrDefault() ?? "";
            if (raizCoincidente.Length == 0) return false;

            try
            {
                string? carpeta = Path.GetDirectoryName(canonica);
                while (carpeta is not null && carpeta.Length > raizCoincidente.Length)
                {
                    if ((File.GetAttributes(carpeta) & FileAttributes.ReparsePoint) != 0)
                        return true;
                    carpeta = Path.GetDirectoryName(carpeta);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return true;
            }
            return false;
        }

        private bool ContieneSegmentoProhibido(string canonica, out string? segmentoEncontrado)
        {
            string[] segmentos = canonica.Split(
                new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                StringSplitOptions.RemoveEmptyEntries);

            foreach (string segmento in segmentos)
            {
                foreach (string prohibido in SegmentosProhibidos)
                {
                    if (string.Equals(segmento, prohibido, _comparacion))
                    {
                        segmentoEncontrado = prohibido;
                        return true;
                    }
                }
            }
            segmentoEncontrado = null;
            return false;
        }
    }
}
