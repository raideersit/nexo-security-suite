using System;
using System.IO;
using System.Text;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Escritura atomica: archivo temporal en la misma carpeta y luego reemplazo.
    /// Importa porque el servicio corre como LocalSystem y puede ser detenido por
    /// el SCM en mitad de una escritura; una nota a medias rompe el front matter y
    /// Obsidian deja de indexar el archivo entero.
    /// </summary>
    internal static class AtomicFile
    {
        // Sin BOM: es lo que espera Obsidian y evita un caracter invisible antes
        // del '---' que invalidaria el front matter.
        private static readonly UTF8Encoding Utf8SinBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        public static void EscribirTexto(string rutaDestino, string contenido)
        {
            string carpeta = Path.GetDirectoryName(rutaDestino)
                             ?? throw new ArgumentException("Ruta sin carpeta.", nameof(rutaDestino));
            Directory.CreateDirectory(carpeta);

            // El temporal va en la MISMA carpeta: un move entre volumenes no es atomico.
            string temporal = Path.Combine(
                carpeta,
                "~" + Path.GetFileNameWithoutExtension(rutaDestino) + "." +
                Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");

            try
            {
                using (var fs = new FileStream(temporal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var sw = new StreamWriter(fs, Utf8SinBom))
                {
                    sw.Write(contenido);
                    sw.Flush();
                    fs.Flush(flushToDisk: true);
                }

                if (File.Exists(rutaDestino))
                {
                    // File.Replace es atomico en NTFS y preserva la ACL del destino,
                    // que es justo lo que queremos: la carpeta esta restringida al
                    // usuario dueno y no debe heredar los permisos del temporal.
                    File.Replace(temporal, rutaDestino, destinationBackupFileName: null);
                }
                else
                {
                    File.Move(temporal, rutaDestino);
                }
            }
            catch
            {
                TryDelete(temporal);
                throw;
            }
        }

        public static string? LeerTextoSiExiste(string ruta)
            => File.Exists(ruta) ? File.ReadAllText(ruta, Utf8SinBom) : null;

        private static void TryDelete(string ruta)
        {
            try { if (File.Exists(ruta)) File.Delete(ruta); }
            catch (IOException) { /* el temporal quedara huerfano; no vale fallar por esto */ }
            catch (UnauthorizedAccessException) { }
        }
    }
}
