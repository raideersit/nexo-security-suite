using System;
using System.IO;
using System.Security.Cryptography;

namespace Nexo.Modules.Cleanup.Trituracion
{
    /// <summary>
    /// Las operaciones de bajo nivel del triturador, separadas para poder probarlas
    /// una a una: sobrescribir, renombrar y borrar.
    ///
    /// Una sola pasada, con datos aleatorios. NIST SP 800-88 Rev. 1 considera que
    /// una sobrescritura basta en discos magneticos modernos; mas pasadas solo
    /// desgastan el disco (ver Salida 4, §1.7).
    /// </summary>
    public static class Sobrescritor
    {
        private const int TamanoBloque = 64 * 1024;

        /// <summary>
        /// Sobrescribe todo el contenido con bytes aleatorios y fuerza la escritura
        /// a disco. No cambia el largo del archivo.
        /// </summary>
        /// <param name="flujo">Abierto con escritura y, idealmente, FileShare.None.</param>
        public static void Sobrescribir(FileStream flujo)
        {
            if (flujo is null) throw new ArgumentNullException(nameof(flujo));
            if (!flujo.CanWrite) throw new ArgumentException("El flujo no admite escritura.", nameof(flujo));

            long total = flujo.Length;
            flujo.Position = 0;

            byte[] bloque = new byte[TamanoBloque];
            long restante = total;
            while (restante > 0)
            {
                int n = (int)Math.Min(restante, bloque.Length);
                RandomNumberGenerator.Fill(bloque.AsSpan(0, n));
                flujo.Write(bloque, 0, n);
                restante -= n;
            }

            // flush(true) = FlushFileBuffers: sin esto los datos pueden quedarse
            // en la cache del sistema y el "borrado" no habria llegado al disco.
            flujo.Flush(flushToDisk: true);
        }

        /// <summary>
        /// Renombra el archivo a nombres aleatorios (sin extension, mismo largo) para
        /// que el nombre original no sobreviva en el directorio. Devuelve la ruta final.
        /// </summary>
        public static string Renombrar(string ruta, int veces)
        {
            string carpeta = Path.GetDirectoryName(ruta)
                             ?? throw new ArgumentException("Ruta sin carpeta.", nameof(ruta));
            string actual = ruta;

            for (int i = 0; i < veces; i++)
            {
                string nuevo;
                do
                {
                    nuevo = Path.Combine(carpeta, NombreAleatorio(Math.Max(8, Path.GetFileName(ruta).Length)));
                } while (File.Exists(nuevo) || Directory.Exists(nuevo));

                File.Move(actual, nuevo);
                actual = nuevo;
            }
            return actual;
        }

        /// <summary>Trunca a cero bytes y borra. El truncado oculta el largo original en el directorio.</summary>
        public static void TruncarYBorrar(string ruta)
        {
            var info = new FileInfo(ruta);
            if (info.IsReadOnly) info.IsReadOnly = false;

            using (var f = new FileStream(ruta, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                f.SetLength(0);
                f.Flush(flushToDisk: true);
            }
            File.Delete(ruta);
        }

        private static string NombreAleatorio(int largo)
        {
            const string alfabeto = "abcdefghijklmnopqrstuvwxyz0123456789";
            Span<char> c = stackalloc char[largo];
            for (int i = 0; i < c.Length; i++)
                c[i] = alfabeto[RandomNumberGenerator.GetInt32(alfabeto.Length)];
            return new string(c);
        }
    }
}
