using System;
using System.Collections.Generic;
using System.IO;
using Nexo.Modules.Cleanup.Abstractions;

namespace Nexo.Modules.Cleanup.Platform
{
    /// <summary>
    /// Borrado real desde el sistema de archivos, archivo por archivo.
    ///
    /// Es la variante PERMANENTE. En Windows, la opcion por defecto del modulo
    /// debe ser <c>BorradorPapelera</c> (Nexo.Modules.Cleanup.Windows), que usa
    /// SHFileOperation con FOF_ALLOWUNDO y por tanto es reversible: es la unica
    /// red de seguridad real ante un error en el catalogo de rutas.
    ///
    /// Esta clase existe para dos casos: el borrado permanente que el usuario pide
    /// explicitamente, y las pruebas contra un corpus sintetico fuera de Windows.
    /// </summary>
    public sealed class BorradorReal : IBorrador
    {
        public bool EsReversible => false;

        public ResultadoBorrado Borrar(IReadOnlyList<(string Ruta, long Bytes)> elementos)
        {
            int eliminados = 0;
            long bytes = 0;
            var omitidos = new List<string>();

            foreach (var (ruta, tamano) in elementos)
            {
                try
                {
                    // Un archivo de solo lectura hace fallar File.Delete. Quitar el
                    // atributo es seguro aqui: el guardia ya valido que la ruta esta
                    // dentro de una carpeta limpiable y no es de sistema.
                    var info = new FileInfo(ruta);
                    if (info.IsReadOnly) info.IsReadOnly = false;

                    File.Delete(ruta);
                    eliminados++;
                    bytes += tamano;
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    // Lo normal: el archivo esta en uso y Windows lo bloquea.
                    omitidos.Add(ruta + " — " + ex.GetType().Name);
                }
            }

            return new ResultadoBorrado(eliminados, bytes, omitidos);
        }
    }
}
