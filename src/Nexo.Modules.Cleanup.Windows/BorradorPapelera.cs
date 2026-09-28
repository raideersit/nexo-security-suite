using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Native.Shell;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Borrador por DEFECTO en Windows: envia a la Papelera de reciclaje.
    ///
    /// Es la unica red de seguridad real ante un error en el catalogo de rutas o
    /// un fallo del guardia. Cuesta espacio en disco temporalmente y a cambio
    /// hace reversible la operacion mas peligrosa de todo Nexo.
    ///
    /// El borrado permanente existe (BorradorReal) pero debe ser una eleccion
    /// explicita del usuario, nunca el valor por omision.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class BorradorPapelera : IBorrador
    {
        /// <summary>
        /// Tamano maximo que se manda a la Papelera de una sola vez. Por encima,
        /// se trocea: SHFileOperation con decenas de miles de rutas en una cadena
        /// puede agotar el buffer interno del shell.
        /// </summary>
        private const int TamanoLote = 1000;

        public bool EsReversible => true;

        public ResultadoBorrado Borrar(IReadOnlyList<(string Ruta, long Bytes)> elementos)
        {
            int eliminados = 0;
            long bytes = 0;
            var omitidos = new List<string>();

            for (int inicio = 0; inicio < elementos.Count; inicio += TamanoLote)
            {
                int fin = Math.Min(inicio + TamanoLote, elementos.Count);

                var rutas = new List<string>(fin - inicio);
                var tamanos = new List<long>(fin - inicio);
                long bytesLote = 0;
                for (int i = inicio; i < fin; i++)
                {
                    // Reconfirmar la existencia justo antes: el shell falla el lote
                    // completo si una sola ruta no existe.
                    if (!File.Exists(elementos[i].Ruta))
                    {
                        omitidos.Add(elementos[i].Ruta + " — desaparecio antes del borrado");
                        continue;
                    }
                    rutas.Add(elementos[i].Ruta);
                    tamanos.Add(elementos[i].Bytes);
                    bytesLote += elementos[i].Bytes;
                }

                if (rutas.Count == 0) continue;

                (int codigo, bool abortado) = ShellFileOperations.EnviarAPapelera(rutas.ToArray());

                if (codigo == 0 && !abortado)
                {
                    eliminados += rutas.Count;
                    bytes += bytesLote;
                    continue;
                }

                // El shell no dice QUE ruta del lote fallo, solo que el lote fallo.
                // Se reintenta de una en una para no perder el resto del lote y
                // poder nombrar al culpable en el reporte.
                for (int i = 0; i < rutas.Count; i++)
                {
                    (int c, bool a) = ShellFileOperations.EnviarAPapelera(new[] { rutas[i] });
                    if (c == 0 && !a)
                    {
                        eliminados++;
                        // El tamano se toma de la vista previa, no del disco: el
                        // archivo ya esta en la Papelera y consultarlo devolveria
                        // FileNotFoundException, dejando el contador a cero.
                        bytes += tamanos[i];
                    }
                    else
                    {
                        omitidos.Add(rutas[i] + " — SHFileOperation devolvio 0x" +
                                     c.ToString("X", System.Globalization.CultureInfo.InvariantCulture));
                    }
                }
            }

            return new ResultadoBorrado(eliminados, bytes, omitidos);
        }
    }
}
