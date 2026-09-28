using System.Collections.Generic;
using Nexo.Modules.Cleanup.Abstractions;

namespace Nexo.Modules.Cleanup.Platform
{
    /// <summary>
    /// Doble de prueba: cuenta lo que se borraria sin tocar el disco.
    ///
    /// Es el borrador por defecto del arnes de aceptacion. Permite ejercitar el
    /// flujo completo —catalogo, guardia, vista previa, token, reporte— sin
    /// arriesgar un solo archivo, que es exactamente lo que hace falta mientras
    /// se afina el catalogo de rutas.
    /// </summary>
    public sealed class BorradorSimulado : IBorrador
    {
        public bool EsReversible => true;

        public List<string> Registro { get; } = new List<string>();

        public ResultadoBorrado Borrar(IReadOnlyList<(string Ruta, long Bytes)> elementos)
        {
            long bytes = 0;
            foreach (var (ruta, tamano) in elementos)
            {
                Registro.Add(ruta);
                bytes += tamano;
            }
            return new ResultadoBorrado(elementos.Count, bytes, new List<string>());
        }
    }
}
