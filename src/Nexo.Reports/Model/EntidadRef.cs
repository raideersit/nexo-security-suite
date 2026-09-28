using System;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Referencia a una entidad del mundo real (un archivo, un proceso, un disco).
    /// El ReportWriter crea una nota por entidad la primera vez que la ve y enlaza
    /// a ella con un wikilink; a partir de ahi Obsidian acumula los backlinks solo.
    /// </summary>
    public sealed class EntidadRef
    {
        public EntidadRef(TipoEntidad tipo, string nombre, string? detalle = null)
        {
            if (string.IsNullOrWhiteSpace(nombre))
                throw new ArgumentException("El nombre de la entidad no puede ser vacio.", nameof(nombre));

            Tipo = tipo;
            Nombre = nombre.Trim();
            Detalle = detalle;
        }

        public TipoEntidad Tipo { get; }

        /// <summary>
        /// Identificador legible y estable. Para archivos es el nombre base
        /// (factura.pdf), no la ruta completa: asi todas las copias del mismo
        /// archivo convergen en una nota y el grafo tiene sentido.
        /// </summary>
        public string Nombre { get; }

        /// <summary>Contexto opcional que se guarda en la nota de la entidad (ruta, PID, fabricante).</summary>
        public string? Detalle { get; }

        public static EntidadRef Archivo(string nombreArchivo, string? rutaCompleta = null)
            => new EntidadRef(TipoEntidad.Archivo, nombreArchivo, rutaCompleta);

        public static EntidadRef Proceso(string nombreProceso, string? detalle = null)
            => new EntidadRef(TipoEntidad.Proceso, nombreProceso, detalle);

        public static EntidadRef Aplicacion(string nombreApp, string? detalle = null)
            => new EntidadRef(TipoEntidad.Aplicacion, nombreApp, detalle);

        public static EntidadRef Dispositivo(string idDispositivo, string? detalle = null)
            => new EntidadRef(TipoEntidad.Dispositivo, idDispositivo, detalle);

        public static EntidadRef Dominio(string dominio, string? detalle = null)
            => new EntidadRef(TipoEntidad.Dominio, dominio, detalle);

        public static EntidadRef Cuenta(string cuentaRedactada, string? detalle = null)
            => new EntidadRef(TipoEntidad.Cuenta, cuentaRedactada, detalle);
    }
}
