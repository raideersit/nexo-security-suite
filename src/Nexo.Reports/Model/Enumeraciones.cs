namespace Nexo.Reports.Model
{
    /// <summary>Modulo que origino el evento. Determina la carpeta destino en el vault.</summary>
    public enum ModuloOrigen
    {
        Amenazas,
        Privacidad,
        Identidad,
        Limpieza,
        Sistema
    }

    /// <summary>
    /// Severidad del evento. Se escribe en el front matter y como etiqueta
    /// (nexo/severidad/alta) para poder filtrar desde el panel de busqueda de Obsidian.
    /// </summary>
    public enum Severidad
    {
        Info,
        Baja,
        Media,
        Alta,
        Critica
    }

    /// <summary>Que hizo Nexo al respecto. Nunca es nulo: si no hizo nada, es Ninguna.</summary>
    public enum Accion
    {
        Ninguna,
        Registrada,
        Bloqueada,
        Cuarentena,
        Eliminada,
        Restaurada,
        Omitida,
        PendienteConfirmacion
    }

    /// <summary>
    /// Tipo de entidad a la que apunta un wikilink. Cada entidad tiene su propia
    /// nota, y es lo que convierte el vault en un grafo util: al abrir la nota de
    /// un archivo se ven, por backlinks, todos los eventos que lo tocaron.
    /// </summary>
    public enum TipoEntidad
    {
        Archivo,
        Proceso,
        Aplicacion,
        Dispositivo,
        Dominio,
        Cuenta
    }
}
