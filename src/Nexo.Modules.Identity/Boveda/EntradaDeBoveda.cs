using System;

namespace Nexo.Modules.Identity.Boveda
{
    /// <summary>
    /// Una credencial guardada. Los textos son cadenas de .NET: no se pueden borrar de la memoria a voluntad (el recolector de
    /// basura decide), asi que Nexo solo garantiza borrar la CLAVE al bloquear; ver <see cref="Boveda.Bloquear"/>.
    /// </summary>
    public sealed record EntradaDeBoveda(
        Guid Id,
        string Sitio,
        string Usuario,
        string Contrasena,
        string Notas,
        DateTimeOffset Creada,
        DateTimeOffset Modificada);
}
