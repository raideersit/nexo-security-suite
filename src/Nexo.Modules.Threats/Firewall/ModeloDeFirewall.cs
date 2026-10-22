using System;
using System.Collections.Generic;

namespace Nexo.Modules.Threats.Firewall
{
    public enum DireccionDeRegla
    {
        Entrante,
        Saliente
    }

    public enum AccionDeRegla
    {
        Bloquear,
        Permitir
    }

    /// <summary>Perfiles de red de Windows. Se combinan como banderas.</summary>
    [Flags]
    public enum PerfilesDeRed
    {
        Ninguno = 0,
        Dominio = 1,
        Privado = 2,
        Publico = 4,
        Todos = Dominio | Privado | Publico
    }

    /// <summary>
    /// Una regla del Firewall de Windows, reducida a lo que Nexo necesita leer y
    /// escribir. Es un registro inmutable: modificarla es crear otra.
    /// </summary>
    public sealed record ReglaDeFirewall(
        string Nombre,
        string? RutaApp,
        DireccionDeRegla Direccion,
        AccionDeRegla Accion,
        PerfilesDeRed Perfiles,
        bool Habilitada,
        string? Grupo = null,
        string? Descripcion = null,
        int? Protocolo = null,
        string? TiposIcmp = null)
    {
        /// <summary>
        /// Grupo con el que Nexo marca TODAS sus reglas. Es la frontera de lo que el
        /// administrador puede modificar: una regla que no esta en este grupo
        /// pertenece a Windows o a otro programa y Nexo no la toca.
        /// </summary>
        public const string GrupoNexo = "Nexo Security Suite";

        public const string PrefijoNombre = "Nexo: ";

        public bool EsDeNexo
            => string.Equals(Grupo, GrupoNexo, StringComparison.Ordinal)
               && Nombre.StartsWith(PrefijoNombre, StringComparison.Ordinal);
    }

    /// <summary>Estado de un perfil de red del firewall (solo lectura).</summary>
    public sealed record PoliticaDePerfil(
        PerfilesDeRed Perfil,
        bool FirewallActivo,
        AccionDeRegla EntradaPorDefecto,
        AccionDeRegla SalidaPorDefecto);

    /// <summary>
    /// Acceso al Firewall de Windows. Se abstrae porque la implementacion real es
    /// COM (INetFwPolicy2) y las pruebas necesitan un almacen en memoria que pueda
    /// fallar a voluntad.
    /// </summary>
    public interface IAlmacenDeFirewall
    {
        IReadOnlyList<ReglaDeFirewall> Enumerar();

        /// <exception cref="UnauthorizedAccessException">Sin permisos de administrador.</exception>
        void Agregar(ReglaDeFirewall regla);

        /// <exception cref="UnauthorizedAccessException">Sin permisos de administrador.</exception>
        void Eliminar(string nombre);

        /// <exception cref="UnauthorizedAccessException">Sin permisos de administrador.</exception>
        void Habilitar(string nombre, bool habilitada);

        IReadOnlyList<PoliticaDePerfil> LeerPoliticas();
    }
}
