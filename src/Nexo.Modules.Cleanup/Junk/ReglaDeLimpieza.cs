using System;
using System.Collections.Generic;

namespace Nexo.Modules.Cleanup.Junk
{
    /// <summary>
    /// Carpeta base a la que se ancla una regla. Nunca se escriben rutas absolutas
    /// en el catalogo: el perfil del usuario y la carpeta de Windows cambian de
    /// equipo a equipo, y una ruta literal es un borrado equivocado esperando.
    /// </summary>
    public enum BaseDeRuta
    {
        LocalAppData,
        RoamingAppData,
        UserProfile,
        SystemRoot,
        ProgramData,
        /// <summary>Solo para pruebas contra un corpus sintetico.</summary>
        RaizDePrueba
    }

    public enum NivelRiesgo
    {
        /// <summary>Se puede borrar sin consecuencias visibles. Activo por defecto.</summary>
        Bajo,
        /// <summary>Tiene efecto perceptible (cierra sesiones, ralentiza el primer arranque). Desactivado por defecto.</summary>
        Medio,
        /// <summary>Puede romper funciones de Windows. Nunca se activa automaticamente.</summary>
        Alto
    }

    /// <summary>Una entrada del catalogo de rutas limpiables.</summary>
    public sealed class ReglaDeLimpieza
    {
        public string Id { get; set; } = "";
        public string Categoria { get; set; } = "";
        public string Nombre { get; set; } = "";
        public BaseDeRuta Base { get; set; } = BaseDeRuta.LocalAppData;

        /// <summary>
        /// Subruta bajo la base. Admite un unico comodin '*' por segmento, para
        /// casos como los perfiles de Firefox (Profiles\*\cache2).
        /// </summary>
        public string Subruta { get; set; } = "";

        public string Patron { get; set; } = "*";
        public bool Recursivo { get; set; } = true;
        public bool RequiereAdmin { get; set; }
        public NivelRiesgo Riesgo { get; set; } = NivelRiesgo.Bajo;

        /// <summary>Dias que debe tener un archivo sin modificarse para ser candidato.</summary>
        public int AntiguedadMinimaDias { get; set; } = 1;

        public List<string> Excluir { get; set; } = new List<string>();

        /// <summary>Explicacion que se muestra al usuario en la vista previa.</summary>
        public string Nota { get; set; } = "";

        /// <summary>Solo las reglas de riesgo bajo se marcan solas en la vista previa.</summary>
        public bool ActivaPorDefecto => Riesgo == NivelRiesgo.Bajo;

        public TimeSpan Antiguedad => TimeSpan.FromDays(Math.Max(0, AntiguedadMinimaDias));
    }
}
