using System;
using System.Collections.Generic;
using System.IO;
using Nexo.Modules.Cleanup.Junk;

namespace Nexo.Modules.Cleanup.Platform
{
    /// <summary>
    /// Traduce las bases simbolicas del catalogo a rutas reales del equipo.
    /// Aislado aqui para que el catalogo nunca contenga rutas absolutas y para
    /// poder sustituirlas por un corpus sintetico en las pruebas.
    /// </summary>
    public static class ResolutorDeBases
    {
        /// <summary>Rutas reales de Windows.</summary>
        public static IReadOnlyDictionary<BaseDeRuta, string> DelSistema()
        {
            var d = new Dictionary<BaseDeRuta, string>
            {
                [BaseDeRuta.LocalAppData] = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                [BaseDeRuta.RoamingAppData] = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                [BaseDeRuta.UserProfile] = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                [BaseDeRuta.ProgramData] = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            };

            // SpecialFolder.Windows no existe en todas las plataformas; se resuelve
            // por variable de entorno, que es lo que usa el propio Windows.
            string? sistema = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(sistema)) d[BaseDeRuta.SystemRoot] = sistema;

            return d;
        }

        /// <summary>Todas las bases apuntando dentro de una carpeta de pruebas.</summary>
        public static IReadOnlyDictionary<BaseDeRuta, string> DeCorpus(string raizCorpus)
            => new Dictionary<BaseDeRuta, string>
            {
                [BaseDeRuta.RaizDePrueba] = Path.GetFullPath(raizCorpus)
            };
    }
}
