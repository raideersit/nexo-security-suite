using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Ransomware
{
    /// <summary>
    /// Un perfil de usuario visto por el servicio. <c>CarpetasDelShell</c>: los valores SIN expandir de «User Shell Folders»
    /// (Personal, Desktop, My Pictures) si el perfil está abierto (su parte del registro está cargada); null si no.
    /// </summary>
    public sealed record PerfilParaSenuelos(string Sid, string Carpeta, IReadOnlyDictionary<string, string>? CarpetasDelShell);

    /// <summary>
    /// Qué carpetas reciben señuelo: Documentos, Escritorio e Imágenes de cada perfil real, que es lo que un ransomware cifra
    /// primero. Lógica pura: la lectura del registro está en Nexo.Modules.Threats.Windows.
    /// </summary>
    public static class CarpetasParaSenuelos
    {
        /// <summary>(valor en «User Shell Folders», carpeta por omisión dentro del perfil).</summary>
        public static readonly IReadOnlyList<(string Clave, string PorOmision)> Carpetas = new[]
        {
            ("Personal", "Documents"),
            ("Desktop", "Desktop"),
            ("My Pictures", "Pictures")
        };

        private static readonly Regex Variable = new Regex("%[^%]+%", RegexOptions.CultureInvariant);

        public static IReadOnlyList<string> Elegir(IEnumerable<PerfilParaSenuelos> perfiles, out IReadOnlyList<CarpetaSinSenuelo> descartadas)
        {
            var elegidas = new List<string>();
            var fuera = new List<CarpetaSinSenuelo>();

            foreach (PerfilParaSenuelos p in perfiles)
            {
                string perfil = p.Carpeta.TrimEnd('\\', '/');
                if (!EsRutaLocal(perfil)) { fuera.Add(new CarpetaSinSenuelo(p.Carpeta, "perfil " + p.Sid + " sin una carpeta local")); continue; }

                foreach ((string clave, string porOmision) in Carpetas)
                {
                    string ruta;
                    if (p.CarpetasDelShell is { } shell && shell.TryGetValue(clave, out string? valor) && !string.IsNullOrWhiteSpace(valor))
                    {
                        ruta = Regex.Replace(valor.Trim(), "%USERPROFILE%", perfil.Replace("$", "$$"), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        if (Variable.IsMatch(ruta)) { fuera.Add(new CarpetaSinSenuelo(valor, "la ruta usa variables que el servicio no puede resolver por ese usuario")); continue; }
                    }
                    else ruta = Path.Combine(perfil, porOmision);

                    ruta = ruta.TrimEnd('\\', '/');
                    if (!EsRutaLocal(ruta)) { fuera.Add(new CarpetaSinSenuelo(ruta, "carpeta de red o ruta no local: no se ponen señuelos fuera de este equipo")); continue; }
                    if (EnOneDrive(ruta)) { fuera.Add(new CarpetaSinSenuelo(ruta, "carpeta de OneDrive: el señuelo se subiría a la nube y la sincronización podría dar falsas alarmas")); continue; }
                    if (!elegidas.Contains(ruta, StringComparer.OrdinalIgnoreCase)) elegidas.Add(ruta);
                }
            }

            descartadas = fuera;
            return elegidas;
        }

        /// <summary>«C:\...» con letra de unidad. Rechaza UNC («\\servidor»), rutas relativas y «\\?\».</summary>
        public static bool EsRutaLocal(string ruta)
            => ruta.Length >= 3 && char.IsAsciiLetter(ruta[0]) && ruta[1] == ':' && (ruta[2] == '\\' || ruta[2] == '/');

        /// <summary>Algún tramo de la ruta es «OneDrive» u «OneDrive - Algo» (la carpeta que crea OneDrive para cada cuenta).</summary>
        public static bool EnOneDrive(string ruta)
            => ruta.Split('\\', '/').Any(t => t.Equals("OneDrive", StringComparison.OrdinalIgnoreCase)
                                              || t.StartsWith("OneDrive - ", StringComparison.OrdinalIgnoreCase));
    }
}
