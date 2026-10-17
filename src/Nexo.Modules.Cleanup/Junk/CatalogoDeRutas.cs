using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nexo.Modules.Cleanup.Junk
{
    /// <summary>
    /// Carga el catalogo de rutas limpiables.
    ///
    /// Esta en JSON y no en codigo porque la lista cambia con cada version de
    /// Windows y con cada navegador nuevo, y porque poder revisarla de un vistazo
    /// —sin compilar— es parte de la seguridad: es la lista de lo que el programa
    /// tiene permiso para destruir.
    /// </summary>
    public sealed class CatalogoDeRutas
    {
        private static readonly JsonSerializerOptions Opciones = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
        };

        public CatalogoDeRutas(IReadOnlyList<ReglaDeLimpieza> reglas) => Reglas = reglas;

        public IReadOnlyList<ReglaDeLimpieza> Reglas { get; }

        private sealed class Documento
        {
            [JsonPropertyName("version")] public int Version { get; set; }
            [JsonPropertyName("reglas")] public List<ReglaDeLimpieza> Reglas { get; set; } = new List<ReglaDeLimpieza>();
        }

        /// <summary>Carga el catalogo embebido en el ensamblado.</summary>
        public static CatalogoDeRutas Predeterminado()
        {
            Assembly asm = typeof(CatalogoDeRutas).Assembly;
            const string recurso = "Nexo.Modules.Cleanup.Junk.Data.cleanup-paths.json";

            using Stream? s = asm.GetManifestResourceStream(recurso)
                ?? throw new InvalidOperationException(
                    "No se encontro el catalogo embebido '" + recurso + "'. " +
                    "Revisa el <EmbeddedResource> del csproj.");

            return Cargar(s);
        }

        public static CatalogoDeRutas CargarDesdeArchivo(string ruta)
        {
            using FileStream fs = File.OpenRead(ruta);
            return Cargar(fs);
        }

        private static CatalogoDeRutas Cargar(Stream s)
        {
            Documento doc = JsonSerializer.Deserialize<Documento>(s, Opciones)
                ?? throw new InvalidDataException("El catalogo de rutas esta vacio o mal formado.");

            Validar(doc.Reglas);
            return new CatalogoDeRutas(doc.Reglas);
        }

        /// <summary>
        /// Un catalogo mal escrito es la forma mas probable de que este modulo
        /// borre algo que no debe, asi que se valida al cargar y se falla temprano.
        /// </summary>
        private static void Validar(List<ReglaDeLimpieza> reglas)
        {
            var vistos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (ReglaDeLimpieza r in reglas)
            {
                if (string.IsNullOrWhiteSpace(r.Id))
                    throw new InvalidDataException("Hay una regla sin 'id' en el catalogo.");
                if (!vistos.Add(r.Id))
                    throw new InvalidDataException("Id de regla duplicado en el catalogo: " + r.Id);
                if (string.IsNullOrWhiteSpace(r.Categoria))
                    throw new InvalidDataException("La regla '" + r.Id + "' no declara categoria.");

                // Una subruta vacia anclaria la regla a la carpeta base completa:
                // "limpiar todo %LOCALAPPDATA%" o, peor, "todo %SystemRoot%".
                if (string.IsNullOrWhiteSpace(r.Subruta))
                    throw new InvalidDataException(
                        "La regla '" + r.Id + "' tiene subruta vacia: apuntaria a la carpeta base completa.");

                if (r.Subruta.Contains("..", StringComparison.Ordinal))
                    throw new InvalidDataException(
                        "La regla '" + r.Id + "' contiene '..' en la subruta.");

                if (Path.IsPathRooted(r.Subruta))
                    throw new InvalidDataException(
                        "La regla '" + r.Id + "' usa una ruta absoluta; debe ser relativa a la base.");
            }
        }
    }
}
