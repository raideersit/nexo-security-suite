using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;

namespace Nexo.Modules.Threats.Apps
{
    public sealed record Senal(string Id, int Peso, string Motivo);
    public sealed record Combinacion(string Id, IReadOnlyList<string> Requiere, int Peso, string Motivo);
    public sealed record AppConocida(string Paquete, IReadOnlySet<string> Permite, string Nota);

    /// <summary>
    /// Catalogo de senales de riesgo (senales-de-riesgo.json), igual que cleanup-paths.json: se lee de un vistazo, sin compilar.
    /// Se VALIDA al cargar: un catalogo con una combinacion que nombra una senal inexistente o con umbrales al reves falla en voz alta
    /// en vez de puntuar mal en silencio.
    /// </summary>
    public sealed class CatalogoDeSenales
    {
        public int UmbralARevisar { get; }
        public int UmbralPrioritaria { get; }
        public int ParcheMaximoDias { get; }
        public int ApiMinimaConSoporte { get; }
        public IReadOnlyDictionary<string, Senal> Senales { get; }
        public IReadOnlyList<Combinacion> Combinaciones { get; }
        public IReadOnlyDictionary<string, AppConocida> AppsConocidas { get; }
        public IReadOnlySet<string> TiendasOficiales { get; }
        public IReadOnlySet<string> TiendasConocidas { get; }
        public IReadOnlySet<string> Navegadores { get; }
        public IReadOnlySet<string> InstaladoresDeArchivo { get; }

        private CatalogoDeSenales(Dto d)
        {
            var errores = new List<string>();
            var senales = new Dictionary<string, Senal>();
            foreach (var s in d.Senales ?? new())
            {
                if (string.IsNullOrWhiteSpace(s.Id)) { errores.Add("senal sin id"); continue; }
                if (s.Peso < 0 || s.Peso > 10) errores.Add($"senal {s.Id}: peso {s.Peso} fuera de 0..10");
                if (string.IsNullOrWhiteSpace(s.Motivo)) errores.Add($"senal {s.Id}: sin motivo");
                if (!senales.TryAdd(s.Id, new Senal(s.Id, s.Peso, s.Motivo ?? ""))) errores.Add($"senal repetida: {s.Id}");
            }
            var combos = new List<Combinacion>();
            foreach (var c in d.Combinaciones ?? new())
            {
                var req = c.Requiere ?? new();
                if (req.Count < 2) errores.Add($"combinacion {c.Id}: necesita al menos 2 senales");
                foreach (var r in req) if (!senales.ContainsKey(r)) errores.Add($"combinacion {c.Id}: senal desconocida «{r}»");
                if (c.Peso <= 0) errores.Add($"combinacion {c.Id}: el peso debe ser positivo");
                combos.Add(new Combinacion(c.Id ?? "", req, c.Peso, c.Motivo ?? ""));
            }
            var conocidas = new Dictionary<string, AppConocida>(StringComparer.Ordinal);
            foreach (var a in d.AppsConocidas ?? new())
            {
                foreach (var p in a.Permite ?? new()) if (!senales.ContainsKey(p)) errores.Add($"app conocida {a.Paquete}: senal desconocida «{p}»");
                if (!conocidas.TryAdd(a.Paquete ?? "", new AppConocida(a.Paquete ?? "", new HashSet<string>(a.Permite ?? new()), a.Nota ?? ""))) errores.Add($"app conocida repetida: {a.Paquete}");
            }
            var u = d.Umbrales ?? new();
            if (u.ARevisar < 1 || u.Prioritaria <= u.ARevisar) errores.Add($"umbrales incoherentes: aRevisar={u.ARevisar}, prioritaria={u.Prioritaria}");
            var eq = d.Equipo ?? new();
            if (eq.ParcheMaximoDias < 1 || eq.ParcheMaximoDias > 3650) errores.Add($"equipo: parcheMaximoDias {eq.ParcheMaximoDias} fuera de 1..3650");
            if (eq.ApiMinimaConSoporte < 30 || eq.ApiMinimaConSoporte > 100) errores.Add($"equipo: apiMinimaConSoporte {eq.ApiMinimaConSoporte} fuera de 30..100");
            if (errores.Count > 0) throw new InvalidDataException("Catalogo de senales invalido: " + string.Join("; ", errores));

            UmbralARevisar = u.ARevisar; UmbralPrioritaria = u.Prioritaria;
            ParcheMaximoDias = eq.ParcheMaximoDias; ApiMinimaConSoporte = eq.ApiMinimaConSoporte;
            Senales = senales; Combinaciones = combos; AppsConocidas = conocidas;
            var o = d.Origenes ?? new();
            TiendasOficiales = new HashSet<string>(o.TiendasOficiales ?? new());
            TiendasConocidas = new HashSet<string>(o.TiendasConocidas ?? new());
            Navegadores = new HashSet<string>(o.Navegadores ?? new());
            InstaladoresDeArchivo = new HashSet<string>(o.InstaladoresDeArchivo ?? new());
        }

        public static CatalogoDeSenales Desde(string json)
        {
            Dto? d;
            try { d = JsonSerializer.Deserialize<Dto>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip }); }
            catch (JsonException ex) { throw new InvalidDataException("Catalogo de senales ilegible: " + ex.Message, ex); }
            return new CatalogoDeSenales(d ?? throw new InvalidDataException("Catalogo de senales vacio."));
        }

        /// <summary>El catalogo que viaja dentro del ensamblado.</summary>
        public static CatalogoDeSenales Embebido()
        {
            using var s = typeof(CatalogoDeSenales).Assembly.GetManifestResourceStream("senales-de-riesgo.json")
                          ?? throw new InvalidDataException("Falta el recurso senales-de-riesgo.json.");
            using var r = new StreamReader(s);
            return Desde(r.ReadToEnd());
        }

        public OrigenDeInstalacion ClasificarOrigen(string? instaladoPor)
        {
            if (string.IsNullOrEmpty(instaladoPor)) return OrigenDeInstalacion.ArchivoOAdb;
            if (TiendasOficiales.Contains(instaladoPor)) return OrigenDeInstalacion.TiendaOficial;
            if (TiendasConocidas.Contains(instaladoPor)) return OrigenDeInstalacion.TiendaConocida;
            if (Navegadores.Contains(instaladoPor)) return OrigenDeInstalacion.Navegador;
            if (InstaladoresDeArchivo.Contains(instaladoPor)) return OrigenDeInstalacion.ArchivoOAdb;
            return OrigenDeInstalacion.OtraTienda;
        }

        // ---- forma del JSON ----
        private sealed class Dto
        {
            public UmbralesDto? Umbrales { get; set; }
            public EquipoDto? Equipo { get; set; }
            public List<SenalDto>? Senales { get; set; }
            public List<CombinacionDto>? Combinaciones { get; set; }
            public OrigenesDto? Origenes { get; set; }
            public List<AppConocidaDto>? AppsConocidas { get; set; }
        }
        private sealed class EquipoDto { public int ParcheMaximoDias { get; set; } public int ApiMinimaConSoporte { get; set; } }
        private sealed class UmbralesDto { public int ARevisar { get; set; } public int Prioritaria { get; set; } }
        private sealed class SenalDto { public string? Id { get; set; } public int Peso { get; set; } public string? Motivo { get; set; } }
        private sealed class CombinacionDto { public string? Id { get; set; } public List<string>? Requiere { get; set; } public int Peso { get; set; } public string? Motivo { get; set; } }
        private sealed class OrigenesDto
        {
            public List<string>? TiendasOficiales { get; set; }
            public List<string>? TiendasConocidas { get; set; }
            public List<string>? Navegadores { get; set; }
            public List<string>? InstaladoresDeArchivo { get; set; }
        }
        private sealed class AppConocidaDto { public string? Paquete { get; set; } public List<string>? Permite { get; set; } public string? Nota { get; set; } }
    }
}
