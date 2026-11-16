using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  HUELLAS DE APK (Salida 7, 3.2). Portable: no sabe nada de Android.
    //
    //  Calcular el SHA-256 de los APK de un telefono es CARO (medido en un S20 FE: 106 apps, 8,5 GiB, 58 s). Por eso la CACHE no es una
    //  optimizacion sino parte del diseño: se guarda por (paquete, versionCode, lastUpdateTime) y solo se rehashea lo nuevo o actualizado.
    //  Solo se hashean apps de USUARIO: las del sistema vienen firmadas por el fabricante y se actualizan con el sistema.
    //
    //  Limite honesto: una huella solo reconoce ESA copia exacta. Una app maliciosa reempaquetada tiene otra huella.
    // =====================================================================================================

    public sealed record HuellaDeArchivo(string Archivo, long Tamano, string Sha256);

    public sealed record HuellaDeApp(string Paquete, long VersionCode, long UltimaActualizacionMs, IReadOnlyList<HuellaDeArchivo> Archivos);

    /// <summary>De donde salen los bytes de los APK (el sistema de archivos; falso en las pruebas).</summary>
    public interface IOrigenDeApks
    {
        /// <summary>Tamano del archivo, o null si no existe o no se puede leer.</summary>
        long? Tamano(string ruta);
        Stream Abrir(string ruta);
    }

    public sealed class OrigenDeApksEnDisco : IOrigenDeApks
    {
        public long? Tamano(string ruta)
        {
            try { var f = new FileInfo(ruta); return f.Exists ? f.Length : null; }
            catch (Exception) { return null; }
        }
        public Stream Abrir(string ruta) => new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 81920, FileOptions.SequentialScan);
    }

    /// <summary>Cache de huellas en un JSON. Un archivo danado NO se usa: se empieza de cero y se avisa, nunca se confia en datos a medias.</summary>
    public sealed class CacheDeHuellas
    {
        private readonly Dictionary<string, HuellaDeApp> _porPaquete = new(StringComparer.Ordinal);

        public int Cantidad => _porPaquete.Count;
        public IReadOnlyCollection<HuellaDeApp> Todas => _porPaquete.Values;

        /// <summary>Devuelve la huella guardada SOLO si la app sigue igual: mismo versionCode, misma fecha de actualizacion y mismos archivos con el mismo tamano.</summary>
        public HuellaDeApp? Obtener(ModeloDeApp app, IOrigenDeApks origen)
        {
            if (!_porPaquete.TryGetValue(app.Paquete, out var h)) return null;
            if (h.VersionCode != app.VersionCode || h.UltimaActualizacionMs != app.UltimaActualizacionMs) return null;
            if (h.Archivos.Count != app.Apks.Count) return null;
            for (int i = 0; i < app.Apks.Count; i++)
            {
                if (!string.Equals(h.Archivos[i].Archivo, Path.GetFileName(app.Apks[i]), StringComparison.Ordinal)) return null;
                if (origen.Tamano(app.Apks[i]) != h.Archivos[i].Tamano) return null;
            }
            return h;
        }

        public void Poner(HuellaDeApp h) => _porPaquete[h.Paquete] = h;

        /// <summary>Olvida las apps que ya no estan instaladas. Devuelve cuantas.</summary>
        public int Podar(IEnumerable<string> instaladas)
        {
            var vivas = new HashSet<string>(instaladas, StringComparer.Ordinal);
            var sobran = _porPaquete.Keys.Where(k => !vivas.Contains(k)).ToList();
            foreach (var k in sobran) _porPaquete.Remove(k);
            return sobran.Count;
        }

        // ---- persistencia ----
        private sealed class Dto { public int Version { get; set; } = 1; public List<HuellaDeApp>? Apps { get; set; } }
        private static readonly JsonSerializerOptions Opciones = new() { WriteIndented = false };

        /// <summary>Escribe en un temporal y lo mueve: un corte a mitad de escritura no deja un JSON roto.</summary>
        public void Guardar(string ruta)
        {
            var carpeta = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (!string.IsNullOrEmpty(carpeta)) Directory.CreateDirectory(carpeta);
            var temporal = ruta + ".tmp";
            File.WriteAllText(temporal, JsonSerializer.Serialize(new Dto { Apps = _porPaquete.Values.OrderBy(a => a.Paquete, StringComparer.Ordinal).ToList() }, Opciones));
            File.Move(temporal, ruta, overwrite: true);
        }

        /// <summary>Carga la cache. Si no existe, vacia sin aviso. Si esta danada, vacia CON aviso.</summary>
        public static CacheDeHuellas Cargar(string ruta, out string? aviso)
        {
            aviso = null;
            var c = new CacheDeHuellas();
            if (!File.Exists(ruta)) return c;
            try
            {
                var d = JsonSerializer.Deserialize<Dto>(File.ReadAllText(ruta), Opciones);
                if (d?.Apps is null || d.Version != 1) { aviso = "La cache de huellas tiene un formato desconocido: se vuelve a calcular."; return c; }
                foreach (var a in d.Apps)
                {
                    if (string.IsNullOrEmpty(a.Paquete) || a.Archivos is null || a.Archivos.Any(f => !EsSha256(f.Sha256))) { aviso = "La cache de huellas tiene entradas invalidas: se vuelve a calcular."; return new CacheDeHuellas(); }
                    c._porPaquete[a.Paquete] = a;
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                aviso = "La cache de huellas estaba danada: se vuelve a calcular.";
                return new CacheDeHuellas();
            }
            return c;
        }

        internal static bool EsSha256(string? s) => s is { Length: 64 } && s.All(Uri.IsHexDigit);
    }

    public sealed record ResumenDeHuellas(int Calculadas, int DeCache, int Fallidas, int Podadas, long BytesLeidos, IReadOnlyList<string> Errores);

    public sealed class ResultadoDeHuellas
    {
        public required ResumenDeHuellas Resumen { get; init; }
        public required IReadOnlyDictionary<string, HuellaDeApp> Huellas { get; init; }
    }

    public sealed class CalculadorDeHuellas
    {
        private readonly IOrigenDeApks _origen;
        private readonly CacheDeHuellas _cache;

        public CalculadorDeHuellas(IOrigenDeApks origen, CacheDeHuellas cache) { _origen = origen; _cache = cache; }

        /// <summary>
        /// Calcula (o recupera de la cache) la huella de cada app de USUARIO. Lo que ya se calculo queda en la cache aunque se cancele:
        /// la proxima vez se sigue donde se quedo. Una app que no se puede leer se anota como fallida y NO se guarda en la cache.
        /// </summary>
        public ResultadoDeHuellas Calcular(IReadOnlyList<ModeloDeApp> apps, IProgress<(int Hechas, int Total)>? progreso = null, CancellationToken ct = default)
        {
            var deUsuario = apps.Where(a => !a.EsDeSistema && a.Apks.Count > 0).ToList();
            int podadas = _cache.Podar(apps.Select(a => a.Paquete));
            var huellas = new Dictionary<string, HuellaDeApp>(StringComparer.Ordinal);
            var errores = new List<string>();
            int calculadas = 0, deCache = 0, fallidas = 0; long bytes = 0, hechas = 0;

            foreach (var app in deUsuario)
            {
                ct.ThrowIfCancellationRequested();
                var guardada = _cache.Obtener(app, _origen);
                if (guardada is not null) { huellas[app.Paquete] = guardada; deCache++; }
                else
                {
                    try
                    {
                        var archivos = new List<HuellaDeArchivo>();
                        foreach (var ruta in app.Apks)
                        {
                            var (sha, n) = Hashear(ruta, ct);
                            archivos.Add(new HuellaDeArchivo(Path.GetFileName(ruta), n, sha));
                            bytes += n;
                        }
                        var h = new HuellaDeApp(app.Paquete, app.VersionCode, app.UltimaActualizacionMs, archivos);
                        _cache.Poner(h);
                        huellas[app.Paquete] = h;
                        calculadas++;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        fallidas++;
                        errores.Add($"{app.Paquete}: {ex.GetType().Name}");
                    }
                }
                progreso?.Report(((int)++hechas, deUsuario.Count));
            }
            return new ResultadoDeHuellas { Resumen = new ResumenDeHuellas(calculadas, deCache, fallidas, podadas, bytes, errores), Huellas = huellas };
        }

        private (string Sha256, long Bytes) Hashear(string ruta, CancellationToken ct)
        {
            using var s = _origen.Abrir(ruta);
            using var sha = SHA256.Create();
            var buffer = new byte[81920];
            long total = 0; int n;
            while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                sha.TransformBlock(buffer, 0, n, null, 0);
                total += n;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return (Convert.ToHexString(sha.Hash!).ToLowerInvariant(), total);
        }
    }
}
