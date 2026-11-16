using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Nexo.Modules.Threats.Apps
{
    /// <summary>
    /// Apps en las que el usuario dijo «confio» (Salida 7, 3.1 y 9). Efectos:
    ///  - la app sale de «a revisar» (queda como «Confiada» y conserva sus puntos y motivos: no se esconde nada);
    ///  - NO silencia una coincidencia exacta con una huella conocida (eso lo decide el vigilante y el buscador, no este almacen).
    ///
    /// La confianza se ata a UNA INSTALACION: (paquete, fecha de la primera instalacion). Android reinicia esa fecha cuando la app se desinstala y
    /// se vuelve a instalar, y la conserva en las actualizaciones. Asi otra app que se instale despues con el mismo nombre de paquete NO hereda
    /// la confianza, aunque no haya habido ninguna revision entre la desinstalacion y la nueva instalacion.
    /// </summary>
    public sealed class AlmacenDeConfianza
    {
        private readonly Dictionary<string, long> _instalaciones = new(StringComparer.Ordinal);

        public int Cantidad => _instalaciones.Count;

        /// <summary>true si el usuario confio en ESTA instalacion de la app.</summary>
        public bool Confia(ModeloDeApp app) => _instalaciones.TryGetValue(app.Paquete, out var t) && t == app.PrimeraInstalacionMs;

        /// <summary>false si el paquete no tiene forma de paquete o no se conoce cuando se instalo (sin esa fecha no se puede atar la confianza).</summary>
        public bool Confiar(ModeloDeApp app)
        {
            if (!EsPaqueteValido(app.Paquete) || app.PrimeraInstalacionMs <= 0) return false;
            _instalaciones[app.Paquete] = app.PrimeraInstalacionMs;
            return true;
        }

        public bool DejarDeConfiar(string paquete) => _instalaciones.Remove(paquete);

        /// <summary>Los paquetes cuya confianza SIGUE valiendo para lo instalado ahora. Es lo que se le pasa al puntuador y al vigilante.</summary>
        public IReadOnlySet<string> Vigentes(IEnumerable<ModeloDeApp> instaladas) =>
            new HashSet<string>(instaladas.Where(Confia).Select(a => a.Paquete), StringComparer.Ordinal);

        /// <summary>Olvida la confianza de lo que ya no esta instalado O de lo que se reinstalo. Devuelve cuantas.</summary>
        public int Podar(IEnumerable<ModeloDeApp> instaladas)
        {
            var vigentes = Vigentes(instaladas);
            var sobran = _instalaciones.Keys.Where(k => !vigentes.Contains(k)).ToList();
            foreach (var k in sobran) _instalaciones.Remove(k);
            return sobran.Count;
        }

        internal static bool EsPaqueteValido(string? p) =>
            !string.IsNullOrWhiteSpace(p) && p!.Length <= 255 && p.Contains('.') && p.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '_');

        // ---- persistencia ----
        private sealed class Dto { public int Version { get; set; } = 2; public Dictionary<string, long>? Instalaciones { get; set; } }
        private static readonly JsonSerializerOptions Opciones = new() { WriteIndented = true };

        public void Guardar(string ruta)
        {
            var carpeta = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (!string.IsNullOrEmpty(carpeta)) Directory.CreateDirectory(carpeta);
            var temporal = ruta + ".tmp";
            File.WriteAllText(temporal, JsonSerializer.Serialize(new Dto { Instalaciones = new Dictionary<string, long>(_instalaciones) }, Opciones));
            File.Move(temporal, ruta, overwrite: true);
        }

        /// <summary>Un archivo danado se descarta con aviso: es mas seguro volver a revisar de mas que confiar en lo que no se sabe.</summary>
        public static AlmacenDeConfianza Cargar(string ruta, out string? aviso)
        {
            aviso = null;
            var a = new AlmacenDeConfianza();
            if (!File.Exists(ruta)) return a;
            try
            {
                var d = JsonSerializer.Deserialize<Dto>(File.ReadAllText(ruta), Opciones);
                if (d?.Instalaciones is null || d.Version != 2) { aviso = "La lista de apps de confianza tiene un formato desconocido: se empieza vacia."; return new AlmacenDeConfianza(); }
                foreach (var (paquete, cuando) in d.Instalaciones)
                {
                    if (!EsPaqueteValido(paquete) || cuando <= 0) { aviso = "La lista de apps de confianza tenia entradas invalidas: se empieza vacia."; return new AlmacenDeConfianza(); }
                    a._instalaciones[paquete] = cuando;
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                aviso = "La lista de apps de confianza estaba danada: se empieza vacia.";
                return new AlmacenDeConfianza();
            }
            return a;
        }
    }
}
