using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Nexo.Modules.Threats.Apps
{
    /// <summary>
    /// Lista local de huellas SHA-256 de malware Android conocido (Salida 7, 3.2). Admite dos formatos, sin saber de donde vino:
    ///   - texto plano: una huella por linea; las lineas que empiezan por «#» son comentarios;
    ///   - CSV con varias columnas (como las exportaciones de MalwareBazaar): se toma la columna que parece una huella y, si alguna
    ///     columna dice «apk», solo se aceptan las filas de APK (esas listas mezclan todos los tipos de archivo).
    /// El formato CSV de MalwareBazaar es un SUPUESTO sin verificar con datos reales: sus exportaciones exigen una Auth-Key gratuita.
    /// Una linea invalida no tumba la lista: se cuenta. Una lista sin ninguna huella valida es un error, no «cero amenazas».
    /// </summary>
    public sealed class ListaDeHuellas
    {
        private readonly HashSet<string> _huellas;

        public string Nombre { get; }
        public int Cantidad => _huellas.Count;
        public int LineasInvalidas { get; }
        public int FilasQueNoSonApk { get; }

        private ListaDeHuellas(string nombre, HashSet<string> huellas, int invalidas, int noApk)
        {
            Nombre = nombre; _huellas = huellas; LineasInvalidas = invalidas; FilasQueNoSonApk = noApk;
        }

        public bool Contiene(string sha256) => _huellas.Contains(sha256.ToLowerInvariant());

        public static ListaDeHuellas Desde(string nombre, TextReader lector)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            int invalidas = 0, noApk = 0;
            string? linea;
            while ((linea = lector.ReadLine()) != null)
            {
                linea = linea.Trim();
                if (linea.Length == 0 || linea[0] == '#') continue;
                var campos = linea.Contains(',') ? Campos(linea) : new List<string> { linea };
                var huella = campos.FirstOrDefault(CacheDeHuellas.EsSha256);
                if (huella is null) { invalidas++; continue; }
                if (campos.Count > 1 && !campos.Any(c => c.Equals("apk", StringComparison.OrdinalIgnoreCase))) { noApk++; continue; }
                set.Add(huella.ToLowerInvariant());
            }
            if (set.Count == 0) throw new InvalidDataException($"La lista «{nombre}» no tiene ninguna huella valida ({invalidas} lineas invalidas, {noApk} filas que no son APK).");
            return new ListaDeHuellas(nombre, set, invalidas, noApk);
        }

        public static ListaDeHuellas DesdeArchivo(string ruta)
        {
            using var r = new StreamReader(ruta);
            return Desde(Path.GetFileName(ruta), r);
        }

        /// <summary>Separa una linea CSV respetando comillas dobles.</summary>
        private static List<string> Campos(string linea)
        {
            var l = new List<string>(); var sb = new System.Text.StringBuilder(); bool comillas = false;
            foreach (var c in linea)
            {
                if (c == '"') comillas = !comillas;
                else if (c == ',' && !comillas) { l.Add(sb.ToString().Trim()); sb.Clear(); }
                else sb.Append(c);
            }
            l.Add(sb.ToString().Trim());
            return l;
        }
    }

    /// <summary>Una huella de una app instalada que esta en una lista. Es una COINCIDENCIA EXACTA de esa copia, no un analisis.</summary>
    public sealed record Coincidencia(string Paquete, string Archivo, string Sha256, string Lista);

    public static class BuscadorDeCoincidencias
    {
        public static IReadOnlyList<Coincidencia> Buscar(IEnumerable<HuellaDeApp> huellas, IEnumerable<ListaDeHuellas> listas)
        {
            var l = listas.ToList();
            var r = new List<Coincidencia>();
            foreach (var app in huellas)
                foreach (var f in app.Archivos)
                    foreach (var lista in l)
                        if (lista.Contiene(f.Sha256)) r.Add(new Coincidencia(app.Paquete, f.Archivo, f.Sha256, lista.Nombre));
            return r;
        }
    }
}
