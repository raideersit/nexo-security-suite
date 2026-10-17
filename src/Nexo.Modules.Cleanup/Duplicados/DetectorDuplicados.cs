using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Duplicados
{
    /// <summary>
    /// Detector de archivos duplicados por CONTENIDO.
    ///
    /// Nunca por nombre ni por tamano solo: dos archivos distintos comparten tamano
    /// constantemente (iconos, plantillas, archivos generados) y borrar por esa
    /// coincidencia destruye datos. La regla del Prompt 4 es explicita al respecto.
    ///
    /// Tres etapas, cada una mas cara que la anterior, para no leer el disco entero:
    ///
    ///   1. Agrupar por TAMANO           — coste O(n), solo metadatos. Descarta el 95%.
    ///   2. Hash de los primeros 8 KB    — una lectura corta por archivo superviviente.
    ///   3. Hash SHA-256 COMPLETO        — solo para los que siguen empatados.
    ///
    /// En un disco con 200.000 archivos, la etapa 3 suele tocar unos pocos cientos.
    /// Sin la etapa 1 habria que hashear los 200.000 enteros.
    ///
    /// Este detector NO borra nada: produce grupos y una nota de reporte con accion
    /// "pendiente de confirmacion". El borrado pasa por el mismo flujo de vista
    /// previa y token que el resto del modulo.
    /// </summary>
    public sealed class DetectorDuplicados
    {
        private const int TamanoCabecera = 8 * 1024;

        /// <summary>
        /// Archivos por debajo de esto se ignoran. Un disco tiene decenas de miles
        /// de archivos diminutos identicos (iconos, __init__.py vacios, marcadores)
        /// y reportarlos solo produce ruido: el espacio recuperable es irrelevante
        /// y el riesgo de borrar algo que una aplicacion espera encontrar, no.
        /// </summary>
        public long TamanoMinimoBytes { get; set; } = 4 * 1024;

        private readonly IReportWriter _reportes;

        public DetectorDuplicados(IReportWriter reportes) => _reportes = reportes;

        public sealed class Resultado
        {
            public Resultado(IReadOnlyList<GrupoDuplicados> grupos, int archivosAnalizados,
                             int archivosHasheadosCompletos, TimeSpan duracion)
            {
                Grupos = grupos;
                ArchivosAnalizados = archivosAnalizados;
                ArchivosHasheadosCompletos = archivosHasheadosCompletos;
                Duracion = duracion;
            }

            public IReadOnlyList<GrupoDuplicados> Grupos { get; }
            public int ArchivosAnalizados { get; }

            /// <summary>Cuantos llegaron a la etapa 3. Sirve para verificar que el filtrado funciona.</summary>
            public int ArchivosHasheadosCompletos { get; }
            public TimeSpan Duracion { get; }

            public int TotalArchivosDuplicados => Grupos.Sum(g => g.Copias);
            public long BytesRecuperables => Grupos.Sum(g => g.BytesRecuperables);
        }

        public async Task<Resultado> AnalizarAsync(
            IReadOnlyList<string> carpetas,
            bool escribirReporte = true,
            CancellationToken ct = default)
        {
            var reloj = Stopwatch.StartNew();

            // --- Etapa 1: agrupar por tamano ---
            var porTamano = new Dictionary<long, List<string>>();
            int analizados = 0;

            foreach (string carpeta in carpetas)
            {
                foreach (string archivo in EnumerarSeguro(carpeta, ct))
                {
                    ct.ThrowIfCancellationRequested();

                    long tamano;
                    try
                    {
                        var info = new FileInfo(archivo);
                        // Un enlace simbolico apunta al mismo contenido que su
                        // destino: contarlo como duplicado llevaria a "liberar"
                        // espacio que no existe.
                        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        tamano = info.Length;
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        continue;
                    }

                    analizados++;
                    if (tamano < TamanoMinimoBytes) continue;

                    if (!porTamano.TryGetValue(tamano, out List<string>? lista))
                        porTamano[tamano] = lista = new List<string>();
                    lista.Add(archivo);
                }
            }

            // --- Etapa 2: hash de cabecera ---
            var porCabecera = new Dictionary<(long, string), List<string>>();

            foreach (KeyValuePair<long, List<string>> par in porTamano)
            {
                ct.ThrowIfCancellationRequested();
                if (par.Value.Count < 2) continue;      // tamano unico: no puede tener duplicado

                foreach (string archivo in par.Value)
                {
                    string? cabecera = await HashearAsync(archivo, TamanoCabecera, ct).ConfigureAwait(false);
                    if (cabecera is null) continue;

                    var clave = (par.Key, cabecera);
                    if (!porCabecera.TryGetValue(clave, out List<string>? lista))
                        porCabecera[clave] = lista = new List<string>();
                    lista.Add(archivo);
                }
            }

            // --- Etapa 3: hash completo ---
            var grupos = new List<GrupoDuplicados>();
            int hasheadosCompletos = 0;

            foreach (KeyValuePair<(long Tamano, string Cabecera), List<string>> par in porCabecera)
            {
                ct.ThrowIfCancellationRequested();
                if (par.Value.Count < 2) continue;

                // Si el archivo cabe entero en la cabecera, la etapa 2 ya comparo
                // todo su contenido: repetir la lectura no aporta nada.
                if (par.Key.Tamano <= TamanoCabecera)
                {
                    grupos.Add(new GrupoDuplicados(par.Key.Cabecera, par.Key.Tamano, Ordenar(par.Value)));
                    continue;
                }

                var porCompleto = new Dictionary<string, List<string>>(StringComparer.Ordinal);
                foreach (string archivo in par.Value)
                {
                    string? completo = await HashearAsync(archivo, long.MaxValue, ct).ConfigureAwait(false);
                    if (completo is null) continue;
                    hasheadosCompletos++;

                    if (!porCompleto.TryGetValue(completo, out List<string>? lista))
                        porCompleto[completo] = lista = new List<string>();
                    lista.Add(archivo);
                }

                foreach (KeyValuePair<string, List<string>> g in porCompleto)
                {
                    if (g.Value.Count < 2) continue;
                    grupos.Add(new GrupoDuplicados(g.Key, par.Key.Tamano, Ordenar(g.Value)));
                }
            }

            reloj.Stop();
            grupos.Sort((a, b) => b.BytesRecuperables.CompareTo(a.BytesRecuperables));

            var resultado = new Resultado(grupos, analizados, hasheadosCompletos, reloj.Elapsed);

            if (escribirReporte)
                await EscribirReporteAsync(resultado, ct).ConfigureAwait(false);

            return resultado;
        }

        /// <summary>
        /// Se propone conservar el mas antiguo: suele ser el original y el que
        /// tienen referenciado otras aplicaciones. Ante empate, orden alfabetico
        /// para que el resultado sea determinista entre ejecuciones.
        /// </summary>
        private static List<string> Ordenar(List<string> rutas)
        {
            return rutas
                .OrderBy(r => { try { return File.GetCreationTimeUtc(r); } catch (IOException) { return DateTime.MaxValue; } })
                .ThenBy(r => r, StringComparer.Ordinal)
                .ToList();
        }

        private static async Task<string?> HashearAsync(string ruta, long maxBytes, CancellationToken ct)
        {
            try
            {
                using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                                              bufferSize: 64 * 1024, useAsync: true);
                using var sha = SHA256.Create();

                byte[] buffer = new byte[64 * 1024];
                long restante = maxBytes;

                while (restante > 0)
                {
                    int aLeer = (int)Math.Min(buffer.Length, restante);
                    int leidos = await fs.ReadAsync(buffer.AsMemory(0, aLeer), ct).ConfigureAwait(false);
                    if (leidos == 0) break;
                    sha.TransformBlock(buffer, 0, leidos, null, 0);
                    restante -= leidos;
                }

                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return Convert.ToHexString(sha.Hash!);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // Archivo en uso o sin permisos: se ignora, no es un error del analisis.
                return null;
            }
        }

        private static IEnumerable<string> EnumerarSeguro(string carpeta, CancellationToken ct)
        {
            if (!Directory.Exists(carpeta)) yield break;

            var pendientes = new Stack<string>();
            pendientes.Push(carpeta);

            while (pendientes.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string actual = pendientes.Pop();

                string[] subcarpetas;
                string[] archivos;
                try
                {
                    // Recorrido manual en vez de AllDirectories: asi una subcarpeta
                    // sin permisos no aborta el recorrido completo.
                    subcarpetas = Directory.GetDirectories(actual);
                    archivos = Directory.GetFiles(actual);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                {
                    continue;
                }

                foreach (string s in subcarpetas)
                {
                    try
                    {
                        if ((new DirectoryInfo(s).Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    catch (IOException) { continue; }
                    pendientes.Push(s);
                }

                foreach (string a in archivos) yield return a;
            }
        }

        private async Task EscribirReporteAsync(Resultado r, CancellationToken ct)
        {
            NexoEvent ev = Eventos.Limpieza.Duplicados(
                grupos:            r.Grupos.Count,
                archivos:          r.TotalArchivosDuplicados,
                bytesRecuperables: r.BytesRecuperables,
                algoritmo:         "tamano -> SHA-256 de 8 KB -> SHA-256 completo");

            ev.Con("archivos_analizados", r.ArchivosAnalizados)
              .Con("hasheados_completos", r.ArchivosHasheadosCompletos)
              .Con("duracion_segundos", Math.Round(r.Duracion.TotalSeconds, 2));

            await _reportes.EscribirAsync(ev, ct).ConfigureAwait(false);
        }
    }
}
