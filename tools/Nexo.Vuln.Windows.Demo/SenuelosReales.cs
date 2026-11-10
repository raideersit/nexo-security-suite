using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Files;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private sealed class VaultEnMemoria : IReportWriter
        {
            public readonly List<NexoEvent> Eventos = new();
            public Task<NoteRef> EscribirAsync(NexoEvent e, CancellationToken ct = default) { lock (Eventos) Eventos.Add(e); return Task.FromResult<NoteRef>(null!); }
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        /// <summary>Señuelos sobre el disco REAL, en una carpeta temporal propia (nunca en Documentos del usuario). Sin administrador.</summary>
        public static void ProbarSenuelosReales()
        {
            Console.WriteLine("13. Señuelos contra ransomware sobre el disco REAL (carpeta temporal propia, sin administrador)");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-senuelos-real-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "Documentos"), escr = Path.Combine(raiz, "Escritorio");
            Directory.CreateDirectory(docs);
            Directory.CreateDirectory(escr);
            try
            {
                // --- Capa nativa ---
                string a = Path.Combine(raiz, "a.bin");
                File.WriteAllBytes(a, new byte[] { 1, 2, 3 });
                ulong? id = NumeroDeArchivo.De(a, out int err);
                Check(id is > 0, "NumeroDeArchivo.De da un número para un archivo real", "error " + err);
                Check(NumeroDeArchivo.De(Path.Combine(raiz, "no-existe"), out int err2) is null && err2 == NumeroDeArchivo.ErrorNoEncontrado, "archivo que no existe: null con el error 2");
                string b = Path.Combine(raiz, "sub", "b.locked");
                Directory.CreateDirectory(Path.GetDirectoryName(b)!);
                File.Move(a, b);
                Check(NumeroDeArchivo.De(b, out _) == id, "el número no cambia al renombrar y mover de carpeta");
                string? donde = NumeroDeArchivo.RutaPorNumero(Path.GetPathRoot(raiz)!, id!.Value, out int err3);
                Check(string.Equals(donde, b, StringComparison.OrdinalIgnoreCase) && err3 == 0, "RutaPorNumero encuentra la ruta nueva SIN administrador", donde + " / error " + err3);
                File.Delete(b);
                Check(NumeroDeArchivo.RutaPorNumero(Path.GetPathRoot(raiz)!, id.Value, out int err4) is null && err4 == 0, "borrado: null con error 0 («no existe»)", "error " + err4);
                File.WriteAllBytes(a, new byte[] { 4 });
                ulong? idNuevo = NumeroDeArchivo.De(a, out _);
                Check(idNuevo != id && NumeroDeArchivo.RutaPorNumero(Path.GetPathRoot(raiz)!, id.Value, out int err5) is null && err5 == 0,
                    "un archivo nuevo no hereda el número del borrado (la secuencia lo distingue)");

                // --- AccesoASenuelosWindows ---
                var acc = new AccesoASenuelosWindows();
                string s = Path.Combine(docs, "!nexo-señuelo.docx");
                byte[] contenido = new byte[50_000]; new Random(1).NextBytes(contenido);
                CreacionDeSenuelo c = acc.Crear(s, contenido);
                Check(c.Estado == EstadoDeCreacion.Creado && c.Id is > 0 && c.Motivo is null, "crea el señuelo y devuelve su número", c.Motivo);
                Check((File.GetAttributes(s) & FileAttributes.Hidden) != 0, "queda oculto");
                Check(File.ReadAllBytes(s).SequenceEqual(contenido), "con el contenido pedido (nombre con «ñ» incluido)");
                File.WriteAllBytes(a, new byte[] { 9, 9 });
                Check(acc.Crear(a, contenido).Estado == EstadoDeCreacion.Ocupado && File.ReadAllBytes(a).SequenceEqual(new byte[] { 9, 9 }), "un nombre ocupado: Ocupado, y el archivo ajeno NO se toca");
                LecturaDeSenuelo l = acc.Leer(s);
                Check(l.Estado == EstadoDeLectura.Leido && l.Bytes == 50_000 && l.Sha256 == VigilanteDeSenuelos.Huella(contenido) && l.Id == c.Id, "leer: tamaño, huella y número correctos");
                using (new FileStream(s, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    Check(acc.Leer(s) is { Estado: EstadoDeLectura.NoLeido } nl && nl.Motivo!.Contains("abierto"), "abierto en exclusiva por otro: NoLeido con el motivo (no «intacto»)");
                Check(acc.Leer(Path.Combine(docs, "nada.docx")).Estado == EstadoDeLectura.NoExiste, "no existe: NoExiste");
                Check(acc.BuscarPorId(docs, c.Id!.Value) is { Estado: EstadoDeBusqueda.Encontrado } bp && string.Equals(bp.Ruta, s, StringComparison.OrdinalIgnoreCase), "buscar por número: lo encuentra donde está");
                Check(acc.Crear(Path.Combine(raiz, "no", "existe.docx"), contenido).Estado == EstadoDeCreacion.Fallo, "carpeta inexistente: Fallo con motivo");
                File.SetAttributes(s, FileAttributes.Normal);
                File.Delete(s);

                // --- De punta a punta con el vigilante, sobre el disco real ---
                string lista = Path.Combine(raiz, "estado", "senuelos.json");
                var vault = new VaultEnMemoria();
                var v = new VigilanteDeSenuelos(acc, new AlmacenDeSenuelosJson(lista), vault);
                v.PrepararAsync(new[] { docs, escr }).GetAwaiter().GetResult();
                EstadoDeSenuelos e = v.Estado();
                Check(e.Senuelos.Count == 4 && e.Senuelos.All(x => File.Exists(x.Ruta) && x.Id is > 0) && File.Exists(lista), "pone 4 señuelos reales y guarda la lista", string.Join("; ", e.SinSenuelo.Select(x => x.Motivo)));
                Check(Directory.GetFiles(docs).Select(Path.GetFileName).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).First() == "!nexo-señuelo.docx",
                    "en el disco real, el «!» va primero en orden alfabético");
                Check(v.RevisarAsync().GetAwaiter().GetResult().Count == 0 && v.Estado().Intactos == 4, "revisar: los 4 intactos");

                string d0 = Path.Combine(docs, "!nexo-señuelo.docx"), d1 = Path.Combine(docs, "zz-nexo-señuelo.xlsx"), e0 = Path.Combine(escr, "!nexo-señuelo.docx"), e1 = Path.Combine(escr, "zz-nexo-señuelo.xlsx");
                // Hallazgo real: CREATE_ALWAYS (File.WriteAllBytes) sobre un archivo OCULTO lo niega Windows.
                byte[] cifrado = File.ReadAllBytes(d1).Select(x => (byte)(x ^ 0xA5)).ToArray();
                bool negado = false;
                try { File.WriteAllBytes(d1, cifrado); } catch (UnauthorizedAccessException) { negado = true; }
                Check(negado && File.Exists(d1) && v.RevisarAsync().GetAwaiter().GetResult().Count == 0,
                    "HALLAZGO fijado: reescribir un señuelo oculto con CREATE_ALWAYS falla (acceso denegado) y el señuelo no cambia");
                // Lo que hace un ransomware típico: abrir, escribir encima y renombrar.
                using (var fs = new FileStream(d1, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { fs.Write(cifrado); fs.SetLength(cifrado.Length); }
                File.Move(d1, d1 + ".locked");
                // Otro: escribir encima.
                using (var fs = new FileStream(d0, FileMode.Open, FileAccess.Write, FileShare.None)) { fs.Write(new byte[] { 0xDE, 0xAD }); }
                // Otro: borrar.
                File.SetAttributes(e0, FileAttributes.Normal);
                File.Delete(e0);
                IReadOnlyList<Senuelo> n = v.RevisarAsync().GetAwaiter().GetResult();
                Check(n.Count == 3, "detecta los 3 tocados", string.Join(" | ", n.Select(x => x.Ruta + ": " + x.Hallazgo!.Detalle)));
                Check(n.Any(x => x.Ruta == d1 && x.Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Renombrado && string.Equals(x.Hallazgo.NuevaRuta, d1 + ".locked", StringComparison.OrdinalIgnoreCase)
                                && x.Hallazgo.Detalle.Contains("Y su contenido cambió")), "renombrado a .locked y cifrado: Renombrado, con la ruta real nueva");
                Check(n.Any(x => x.Ruta == d0 && x.Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Modificado), "escrito encima: Modificado");
                Check(n.Any(x => x.Ruta == e0 && x.Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Borrado), "borrado de verdad: Borrado (buscado por número, sin administrador)");
                Check(vault.Eventos.Count(x => x.Tipo == TipoEvento.SenueloTocado && x.Severidad == Severidad.Alta) == 3
                      && vault.Eventos.Any(x => x.Severidad == Severidad.Critica), "3 eventos Alta y uno Crítico (ráfaga)");

                // Reinicio: otro vigilante con la misma lista.
                var v2 = new VigilanteDeSenuelos(acc, new AlmacenDeSenuelosJson(lista), new VaultEnMemoria());
                Check(v2.RevisarAsync().GetAwaiter().GetResult().Count == 0 && v2.Estado().Tocados == 3, "tras reiniciar: los 3 siguen tocados (no se re-avisan) y el intacto sigue bien");
                File.AppendAllText(e1, "x");
                Check(v2.RevisarAsync().GetAwaiter().GetResult().Single().Ruta == e1, "y lo que se toque después se detecta");

                // Reponer: no borra ni mueve los tocados.
                PlanDeReposicion plan = v2.PrepararReposicion();
                ResultadoDeReposicion r = v2.ReponerAsync(plan).GetAwaiter().GetResult();
                Check(r.Repuestos == 4 && r.Problemas.Count == 0, "repone los 4", string.Join("; ", r.Problemas));
                Check(File.Exists(d1 + ".locked") && File.ReadAllBytes(d1 + ".locked").SequenceEqual(cifrado) && File.Exists(Path.Combine(docs, "!nexo-señuelo (2).docx")) && File.Exists(d1) && File.Exists(e0),
                    "los tocados siguen ahí intactos; los nuevos están (con «(2)» donde el nombre seguía ocupado)");
                Check(v2.RevisarAsync().GetAwaiter().GetResult().Count == 0 && v2.Estado().Intactos == 4 && v2.Estado().Tocados == 0, "los repuestos se revisan y están intactos");

                // Sin ocultar: CREATE_ALWAYS sí funciona, y se detecta.
                string vis = Path.Combine(raiz, "Visibles");
                Directory.CreateDirectory(vis);
                var vVis = new VigilanteDeSenuelos(new AccesoASenuelosWindows(ocultos: false), new AlmacenDeSenuelosJson(Path.Combine(raiz, "estado", "vis.json")), new VaultEnMemoria());
                vVis.PrepararAsync(new[] { vis }).GetAwaiter().GetResult();
                string v0 = Path.Combine(vis, "!nexo-señuelo.docx");
                Check((File.GetAttributes(v0) & FileAttributes.Hidden) == 0, "con Ocultos = false: el señuelo queda visible");
                File.WriteAllBytes(v0, cifrado);
                Check(vVis.RevisarAsync().GetAwaiter().GetResult().Single().Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Modificado, "y reescribirlo con CREATE_ALWAYS sí se detecta");

                // --- Perfiles reales (solo lectura del registro) ---
                IReadOnlyList<PerfilParaSenuelos> perfiles = LectorDePerfilesWindows.Leer(out IReadOnlyList<string> problemas);
                string perfilPropio = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                PerfilParaSenuelos? propio = perfiles.FirstOrDefault(p => string.Equals(p.Carpeta, perfilPropio, StringComparison.OrdinalIgnoreCase));
                Console.WriteLine("      INFO: " + perfiles.Count + " perfil(es): " + string.Join(", ", perfiles.Select(p => p.Carpeta + (p.CarpetasDelShell is null ? " (cerrado)" : " (abierto)"))));
                Check(problemas.Count == 0 && propio is not null && propio.CarpetasDelShell is not null, "lee los perfiles y las carpetas del shell del usuario actual", string.Join("; ", problemas));
                IReadOnlyList<string> elegidas = CarpetasParaSenuelos.Elegir(perfiles, out IReadOnlyList<CarpetaSinSenuelo> fuera);
                Console.WriteLine("      INFO: carpetas: " + string.Join(", ", elegidas) + (fuera.Count > 0 ? " | descartadas: " + string.Join(", ", fuera.Select(f => f.Carpeta + " (" + f.Motivo + ")")) : ""));
                string[] esperadas =
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
                };
                Check(esperadas.All(x => elegidas.Contains(x, StringComparer.OrdinalIgnoreCase) || fuera.Any(f => string.Equals(f.Carpeta, x, StringComparison.OrdinalIgnoreCase))),
                    "las carpetas del usuario actual coinciden con las de Windows (SHGetKnownFolderPath)", string.Join(", ", esperadas));
            }
            finally
            {
                try
                {
                    foreach (string f in Directory.GetFiles(raiz, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
                    Directory.Delete(raiz, true);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}
