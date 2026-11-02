using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Disco;
using Nexo.Modules.Cleanup.Duplicados;
using Nexo.Modules.Cleanup.Inicio;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Modules.Cleanup.Platform;
using Nexo.Modules.Cleanup.Seguridad;
using Nexo.Modules.Cleanup.Trituracion;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Seguridad;
using Nexo.Reports.Vault;

namespace Nexo.Cleanup.Demo
{
    /// <summary>
    /// Arnes de aceptacion del modulo de limpieza.
    ///
    /// Construye un corpus sintetico, ejecuta el flujo completo contra el, y
    /// verifica lo que el Prompt 4 exige: que nada se borre sin confirmacion y
    /// que los duplicados se detecten por contenido y no por nombre ni tamano.
    ///
    /// Incluye archivos TRAMPA que deben sobrevivir. Si alguno desaparece, la
    /// verificacion falla: es la unica forma de probar que el guardia sirve.
    /// </summary>
    public static partial class Program
    {
        private static int _fallos;

        public static async Task<int> Main(string[] args)
        {
            string raiz = args.Length > 0
                ? args[0]
                : Path.Combine(Path.GetTempPath(), "nexo-cleanup-demo");

            string corpus = Path.Combine(raiz, "corpus");
            string vault = Path.Combine(raiz, "vault");

            Console.OutputEncoding = new UTF8Encoding(false);

            if (Directory.Exists(raiz)) BorrarCorpus(raiz);
            ConstruirCorpus(corpus);

            var opciones = new VaultOptions
            {
                RutaVault = vault,
                Equipo = "NEXO-LAB",
                Redaccion = RedactionOptions.Desarrollo()
            };
            using var reportes = new ReportWriter(opciones);
            await reportes.InicializarVaultAsync().ConfigureAwait(false);

            Console.WriteLine("Corpus: " + corpus);
            Console.WriteLine();

            await ProbarGuardia(corpus).ConfigureAwait(false);
            await ProbarLimpieza(corpus, reportes).ConfigureAwait(false);
            await ProbarCarpetaInaccesible(corpus, reportes).ConfigureAwait(false);
            await ProbarDuplicados(corpus, reportes).ConfigureAwait(false);
            await ProbarTrituracion(corpus, reportes).ConfigureAwait(false);
            await ProbarInicio().ConfigureAwait(false);
            ProbarArranque();
            await ProbarSmart().ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(_fallos == 0
                ? "TODAS LAS VERIFICACIONES PASARON"
                : _fallos + " VERIFICACIONES FALLIDAS");
            Console.WriteLine("Vault: " + vault);

            // El corpus se queda en %TEMP% y ensuciaria la vista previa del
            // limpiador real. Si algo fallo se conserva, para poder inspeccionarlo.
            if (_fallos == 0)
            {
                try { BorrarCorpus(corpus); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Console.WriteLine("  [AVISO] No se pudo borrar el corpus: " + ex.GetType().Name);
                }
            }
            else
            {
                Console.WriteLine("Corpus conservado para inspeccion: " + corpus);
            }
            return _fallos == 0 ? 0 : 1;
        }

        private static void BorrarCorpus(string ruta)
        {
            // Puede haber uniones NTFS que apuntan fuera. Se quitan primero
            // (sin recursion: borra solo la union, no su destino).
            foreach (string d in Directory.EnumerateDirectories(ruta, "*", SearchOption.AllDirectories)
                         .Where(d => (new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0)
                         .ToList())
                Directory.Delete(d, recursive: false);
            Directory.Delete(ruta, recursive: true);
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        // ============================================================
        //  CORPUS SINTETICO
        // ============================================================
        private static void ConstruirCorpus(string corpus)
        {
            // --- Basura limpiable ---
            Escribir(corpus, "temp/a.tmp", Patron('A', 2048));
            Escribir(corpus, "temp/b.tmp", Patron('B', 4096));
            Escribir(corpus, "temp/sub/c.tmp", Patron('C', 1024));

            // Cache con perfiles: ejercita el comodin de subruta del catalogo.
            Escribir(corpus, "cache/Default/Cache_Data/f1.bin", Patron('D', 8192));
            Escribir(corpus, "cache/Profile 1/Cache_Data/f2.bin", Patron('E', 8192));

            // --- TRAMPAS: deben sobrevivir a la limpieza ---
            // Fuera de cualquier regla del catalogo.
            Escribir(corpus, "Documents/importante.docx", Patron('X', 10_000));
            Escribir(corpus, "secreto.txt", Patron('S', 500));
            // Dentro de temp, pero es un enlace que apunta fuera: el guardia debe
            // rechazarlo o borraria el destino real.
            CrearEnlace(Path.Combine(corpus, "temp", "enlace-peligroso.tmp"),
                        Path.Combine(corpus, "secreto.txt"));

            // --- Duplicados ---
            // a y b: identicos. c: MISMO TAMANO y MISMA CABECERA de 8 KB que a,
            // pero distinto final. Solo la etapa 3 puede distinguirlos.
            byte[] cabecera = Patron('H', 8192);
            byte[] colaQ = Patron('Q', 24_576);
            byte[] colaR = Patron('R', 24_576);
            Escribir(corpus, "dup/uno/grande-a.bin", Concat(cabecera, colaQ));
            Escribir(corpus, "dup/dos/grande-b.bin", Concat(cabecera, colaQ));
            Escribir(corpus, "dup/tres/grande-c.bin", Concat(cabecera, colaR));

            // Mismo NOMBRE, distinto contenido: no deben agruparse.
            Escribir(corpus, "dup/uno/informe.txt", Patron('1', 6000));
            Escribir(corpus, "dup/dos/informe.txt", Patron('2', 6000));

            // Distinto NOMBRE, mismo contenido: si deben agruparse.
            byte[] mismo = Patron('M', 6000);
            Escribir(corpus, "dup/uno/copia-vieja.dat", mismo);
            Escribir(corpus, "dup/dos/respaldo-2024.dat", mismo);

            // Bajo el minimo de 4 KB: se ignoran aunque sean identicos.
            Escribir(corpus, "dup/uno/mini-a.txt", Patron('m', 100));
            Escribir(corpus, "dup/dos/mini-b.txt", Patron('m', 100));
        }

        private static byte[] Patron(char c, int largo)
        {
            byte[] b = new byte[largo];
            for (int i = 0; i < largo; i++) b[i] = (byte)(c + (i % 7));
            return b;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        private static void Escribir(string raiz, string relativa, byte[] contenido)
        {
            string ruta = Path.Combine(raiz, relativa.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(ruta)!);
            File.WriteAllBytes(ruta, contenido);
        }

        private static void CrearEnlace(string enlace, string destino)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(enlace)!);
            try { File.CreateSymbolicLink(enlace, destino); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // En Windows sin modo desarrollador hace falta privilegio para
                // crear enlaces. La comprobacion se marca como no ejecutada.
                Console.WriteLine("  [AVISO] No se pudo crear el enlace simbolico de prueba: " + ex.GetType().Name);
            }
        }

        private static bool CrearUnion(string union, string destino)
        {
            if (!OperatingSystem.IsWindows()) return false;
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe",
                $"/c mklink /J \"{union}\" \"{destino}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            if (p.ExitCode == 0) return true;
            Console.WriteLine("  [AVISO] No se pudo crear la union NTFS de prueba");
            return false;
        }

        // ============================================================
        //  1. GUARDIA DE RUTAS
        // ============================================================
        private static Task ProbarGuardia(string corpus)
        {
            Console.WriteLine("1. Guardia de rutas (lista blanca + lista negra)");
            var ahora = DateTimeOffset.Now;

            string temp = Path.Combine(corpus, "temp");
            var guardia = new GuardiaDeRutas(TimeSpan.Zero).PermitirRaiz(temp);

            Check(guardia.Validar(Path.Combine(temp, "a.tmp"), ahora).Aceptada,
                  "acepta un archivo dentro de la raiz permitida");

            Check(guardia.Validar(Path.Combine(corpus, "secreto.txt"), ahora).Motivo
                      == MotivoRechazo.FueraDeRaicesPermitidas,
                  "rechaza un archivo fuera de la raiz permitida");

            // El caso que rompe una comparacion por prefijo de texto.
            Directory.CreateDirectory(temp + "-vecino");
            File.WriteAllText(Path.Combine(temp + "-vecino", "x.tmp"), "x");
            Check(guardia.Validar(Path.Combine(temp + "-vecino", "x.tmp"), ahora).Motivo
                      == MotivoRechazo.FueraDeRaicesPermitidas,
                  "rechaza 'temp-vecino' pese a compartir prefijo con 'temp'");

            Check(guardia.Validar(Path.Combine(temp, "..", "secreto.txt"), ahora).Motivo
                      == MotivoRechazo.FueraDeRaicesPermitidas,
                  "rechaza un intento de salir con '..'");

            string enlace = Path.Combine(temp, "enlace-peligroso.tmp");
            if (File.Exists(enlace))
            {
                Check(guardia.Validar(enlace, ahora).Motivo == MotivoRechazo.EsEnlaceSimbolico,
                      "rechaza un enlace simbolico que apunta fuera");
            }

            // Union NTFS (junction): no requiere privilegios, a diferencia del
            // enlace simbolico. Un archivo ACCEDIDO A TRAVES de la union no lleva
            // ReparsePoint propio, pero vive fuera de la raiz permitida.
            string fuera = Path.Combine(corpus, "fuera-de-union");
            Directory.CreateDirectory(fuera);
            string victima = Path.Combine(fuera, "victima.tmp");
            File.WriteAllText(victima, "no debe borrarse");
            string union = Path.Combine(temp, "union-peligrosa");
            if (CrearUnion(union, fuera))
            {
                Check(guardia.Validar(Path.Combine(union, "victima.tmp"), ahora).Motivo
                          == MotivoRechazo.EsEnlaceSimbolico,
                      "rechaza un archivo alcanzado a traves de una union NTFS");
            }

            // Un subdirectorio DENTRO de la raiz: llega hasta la comprobacion de tipo.
            Check(guardia.Validar(Path.Combine(temp, "sub"), ahora).Motivo == MotivoRechazo.EsDirectorio,
                  "rechaza un subdirectorio dentro de la raiz permitida");

            // La raiz permitida en si misma tampoco es borrable: se descarta antes,
            // al exigir que la ruta este estrictamente DENTRO de la raiz.
            Check(guardia.Validar(temp, ahora).Motivo == MotivoRechazo.FueraDeRaicesPermitidas,
                  "rechaza la propia raiz permitida");

            // Lista negra: aunque la raiz permitida sea amplia.
            var guardiaAmplio = new GuardiaDeRutas(TimeSpan.Zero).PermitirRaiz(corpus);
            Check(guardiaAmplio.Validar(Path.Combine(corpus, "Documents", "importante.docx"), ahora).Motivo
                      == MotivoRechazo.EnListaNegra,
                  "rechaza 'Documents' aunque la raiz permitida lo incluya");

            var guardiaViejo = new GuardiaDeRutas(TimeSpan.FromDays(1)).PermitirRaiz(temp);
            Check(guardiaViejo.Validar(Path.Combine(temp, "a.tmp"), ahora).Motivo
                      == MotivoRechazo.DemasiadoReciente,
                  "rechaza un archivo modificado hace menos que la antiguedad minima");

            bool lanzo = false;
            try { new GuardiaDeRutas(TimeSpan.Zero).PermitirRaiz(Path.GetPathRoot(corpus)!); }
            catch (ArgumentException) { lanzo = true; }
            Check(lanzo, "se niega a aceptar la raiz de un volumen como raiz de limpieza");

            Console.WriteLine();
            return Task.CompletedTask;
        }

        // ============================================================
        //  2. LIMPIEZA EN DOS FASES
        // ============================================================
        private static async Task ProbarLimpieza(string corpus, IReportWriter reportes)
        {
            Console.WriteLine("2. Limpieza: vista previa obligatoria y token");

            var catalogo = CatalogoDeRutas.Predeterminado();
            var bases = ResolutorDeBases.DeCorpus(corpus);
            var borrador = new BorradorReal();       // borrado real contra el corpus

            var limpiador = new LimpiadorDeBasura(catalogo, bases, borrador, reportes, esAdministrador: false);

            VistaPreviaLimpieza vista = await limpiador.PrepararVistaPreviaAsync().ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(Sangrar(vista.Describir()));

            Check(vista.TotalArchivos == 5,
                  "la vista previa encuentra los 5 archivos limpiables",
                  "encontrados: " + vista.TotalArchivos);

            Check(vista.Elementos.All(e => !e.Ruta.Contains("Documents", StringComparison.Ordinal)),
                  "la vista previa no incluye nada de Documents");

            Check(vista.Elementos.All(e => !e.Ruta.EndsWith("secreto.txt", StringComparison.Ordinal)),
                  "la vista previa no incluye el archivo fuera de las reglas");

            Check(vista.Elementos.Any(e => e.Ruta.Contains("Profile 1", StringComparison.Ordinal)),
                  "el comodin de subruta encontro el perfil 'Profile 1'");

            // --- El token no es decorativo ---
            var tokenAjeno = TokenConfirmacion.Emitir(
                new[] { ("/otra/cosa", 1L, DateTimeOffset.Now) }, DateTimeOffset.Now);

            bool rechazado = false;
            try { await limpiador.EjecutarAsync(vista, tokenAjeno).ConfigureAwait(false); }
            catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado, "rechaza ejecutar con un token que no corresponde a la vista previa");

            var tokenCaducado = TokenConfirmacion.Emitir(
                vista.Elementos.Select(e => e.Huella),
                DateTimeOffset.Now - TokenConfirmacion.Vigencia - TimeSpan.FromMinutes(1));

            rechazado = false;
            try { await limpiador.EjecutarAsync(vista, tokenCaducado).ConfigureAwait(false); }
            catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado, "rechaza ejecutar con un token caducado");

            // Modificar un archivo despues de la vista previa debe excluirlo (TOCTOU).
            string cambiado = vista.Elementos.First(e => e.Ruta.EndsWith("a.tmp", StringComparison.Ordinal)).Ruta;
            File.AppendAllText(cambiado, "cambio posterior a la vista previa");

            ResultadoBorrado resultado = await limpiador
                .EjecutarAsync(vista, vista.Token)
                .ConfigureAwait(false);

            Check(File.Exists(cambiado),
                  "no borra un archivo que cambio despues de la vista previa (TOCTOU)");

            Check(resultado.Eliminados == 4,
                  "borro los 4 archivos restantes",
                  "eliminados: " + resultado.Eliminados);

            Check(File.Exists(Path.Combine(corpus, "Documents", "importante.docx")),
                  "TRAMPA: Documents/importante.docx sigue intacto");

            Check(File.Exists(Path.Combine(corpus, "secreto.txt")),
                  "TRAMPA: secreto.txt sigue intacto");

            Console.WriteLine();
        }

        // ============================================================
        //  2b. UNA CARPETA SIN PERMISOS NO ABORTA LA REGLA
        // ============================================================
        // Hallazgo real (VM, 2026-10-21): un solo directorio inaccesible en
        // %TEMP% detenia el recorrido completo y la regla acababa con 0 archivos.
        private static async Task ProbarCarpetaInaccesible(string corpus, IReportWriter reportes)
        {
            Console.WriteLine("2b. Limpieza: una carpeta sin permisos se omite y el resto sigue");

            if (!OperatingSystem.IsWindows())
            {
                Console.WriteLine("  [AVISO] Prueba de ACL solo en Windows; no ejecutada.");
                Console.WriteLine();
                return;
            }

            string temp = Path.Combine(corpus, "temp");
            string bloqueada = Path.Combine(temp, "aaa-bloqueada");
            string usuario = Environment.UserDomainName + "\\" + Environment.UserName;

            Escribir(temp, "aaa-bloqueada/x.tmp", Patron('Z', 2048));
            Escribir(temp, "zzz-libre/y.tmp", Patron('Y', 2048));
            Escribir(temp, "w.tmp", Patron('W', 2048));

            try
            {
                if (!EjecutarIcacls($"\"{bloqueada}\" /deny \"{usuario}\":(OI)(CI)(RD,RX)"))
                {
                    Console.WriteLine("  [AVISO] No se pudo aplicar el ACL de denegacion; prueba no ejecutada.");
                    return;
                }

                bool inaccesible = false;
                try { _ = Directory.GetFiles(bloqueada); }
                catch (UnauthorizedAccessException) { inaccesible = true; }
                if (!inaccesible)
                {
                    Console.WriteLine("  [AVISO] La carpeta sigue siendo legible con este token; prueba no ejecutada.");
                    return;
                }

                var limpiador = new LimpiadorDeBasura(
                    CatalogoDeRutas.Predeterminado(), ResolutorDeBases.DeCorpus(corpus),
                    new BorradorReal(), reportes, esAdministrador: false);
                VistaPreviaLimpieza vista = await limpiador.PrepararVistaPreviaAsync().ConfigureAwait(false);

                Check(vista.Elementos.Any(e => e.Ruta.EndsWith("w.tmp", StringComparison.Ordinal)),
                      "sigue encontrando archivos de la carpeta raiz");
                Check(vista.Elementos.Any(e => e.Ruta.EndsWith("y.tmp", StringComparison.Ordinal)),
                      "sigue encontrando archivos de carpetas posteriores a la bloqueada");
                Check(vista.RutasOmitidas.Any(r => r.Contains("aaa-bloqueada", StringComparison.Ordinal)),
                      "la carpeta sin permisos queda anotada como omitida (no como limpia)");
                Check(vista.RutasOmitidas.All(r => !r.Contains("recorrido interrumpido", StringComparison.Ordinal)),
                      "ya no se interrumpe el recorrido completo");
            }
            finally
            {
                EjecutarIcacls($"\"{bloqueada}\" /remove:d \"{usuario}\"");
            }

            Console.WriteLine();
        }

        private static bool EjecutarIcacls(string argumentos)
        {
            try
            {
                using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("icacls", argumentos)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                })!;
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0;
            }
            catch (System.ComponentModel.Win32Exception) { return false; }
        }

        // ============================================================
        //  3. DUPLICADOS POR CONTENIDO
        // ============================================================
        private static async Task ProbarDuplicados(string corpus, IReportWriter reportes)
        {
            Console.WriteLine("3. Duplicados: por contenido, nunca por nombre ni tamano");

            var detector = new DetectorDuplicados(reportes);
            DetectorDuplicados.Resultado r = await detector
                .AnalizarAsync(new[] { Path.Combine(corpus, "dup") })
                .ConfigureAwait(false);

            Console.WriteLine();
            foreach (GrupoDuplicados g in r.Grupos)
            {
                Console.WriteLine($"    grupo {g.Hash[..12]}…  {g.Copias} copias  {g.BytesPorArchivo} B c/u");
                Console.WriteLine($"      conservar: {Rel(corpus, g.Conservar)}");
                foreach (string s in g.Sobrantes) Console.WriteLine($"      sobrante : {Rel(corpus, s)}");
            }
            Console.WriteLine();

            Check(r.Grupos.Count == 2, "encuentra exactamente 2 grupos", "grupos: " + r.Grupos.Count);

            GrupoDuplicados? grandes = r.Grupos.FirstOrDefault(g => g.BytesPorArchivo == 32_768);
            Check(grandes is not null && grandes.Copias == 2,
                  "agrupa grande-a y grande-b, y DESCARTA grande-c",
                  "grande-c comparte tamano y cabecera de 8 KB: solo el hash completo lo separa");

            Check(grandes is not null && grandes.Rutas.All(p => !p.EndsWith("grande-c.bin", StringComparison.Ordinal)),
                  "grande-c.bin no esta en el grupo");

            GrupoDuplicados? seis = r.Grupos.FirstOrDefault(g => g.BytesPorArchivo == 6000);
            Check(seis is not null
                  && seis.Rutas.Any(p => p.EndsWith("copia-vieja.dat", StringComparison.Ordinal))
                  && seis.Rutas.Any(p => p.EndsWith("respaldo-2024.dat", StringComparison.Ordinal)),
                  "agrupa dos archivos con NOMBRES distintos y contenido igual");

            Check(r.Grupos.All(g => !g.Rutas.Any(p => p.EndsWith("informe.txt", StringComparison.Ordinal))),
                  "NO agrupa dos 'informe.txt' con el mismo nombre y distinto contenido");

            Check(r.Grupos.All(g => g.BytesPorArchivo >= 4096),
                  "ignora los archivos por debajo del minimo de 4 KB");

            Check(r.ArchivosHasheadosCompletos == 3,
                  "solo 3 archivos llegaron al hash completo",
                  "hasheados: " + r.ArchivosHasheadosCompletos + " de " + r.ArchivosAnalizados + " analizados");

            Check(r.Grupos.All(g => g.Rutas.Count == g.Rutas.Distinct().Count()),
                  "ningun grupo repite la misma ruta");
        }

        // ============================================================
        //  4. TRITURADOR
        // ============================================================
        private sealed class MedioFalso : IDetectorDeMedio
        {
            private readonly MedioDeAlmacenamiento _m;
            public MedioFalso(MedioDeAlmacenamiento m) { _m = m; }
            public MedioDeAlmacenamiento Detectar(string ruta) => _m;
        }

        private static async Task ProbarTrituracion(string corpus, IReportWriter reportes)
        {
            Console.WriteLine();
            Console.WriteLine("4. Triturador: sobrescritura, vista previa y token");

            // --- Sobrescritor, aislado ---
            string pruebaSobre = Path.Combine(corpus, "triturar-unitario.bin");
            byte[] original = Patron('A', 100_000);
            File.WriteAllBytes(pruebaSobre, original);
            using (var f = new FileStream(pruebaSobre, FileMode.Open, FileAccess.Write, FileShare.None))
                Sobrescritor.Sobrescribir(f);
            byte[] tras = File.ReadAllBytes(pruebaSobre);
            Check(tras.Length == original.Length, "sobrescribir conserva el largo del archivo");
            Check(tras.Count(b => b == (byte)'A') < original.Length / 100,
                  "sobrescribir destruye el contenido original",
                  "bytes 'A' que sobreviven: " + tras.Count(b => b == (byte)'A') + " de " + tras.Length);

            string renombrado = Sobrescritor.Renombrar(pruebaSobre, 3);
            Check(!File.Exists(pruebaSobre) && File.Exists(renombrado)
                  && !Path.GetFileName(renombrado).Contains("triturar", StringComparison.Ordinal),
                  "renombrar quita el nombre original del directorio");
            File.Delete(renombrado);

            // --- Corpus del triturador ---
            string carpeta = Path.Combine(corpus, "triturar", "Documents");   // carpeta de usuario a proposito
            Directory.CreateDirectory(carpeta);

            string normal    = Path.Combine(carpeta, "contrato.pdf");
            string pequeno   = Path.Combine(carpeta, "nota.txt");
            string soloLect  = Path.Combine(carpeta, "solo-lectura.dat");
            string bloqueado = Path.Combine(carpeta, "en-uso.dat");
            string cambiado  = Path.Combine(carpeta, "cambia.dat");
            File.WriteAllBytes(normal, Patron('N', 20_000));
            File.WriteAllBytes(pequeno, Patron('p', 100));
            File.WriteAllBytes(soloLect, Patron('R', 5_000));
            File.SetAttributes(soloLect, FileAttributes.ReadOnly);
            File.WriteAllBytes(bloqueado, Patron('B', 5_000));
            File.WriteAllBytes(cambiado, Patron('C', 5_000));

            var elegidos = new[] { normal, pequeno, soloLect, bloqueado, cambiado, normal /* duplicada */,
                                   carpeta /* directorio */, Path.Combine(carpeta, "no-existe.bin") };

            var triturador = new Triturador(reportes, new MedioFalso(MedioDeAlmacenamiento.Ssd));
            VistaPreviaTrituracion vista = await triturador.PrepararVistaPreviaAsync(elegidos).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(Sangrar(vista.Describir()));

            Check(vista.TotalArchivos == 5, "la vista previa acepta 5 archivos (sin duplicar la repetida)",
                  "aceptados: " + vista.TotalArchivos);
            Check(vista.RutasOmitidas.Count == 2, "la vista previa omite el directorio y el inexistente",
                  "omitidos: " + vista.RutasOmitidas.Count);
            Check(new[] { normal, pequeno, soloLect, bloqueado, cambiado }.All(File.Exists),
                  "la vista previa no borra nada");
            Check(vista.Advertencias.Any(a => a.Contains("SSD", StringComparison.Ordinal)),
                  "avisa de que en SSD la sobrescritura no garantiza el borrado");
            Check(vista.Advertencias.Any(a => a.Contains("$MFT", StringComparison.Ordinal)),
                  "avisa de los archivos residentes en la $MFT");

            var vistaHdd = await new Triturador(reportes, new MedioFalso(MedioDeAlmacenamiento.Hdd))
                .PrepararVistaPreviaAsync(new[] { normal }).ConfigureAwait(false);
            Check(!vistaHdd.Advertencias.Any(a => a.Contains("SSD", StringComparison.Ordinal)),
                  "en disco magnetico no muestra la advertencia de SSD");

            var vistaDesc = await new Triturador(reportes)
                .PrepararVistaPreviaAsync(new[] { normal }).ConfigureAwait(false);
            Check(vistaDesc.Medio == MedioDeAlmacenamiento.Desconocido
                  && vistaDesc.Advertencias.Any(a => a.Contains("caso peor", StringComparison.Ordinal)),
                  "medio desconocido se trata como el caso peor");

            // --- El token no es decorativo ---
            var ajeno = TokenConfirmacion.Emitir(new[] { ("/otra/cosa", 1L, DateTimeOffset.Now) }, DateTimeOffset.Now);
            bool rechazado = false;
            try { await triturador.EjecutarAsync(vista, ajeno).ConfigureAwait(false); }
            catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado && File.Exists(normal), "rechaza un token ajeno y no toca ningun archivo");

            // --- Trampas entre la vista previa y la ejecucion ---
            File.AppendAllText(cambiado, "cambio posterior a la vista previa");
            using var cerrojo = new FileStream(bloqueado, FileMode.Open, FileAccess.Read, FileShare.None);

            ResultadoBorrado r = await triturador.EjecutarAsync(vista, vista.Token).ConfigureAwait(false);

            Console.WriteLine();
            foreach (string o in r.Omitidos) Console.WriteLine("    omitido: " + Path.GetFileName(o.Split(" — ")[0]) + " — " + o.Split(" — ").Last());
            Console.WriteLine();

            Check(r.Eliminados == 3, "tritura los 3 archivos validos (normal, pequeno, solo lectura)",
                  "triturados: " + r.Eliminados);
            Check(!File.Exists(normal) && !File.Exists(pequeno) && !File.Exists(soloLect),
                  "los triturados ya no existen con su nombre");
            Check(Directory.GetFiles(carpeta).Length == 2,
                  "no quedan archivos renombrados de sobra en la carpeta",
                  "archivos en la carpeta: " + string.Join(", ", Directory.GetFiles(carpeta).Select(Path.GetFileName)));
            Check(File.Exists(cambiado), "no tritura un archivo que cambio despues de la vista previa");
            Check(File.Exists(bloqueado), "no tritura un archivo abierto por otro proceso");
            cerrojo.Dispose();
            Check(File.ReadAllBytes(bloqueado).AsSpan().SequenceEqual(Patron('B', 5_000)),
                  "el archivo bloqueado conserva su contenido: nunca se sobrescribio");

            // --- Guardia: la opcion de carpetas de usuario ---
            var ahora = DateTimeOffset.Now;
            string docs = Path.Combine(corpus, "triturar", "Documents", "cambia.dat");
            Check(new GuardiaDeRutas(TimeSpan.Zero).PermitirRaiz(carpeta).Validar(docs, ahora).Motivo
                      == MotivoRechazo.EnListaNegra,
                  "el guardia del limpiador SIGUE prohibiendo 'Documents' (valor por defecto intacto)");
            Check(new GuardiaDeRutas(TimeSpan.Zero, permitirCarpetasDeUsuario: true)
                      .PermitirRaiz(carpeta).Validar(docs, ahora).Aceptada,
                  "con la opcion del triturador, 'Documents' se permite");

            string sys = Path.Combine(corpus, "triturar", "System32");
            Directory.CreateDirectory(sys);
            string enSys = Path.Combine(sys, "x.dll");
            File.WriteAllText(enSys, "x");
            Check(new GuardiaDeRutas(TimeSpan.Zero, permitirCarpetasDeUsuario: true)
                      .PermitirRaiz(sys).Validar(enSys, ahora).Motivo == MotivoRechazo.EnListaNegra,
                  "con la opcion del triturador, 'System32' sigue prohibido");

            if (OperatingSystem.IsWindows())
            {
                string win = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "x.tmp");
                var v = await triturador.PrepararVistaPreviaAsync(new[] { win }).ConfigureAwait(false);
                Check(v.TotalArchivos == 0 && v.RutasOmitidas.Any(o => o.Contains("Windows", StringComparison.Ordinal)),
                      "rechaza triturar dentro de la carpeta de Windows");

                string enRaiz = Path.Combine(Path.GetPathRoot(corpus)!, "nexo-no-existe.tmp");
                var v2 = await triturador.PrepararVistaPreviaAsync(new[] { enRaiz }).ConfigureAwait(false);
                Check(v2.TotalArchivos == 0, "rechaza un archivo en la raiz de un volumen");
            }
        }

        // ============================================================
        //  5. INICIO — codec y reglas (con un registro en memoria)
        // ============================================================
        private sealed class Eventos_ : IReportWriter
        {
            public List<NexoEvent> Lista { get; } = new List<NexoEvent>();
            public Task<NoteRef> EscribirAsync(NexoEvent evento, System.Threading.CancellationToken ct = default)
            {
                Lista.Add(evento);
                return Task.FromResult(new NoteRef(evento.Id, "(memoria)", evento.Titulo, false));
            }
            public Task InicializarVaultAsync(System.Threading.CancellationToken ct = default) => Task.CompletedTask;
        }

        private sealed class RegistroFalso : IRegistroInicio
        {
            public List<EntradaDeInicio> Entradas { get; } = new List<EntradaDeInicio>();
            public Dictionary<string, byte[]> Escrituras { get; } = new Dictionary<string, byte[]>();
            public bool Denegar { get; set; }

            public IReadOnlyList<EntradaDeInicio> Enumerar() => Entradas;

            public void EscribirEstado(EntradaDeInicio entrada, byte[] datos)
            {
                if (Denegar) throw new UnauthorizedAccessException();
                Escrituras[entrada.Id] = datos;
            }
        }

        private static async Task ProbarInicio()
        {
            Console.WriteLine();
            Console.WriteLine("5. Inicio: codec de StartupApproved y reglas");

            Check(StartupApprovedCodec.Leer(null) == EstadoDeInicio.Habilitada,
                  "sin valor en StartupApproved, la entrada cuenta como habilitada");
            Check(StartupApprovedCodec.Leer(new byte[] { 0x02, 0, 0, 0 }) == EstadoDeInicio.Habilitada
                  && StartupApprovedCodec.Leer(new byte[] { 0x06, 0, 0, 0 }) == EstadoDeInicio.Habilitada,
                  "0x02 y 0x06 se leen como habilitada");
            Check(StartupApprovedCodec.Leer(new byte[] { 0x03, 0, 0, 0 }) == EstadoDeInicio.Deshabilitada,
                  "0x03 se lee como deshabilitada");
            Check(StartupApprovedCodec.Leer(new byte[] { 0x09 }) == EstadoDeInicio.Desconocida
                  && StartupApprovedCodec.Leer(Array.Empty<byte>()) == EstadoDeInicio.Desconocida,
                  "un valor que no reconoce se lee como desconocido, no como habilitado");

            var ahora = new DateTimeOffset(2026, 10, 4, 15, 30, 0, TimeSpan.FromHours(-3));
            byte[] off = StartupApprovedCodec.Escribir(false, ahora);
            byte[] on = StartupApprovedCodec.Escribir(true, ahora);
            Check(off.Length == 12 && off[0] == 0x03 && on.Length == 12 && on[0] == 0x02
                  && on.Skip(1).All(b => b == 0),
                  "escribe 12 bytes: 0x03 deshabilitar, 0x02 habilitar con el resto a cero");
            Check(StartupApprovedCodec.FechaDeshabilitado(off) == ahora,
                  "el FILETIME de deshabilitado hace ida y vuelta exacta");
            Check(StartupApprovedCodec.FechaDeshabilitado(on) is null, "habilitada no tiene fecha");

            var registro = new RegistroFalso();
            var normal = new EntradaDeInicio("Spotify", "x", OrigenDeInicio.RunUsuario, EstadoDeInicio.Habilitada);
            var defender = new EntradaDeInicio("SecurityHealth", "x", OrigenDeInicio.RunMaquina, EstadoDeInicio.Habilitada);
            var deMaquina = new EntradaDeInicio("Driver", "x", OrigenDeInicio.RunMaquina, EstadoDeInicio.Habilitada);
            var raro = new EntradaDeInicio("Raro", "x", OrigenDeInicio.RunUsuario, EstadoDeInicio.Desconocida);
            var apagada = new EntradaDeInicio("Vieja", "x", OrigenDeInicio.RunUsuario, EstadoDeInicio.Deshabilitada);
            registro.Entradas.AddRange(new[] { normal, defender, deMaquina, raro, apagada });

            var eventos = new Eventos_();
            var opt = new OptimizadorDeInicio(registro, eventos, esAdministrador: true);

            ResultadoCambioInicio r = await opt.CambiarEstadoAsync(normal, false).ConfigureAwait(false);
            Check(r.Aplicado && registro.Escrituras[normal.Id][0] == 0x03, "deshabilita una entrada normal");

            r = await opt.CambiarEstadoAsync(defender, false).ConfigureAwait(false);
            Check(!r.Aplicado && !registro.Escrituras.ContainsKey(defender.Id),
                  "SecurityHealth esta protegida: no se deshabilita ni siendo administrador");

            r = await opt.CambiarEstadoAsync(defender, true).ConfigureAwait(false);
            Check(r.Motivo is not null && r.Motivo.Contains("ya estaba", StringComparison.Ordinal),
                  "habilitar una protegida que ya esta habilitada no hace nada");

            r = await opt.CambiarEstadoAsync(raro, false).ConfigureAwait(false);
            Check(!r.Aplicado && !registro.Escrituras.ContainsKey(raro.Id),
                  "no toca una entrada con indicador desconocido");

            r = await opt.CambiarEstadoAsync(apagada, false).ConfigureAwait(false);
            Check(!r.Aplicado && !registro.Escrituras.ContainsKey(apagada.Id),
                  "no reescribe lo que ya estaba deshabilitado");

            var sinAdmin = new OptimizadorDeInicio(registro, eventos, esAdministrador: false);
            r = await sinAdmin.CambiarEstadoAsync(deMaquina, false).ConfigureAwait(false);
            Check(!r.Aplicado && !registro.Escrituras.ContainsKey(deMaquina.Id),
                  "una entrada de maquina exige administrador");

            registro.Denegar = true;
            r = await opt.CambiarEstadoAsync(deMaquina, false).ConfigureAwait(false);
            Check(!r.Aplicado && r.Motivo is not null && r.Motivo.Contains("denego", StringComparison.Ordinal),
                  "un acceso denegado del registro se traduce a rechazo, no a excepcion");

            Check(eventos.Lista.Count == 1 && eventos.Lista[0].Tipo == TipoEvento.InicioModificado,
                  "solo el cambio aplicado genera evento");
        }

        // ============================================================
        //  6. S.M.A.R.T.
        // ============================================================
        private sealed class FuenteFalsa : IFuenteSmart
        {
            private readonly IReadOnlyList<LecturaDeDisco> _l;
            public FuenteFalsa(params LecturaDeDisco[] l) { _l = l; }
            public IReadOnlyList<LecturaDeDisco> Leer() => _l;
        }

        /// <summary>Construye el bloque de 512 bytes de MSStorageDriver_FailurePredictData.</summary>
        private static byte[] BloqueSmart(params (byte Id, ulong Crudo)[] atributos)
        {
            var b = new byte[512];
            int i = 0;
            foreach (var (id, crudo) in atributos)
            {
                int o = SmartParser.OffsetPrimerAtributo + i++ * SmartParser.LargoAtributo;
                b[o] = id;
                b[o + 1] = 0x33;            // flags
                b[o + 3] = 100;             // valor
                b[o + 4] = 99;              // peor
                for (int k = 0; k < 6; k++) b[o + 5 + k] = (byte)((crudo >> (8 * k)) & 0xFF);
            }
            return b;
        }

        private static LecturaDeDisco Lectura(string modelo, bool? predice, params (byte, ulong)[] attrs)
        {
            SmartParser.TryAnalizar(BloqueSmart(attrs), out var lista);
            return new LecturaDeDisco(modelo, "****1234") { PrediccionDeFallo = predice, Atributos = lista };
        }

        private static async Task ProbarSmart()
        {
            Console.WriteLine();
            Console.WriteLine("6. S.M.A.R.T.: parser y evaluador");

            // --- Parser ---
            bool ok = SmartParser.TryAnalizar(
                BloqueSmart((5, 8), (9, 0x060504030201), (197, 3)), out var attrs);
            Check(ok && attrs.Count == 3, "el parser lee 3 atributos y se salta los huecos (id 0)");
            Check(attrs.First(a => a.Id == 9).Crudo == 0x060504030201UL,
                  "el crudo de 6 bytes se interpreta little-endian");
            Check(attrs.First(a => a.Id == 5).Valor == 100 && attrs.First(a => a.Id == 5).Peor == 99
                  && attrs.First(a => a.Id == 5).Flags == 0x33,
                  "valor, peor y flags salen de su offset");
            Check(!SmartParser.TryAnalizar(new byte[100], out _) && !SmartParser.TryAnalizar(null, out _),
                  "un bloque mas corto que la estructura, o nulo, se rechaza sin excepcion");

            // --- Evaluador ---
            var sano = EvaluadorDeSalud.Evaluar(Lectura("Sano", false, (5, 0), (197, 0), (9, 5000)));
            Check(sano.Severidad == Severidad.Info && sano.Alertas.Count == 0,
                  "un disco con todo a cero no genera alertas");

            var reasig = EvaluadorDeSalud.Evaluar(Lectura("R", false, (5, 8)));
            Check(reasig.Severidad == Severidad.Media, "sectores reasignados > 0 sin historial: severidad media");

            var reasigCrece = EvaluadorDeSalud.Evaluar(Lectura("R", false, (5, 8)), Lectura("R", false, (5, 2)));
            Check(reasigCrece.Severidad == Severidad.Alta
                  && reasigCrece.Alertas.Any(a => a.Contains("aumentando", StringComparison.Ordinal)),
                  "sectores reasignados que aumentan: severidad alta");

            var reasigEstable = EvaluadorDeSalud.Evaluar(Lectura("R", false, (5, 8)), Lectura("R", false, (5, 8)));
            Check(reasigEstable.Severidad == Severidad.Media, "reasignados estables: se mantiene media");

            var pend = EvaluadorDeSalud.Evaluar(Lectura("P", false, (197, 3)));
            Check(pend.Severidad == Severidad.Alta, "sectores pendientes > 0: alta");

            var pendCrece = EvaluadorDeSalud.Evaluar(Lectura("P", false, (197, 3)), Lectura("P", false, (197, 1)));
            Check(pendCrece.Severidad == Severidad.Critica, "sectores pendientes en aumento: critica (el mas predictivo)");

            Check(EvaluadorDeSalud.Evaluar(Lectura("U", false, (187, 1))).Severidad == Severidad.Alta
                  && EvaluadorDeSalud.Evaluar(Lectura("O", false, (198, 1))).Severidad == Severidad.Alta,
                  "187 y 198 mayores que cero: alta");

            Check(EvaluadorDeSalud.Evaluar(Lectura("T", false, (188, 7))).Alertas.Count == 0,
                  "188 sin lectura anterior no alerta: no se asume crecimiento");
            Check(EvaluadorDeSalud.Evaluar(Lectura("T", false, (188, 9)), Lectura("T", false, (188, 7))).Severidad
                  == Severidad.Media,
                  "188 en aumento: media");

            var predice = EvaluadorDeSalud.Evaluar(Lectura("F", true));
            Check(predice.Severidad == Severidad.Critica && predice.Alertas.Count == 1,
                  "la bandera PredictFailure activa lleva a critica");

            // --- Monitor y evento ---
            var eventos = new Eventos_();
            var monitor = new MonitorDeSalud(
                new FuenteFalsa(
                    Lectura("Disco Sano", false, (5, 0)),
                    Lectura("Disco Dudoso", false, (197, 4)),
                    Lectura("Disco Muerto", true)),
                eventos);

            var res = await monitor.EvaluarAsync().ConfigureAwait(false);
            Check(res.Count == 3 && eventos.Lista.Count == 3, "publica un evento por disco");

            NexoEvent evSano = eventos.Lista.First(e => e.Titulo.Contains("Sano", StringComparison.Ordinal));
            NexoEvent evDudoso = eventos.Lista.First(e => e.Titulo.Contains("Dudoso", StringComparison.Ordinal));
            NexoEvent evMuerto = eventos.Lista.First(e => e.Titulo.Contains("Muerto", StringComparison.Ordinal));

            Check(evSano.Severidad == Severidad.Info && evSano.Cuerpo is null, "disco sano: info y sin aviso");
            Check(evDudoso.Severidad == Severidad.Alta
                  && evDudoso.Cuerpo is not null && evDudoso.Cuerpo.Contains("[!warning]", StringComparison.Ordinal)
                  && evDudoso.Titulo.Contains("con alertas", StringComparison.Ordinal),
                  "disco con atributos malos: alta, con callout de advertencia, aunque PredictFailure sea falso");
            Check(evMuerto.Severidad == Severidad.Critica
                  && evMuerto.Cuerpo is not null && evMuerto.Cuerpo.Contains("[!danger]", StringComparison.Ordinal),
                  "prediccion de fallo: critica, con callout de peligro");

            // Sin datos NO es "correcta": es un estado propio, dicho con todas las letras.
            var evSin = new Eventos_();
            await new MonitorDeSalud(
                    new FuenteFalsa(new LecturaDeDisco("Disco Mudo", "****0000")
                        { Limitaciones = new[] { "Puente USB" } }),
                    evSin)
                .EvaluarAsync().ConfigureAwait(false);
            Check(evSin.Lista[0].Titulo.Contains("sin datos suficientes", StringComparison.Ordinal)
                  && !evSin.Lista[0].Titulo.Contains("correcta", StringComparison.Ordinal)
                  && evSin.Lista[0].Cuerpo is not null && evSin.Lista[0].Cuerpo!.Contains("NO significa", StringComparison.Ordinal),
                  "un disco que no se pudo leer se reporta 'sin datos suficientes', nunca 'correcta'");

            // La firma antigua de SaludDisco sigue funcionando (compatibilidad).
            NexoEvent antiguo = Eventos.Limpieza.SaludDisco("X", "****0000", false, 40, 3, 1000);
            Check(antiguo.Severidad == Severidad.Info && antiguo.Cuerpo is null,
                  "SaludDisco con la firma anterior conserva su comportamiento");

            // El crecimiento se detecta a traves del monitor con lecturas anteriores.
            var previas = new Dictionary<string, LecturaDeDisco>
            {
                [MonitorDeSalud.Clave(Lectura("Disco Dudoso", false))] = Lectura("Disco Dudoso", false, (197, 1))
            };
            var res2 = await new MonitorDeSalud(new FuenteFalsa(Lectura("Disco Dudoso", false, (197, 4))), new Eventos_())
                .EvaluarAsync(previas).ConfigureAwait(false);
            Check(res2[0].Evaluacion.Severidad == Severidad.Critica,
                  "el monitor usa la lectura anterior para detectar crecimiento");

            await ProbarHistorialDeSalud().ConfigureAwait(false);
        }

        private static async Task ProbarHistorialDeSalud()
        {
            string ruta = Path.Combine(Path.GetTempPath(), "nexo-historial-" + Guid.NewGuid().ToString("N")[..8] + ".json");
            try
            {
                var historial = new HistorialDeSalud(ruta);
                async Task<EvaluacionDeSalud> Corrida(params LecturaDeDisco[] l)
                    => (await new MonitorDeSalud(new FuenteFalsa(l), new Eventos_(), historial)
                        .EvaluarAsync().ConfigureAwait(false))[0].Evaluacion;

                var primera = await Corrida(Lectura("Disco Dudoso", false, (197, 1))).ConfigureAwait(false);
                Check(primera.Severidad == Severidad.Alta && File.Exists(ruta),
                      "historial: la primera corrida no asume crecimiento y guarda la lectura");

                var segunda = await Corrida(Lectura("Disco Dudoso", false, (197, 4))).ConfigureAwait(false);
                Check(segunda.Severidad == Severidad.Critica,
                      "historial: la segunda corrida detecta el crecimiento leyendo el archivo");

                // Una lectura sin atributos (p. ej. sin administrador) no borra el historial.
                await Corrida(new LecturaDeDisco("Disco Dudoso", "****1234")).ConfigureAwait(false);
                var guardada = historial.Cargar();
                Check(guardada.TryGetValue(MonitorDeSalud.Clave(Lectura("Disco Dudoso", false)), out var previa)
                      && previa.Atributo(197)?.Crudo == 4,
                      "historial: una lectura sin atributos no reemplaza a la anterior");

                // Un disco que hoy no aparece (USB desconectado) se conserva.
                await Corrida(Lectura("Otro Disco", false, (5, 0))).ConfigureAwait(false);
                guardada = historial.Cargar();
                Check(guardada.Count == 2, "historial: conserva los discos que no aparecen en esta corrida");

                // Un historial danado no rompe la evaluacion, se aparta y se dice.
                File.WriteAllText(ruta, "{ esto no es json");
                var eventos = new Eventos_();
                var monitor = new MonitorDeSalud(new FuenteFalsa(Lectura("Disco Dudoso", false, (197, 9))), eventos, historial);
                var res = await monitor.EvaluarAsync().ConfigureAwait(false);
                Check(res[0].Evaluacion.Severidad == Severidad.Alta
                      && monitor.AdvertenciaDeHistorial is not null
                      && File.Exists(ruta + ".corrupto")
                      && historial.Cargar().Count == 1,
                      "historial danado: se aparta como .corrupto, se evalua sin crecimiento y se rehace");
                Check(eventos.Lista[0].Campos.TryGetValue("limitaciones", out object? lim)
                      && lim is string[] arr && arr.Any(s => s.Contains("crecimiento", StringComparison.Ordinal)),
                      "historial danado: el evento dice que no se evaluo el crecimiento");
            }
            finally
            {
                foreach (string f in new[] { ruta, ruta + ".corrupto" })
                    if (File.Exists(f)) File.Delete(f);
            }
        }

        private static string Rel(string raiz, string ruta)
            => Path.GetRelativePath(raiz, ruta);

        private static string Sangrar(string texto)
            => string.Join("\n", texto.Split('\n').Select(l => l.Length > 0 ? "    " + l : l));
    }
}
