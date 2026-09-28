using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Duplicados;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Modules.Cleanup.Platform;
using Nexo.Modules.Cleanup.Seguridad;
using Nexo.Reports;
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
    public static class Program
    {
        private static int _fallos;

        public static async Task<int> Main(string[] args)
        {
            string raiz = args.Length > 0
                ? args[0]
                : Path.Combine(Path.GetTempPath(), "nexo-cleanup-demo");

            string corpus = Path.Combine(raiz, "corpus");
            string vault = Path.Combine(raiz, "vault");

            if (Directory.Exists(raiz)) Directory.Delete(raiz, recursive: true);
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
            await ProbarDuplicados(corpus, reportes).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(_fallos == 0
                ? "TODAS LAS VERIFICACIONES PASARON"
                : _fallos + " VERIFICACIONES FALLIDAS");
            Console.WriteLine("Vault: " + vault);
            return _fallos == 0 ? 0 : 1;
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

        private static string Rel(string raiz, string ruta)
            => Path.GetRelativePath(raiz, ruta);

        private static string Sangrar(string texto)
            => string.Join("\n", texto.Split('\n').Select(l => l.Length > 0 ? "    " + l : l));
    }
}
