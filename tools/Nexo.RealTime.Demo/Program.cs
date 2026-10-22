using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.RealTime.Demo
{
    internal static partial class Program
    {
        private static int _fallos;
        private static readonly byte[] Marca = Encoding.ASCII.GetBytes("NEXO-MARCADOR-TIEMPO-REAL");

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-realtime-demo-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(raiz);
            try
            {
                ProbarFiltro();
                await ProbarAnalisis(raiz).ConfigureAwait(false);
                await ProbarEstabilizacion(raiz).ConfigureAwait(false);
                await ProbarNoSeFingeCobertura(raiz).ConfigureAwait(false);
                await ProbarConWatcherReal(raiz).ConfigureAwait(false);
                ProbarParserUsn();
            }
            finally
            {
                try { Directory.Delete(raiz, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static OpcionesDeTiempoReal Rapido(IReadOnlyList<string>? excluir = null, long maxBytes = 25L * 1024 * 1024,
            int pendientes = 5000, int reintentos = 3, int errores = 5)
            => new OpcionesDeTiempoReal
            {
                Estabilizacion = TimeSpan.FromMilliseconds(120), Sondeo = TimeSpan.FromMilliseconds(30),
                Excluir = excluir ?? Array.Empty<string>(), MaxBytes = maxBytes, MaxPendientes = pendientes,
                MaxReintentos = reintentos, MaxErroresSeguidos = errores
            };

        private static async Task<bool> EsperarAsync(Func<bool> cond, int ms = 5000)
        {
            for (int t = 0; t < ms; t += 25)
            {
                if (cond()) return true;
                await Task.Delay(25).ConfigureAwait(false);
            }
            return cond();
        }

        private static string Archivo(string carpeta, string nombre, byte[]? contenido = null)
        {
            Directory.CreateDirectory(carpeta);
            string r = Path.Combine(carpeta, nombre);
            File.WriteAllBytes(r, contenido ?? Encoding.ASCII.GetBytes("contenido inofensivo " + nombre));
            return r;
        }

        // ============================================================
        private static void ProbarFiltro()
        {
            Console.WriteLine("1. Filtro: que cambios merecen analisis");

            var f = new FiltroDeCambios(new OpcionesDeTiempoReal { Excluir = new[] { @"C:\ProgramData\Nexo", @"C:\Q\" } });
            Check(f.MotivoParaIgnorar(@"C:\Users\a\Downloads\setup.exe") is null, "un .exe se analiza");
            Check(f.MotivoParaIgnorar(@"C:\Users\a\Downloads\SETUP.EXE") is null, "la extension no distingue mayusculas");
            Check(f.MotivoParaIgnorar(@"C:\Users\a\x.ps1") is null && f.MotivoParaIgnorar(@"C:\Users\a\x.docm") is null, "scripts y documentos con macros tambien");
            Check(f.MotivoParaIgnorar(@"C:\Users\a\foto.jpg") is not null, "una imagen no");
            Check(f.MotivoParaIgnorar(@"C:\Users\a\LEEME") is not null && f.MotivoParaIgnorar(@"C:\Users\a\.exe") is not null,
                  "sin extension, o un nombre que es solo '.exe', no");
            Check(f.MotivoParaIgnorar(@"C:\Users\a\descarga.exe.crdownload") is not null, "una descarga a medias (.crdownload) no: su renombrado si llegara");
            Check(f.MotivoParaIgnorar(@"C:\ProgramData\Nexo\Quarantine\x.exe") == "carpeta excluida", "la carpeta de Nexo se excluye (evita el bucle)");
            Check(f.MotivoParaIgnorar(@"C:\q\sub\x.exe") == "carpeta excluida", "y las exclusiones no distinguen mayusculas ni la barra final");
            Check(f.MotivoParaIgnorar(@"C:\ProgramData\NexoOtro\x.exe") is null, "pero una carpeta que solo empieza igual NO queda excluida");
            Check(f.MotivoParaIgnorar("") is not null, "una ruta vacia se ignora");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarAnalisis(string raiz)
        {
            Console.WriteLine("2. Analisis al vuelo");

            string carpeta = Path.Combine(raiz, "a");
            string excl = Path.Combine(raiz, "excluida");
            var motor = new MotorFalso();
            var rep = new ReportesEnMemoria();
            var fuente = new FuenteManual();
            using var v = new VigilanteEnTiempoReal(motor, rep, Rapido(new[] { excl }));
            var avisados = new List<Deteccion>();
            v.Detectado += avisados.Add;
            v.Iniciar(fuente);

            string malo = Archivo(carpeta, "malo.exe", Marca.Concat(new byte[] { 1 }).ToArray());
            string limpio = Archivo(carpeta, "limpio.exe");
            string imagen = Archivo(carpeta, "foto.jpg");
            string enExcluida = Archivo(excl, "dentro.exe", Marca.ToArray());

            fuente.Emitir(malo);
            fuente.Emitir(limpio);
            fuente.Emitir(imagen);
            fuente.Emitir(enExcluida);

            Check(await EsperarAsync(() => v.Estado().Analizados == 2).ConfigureAwait(false), "se analizan el malo y el limpio", v.Estado().ToString());
            Check(v.Detecciones().Count == 1 && v.Detecciones()[0].Ruta == malo && v.Detecciones()[0].Firma == "Prueba.TiempoReal"
                  && v.Detecciones()[0].Sha256 is { Length: 64 }, "una deteccion, con su firma y su SHA-256");
            Check(avisados.Count == 1, "el evento Detectado se dispara (para notificar)");
            Check(rep.Eventos.Count(e => e.Tipo == TipoEvento.AmenazaDetectada) == 1, "y deja UNA nota de deteccion (la vigilancia no llena el vault de notas)");
            Check(motor.Llamadas == 2, "la imagen y la carpeta excluida ni llegan al motor", "llamadas " + motor.Llamadas);
            Check(File.Exists(malo), "el vigilante NO toca el archivo: solo detecta y avisa");
            Check(v.Estado().Descartados >= 2 && v.Estado().NoAnalizados == 0 && v.Estado().Perdidos == 0 && !v.Estado().MotorCaido,
                  "los contadores cuadran", v.Estado().ToString());

            // Archivo que desaparece antes de analizarlo: no hay nada que analizar y no cuenta como fallo.
            string efimero = Archivo(carpeta, "efimero.exe");
            fuente.Emitir(efimero);
            File.Delete(efimero);
            await Task.Delay(500).ConfigureAwait(false);
            Check(v.Estado().NoAnalizados == 0, "un archivo que desaparece antes de tocarle no se cuenta como no analizado");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarEstabilizacion(string raiz)
        {
            Console.WriteLine("3. Estabilizacion, duplicados y archivos bloqueados");

            string carpeta = Path.Combine(raiz, "b");
            var motor = new MotorFalso();
            var fuente = new FuenteManual();
            using var v = new VigilanteEnTiempoReal(motor, new ReportesEnMemoria(), Rapido(reintentos: 2));
            v.Iniciar(fuente);

            // Una descarga: muchos eventos del mismo archivo mientras se escribe.
            string descarga = Archivo(carpeta, "descarga.exe");
            for (int i = 0; i < 12; i++) { fuente.Emitir(descarga); await Task.Delay(30).ConfigureAwait(false); }
            Check(motor.Llamadas == 0, "mientras sigue cambiando, NO se analiza a medias");
            Check(await EsperarAsync(() => motor.Llamadas == 1).ConfigureAwait(false), "cuando deja de cambiar, se analiza");
            await Task.Delay(300).ConfigureAwait(false);
            Check(motor.Llamadas == 1, "y UNA sola vez, no una por evento", "llamadas " + motor.Llamadas);

            // Mismo contenido, otro evento: no se reanaliza.
            fuente.Emitir(descarga);
            await Task.Delay(400).ConfigureAwait(false);
            Check(motor.Llamadas == 1, "un evento sin cambio real del archivo no lo reanaliza");

            // Cambia de verdad: si se reanaliza.
            File.WriteAllText(descarga, "otro contenido distinto y mas largo");
            fuente.Emitir(descarga);
            Check(await EsperarAsync(() => motor.Llamadas == 2).ConfigureAwait(false), "si el archivo cambia de verdad, se reanaliza");

            // Bloqueado un rato: se reintenta y acaba analizandose.
            string bloqueado = Archivo(carpeta, "bloqueado.exe");
            var fs = new FileStream(bloqueado, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            fuente.Emitir(bloqueado);
            await Task.Delay(300).ConfigureAwait(false);
            long antes = v.Estado().Analizados;
            fs.Dispose();
            Check(await EsperarAsync(() => v.Estado().Analizados == antes + 1).ConfigureAwait(false),
                  "un archivo bloqueado se reintenta y se analiza cuando se libera", v.Estado().ToString());

            // Bloqueado para siempre: NO analizado (no limpio).
            string eterno = Archivo(carpeta, "eterno.exe");
            using (new FileStream(eterno, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                long na = v.Estado().NoAnalizados;
                fuente.Emitir(eterno);
                Check(await EsperarAsync(() => v.Estado().NoAnalizados == na + 1, 8000).ConfigureAwait(false),
                      "si sigue bloqueado tras los reintentos, queda contado como NO ANALIZADO", v.Estado().ToString());
                Check(v.Estado().UltimoAviso?.Contains("bloqueado") == true, "y el aviso lo explica");
            }

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarNoSeFingeCobertura(string raiz)
        {
            Console.WriteLine("4. No se finge cobertura: motor caido, desborde y eventos perdidos");

            string carpeta = Path.Combine(raiz, "c");

            // Motor caido
            var motor = new MotorFalso { Fallar = true };
            var fuente = new FuenteManual();
            using (var v = new VigilanteEnTiempoReal(motor, new ReportesEnMemoria(), Rapido(errores: 3)))
            {
                v.Iniciar(fuente);
                for (int i = 0; i < 4; i++) fuente.Emitir(Archivo(carpeta, $"m{i}.exe", Encoding.ASCII.GetBytes("x" + i)));
                Check(await EsperarAsync(() => v.Estado().MotorCaido).ConfigureAwait(false), "tras varios fallos seguidos se declara MOTOR CAIDO");
                Check(v.Estado().Analizados == 0 && v.Estado().NoAnalizados >= 3 && v.Estado().Detecciones == 0,
                      "y lo que el motor no pudo decidir NO cuenta como analizado ni como limpio", v.Estado().ToString());

                motor.Fallar = false;
                fuente.Emitir(Archivo(carpeta, "recuperado.exe", Encoding.ASCII.GetBytes("ya funciona")));
                Check(await EsperarAsync(() => !v.Estado().MotorCaido && v.Estado().Analizados == 1).ConfigureAwait(false),
                      "cuando el motor vuelve, se recupera solo");
            }

            // Desborde: demasiados pendientes
            var motor2 = new MotorFalso();
            var fuente2 = new FuenteManual();
            var lento = new OpcionesDeTiempoReal { Estabilizacion = TimeSpan.FromSeconds(30), MaxPendientes = 3, Sondeo = TimeSpan.FromMilliseconds(30) };
            using (var v2 = new VigilanteEnTiempoReal(motor2, new ReportesEnMemoria(), lento))
            {
                v2.Iniciar(fuente2);
                for (int i = 0; i < 10; i++) fuente2.Emitir(Path.Combine(carpeta, $"p{i}.exe"));
                Check(v2.Estado().Pendientes == 3 && v2.Estado().Perdidos == 7,
                      "al pasar el maximo de pendientes, lo que se descarta se CUENTA como perdido (no se calla)", v2.Estado().ToString());
                Check(v2.Estado().UltimoAviso?.Contains("perdidos") == true, "y queda un aviso");
            }

            // La fuente pierde eventos
            var fuente3 = new FuenteManual();
            using (var v3 = new VigilanteEnTiempoReal(new MotorFalso(), new ReportesEnMemoria(), Rapido()))
            {
                v3.Iniciar(fuente3);
                fuente3.Perder("desbordo el buffer");
                Check(v3.Estado().Perdidos == 1 && v3.Estado().UltimoAviso!.Contains("desbordo"),
                      "si la fuente avisa de eventos perdidos, se cuentan");
            }

            // Archivo demasiado grande
            using (var v4 = new VigilanteEnTiempoReal(new MotorFalso(), new ReportesEnMemoria(), Rapido(maxBytes: 10)))
            {
                var f4 = new FuenteManual();
                v4.Iniciar(f4);
                f4.Emitir(Archivo(carpeta, "grande.exe", new byte[100]));
                Check(await EsperarAsync(() => v4.Estado().NoAnalizados == 1).ConfigureAwait(false), "un archivo mayor que el limite queda como NO ANALIZADO");
            }

            // Parar rapido
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var v5 = new VigilanteEnTiempoReal(new MotorFalso(), new ReportesEnMemoria(), Rapido());
            v5.Iniciar(new FuenteManual());
            v5.Dispose();
            Check(sw.Elapsed < TimeSpan.FromSeconds(3), "parar el vigilante es rapido", sw.Elapsed.TotalSeconds.ToString("0.0") + " s");
            Check(!v5.Estado().Activo, "y queda inactivo");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarConWatcherReal(string raiz)
        {
            Console.WriteLine("5. FileSystemWatcher real sobre una carpeta temporal");

            string carpeta = Path.Combine(raiz, "real");
            Directory.CreateDirectory(carpeta);
            string inexistente = Path.Combine(raiz, "no-existe");

            var motor = new MotorFalso();
            using var fuente = new FuenteFileSystemWatcher(new[] { carpeta, inexistente });
            using var v = new VigilanteEnTiempoReal(motor, new ReportesEnMemoria(), Rapido());
            v.Iniciar(fuente);

            Check(fuente.NoVigiladas.Count == 1 && fuente.NoVigiladas[0].Contains("no existe"), "una raiz que no existe se informa, no se ignora");

            string malo = Path.Combine(carpeta, "recien-creado.exe");
            File.WriteAllBytes(malo, Marca.Concat(new byte[] { 9 }).ToArray());
            Check(await EsperarAsync(() => v.Detecciones().Count == 1, 8000).ConfigureAwait(false),
                  "un archivo malo creado en la carpeta se detecta solo", v.Estado().ToString());

            // Renombrado: algo que se descargo como .tmp y se renombra a .exe
            string tmp = Path.Combine(carpeta, "descarga.tmp");
            File.WriteAllBytes(tmp, Marca.Concat(new byte[] { 7 }).ToArray());
            await Task.Delay(300).ConfigureAwait(false);
            long antes = v.Estado().Detecciones;
            File.Move(tmp, Path.Combine(carpeta, "descarga.exe"));
            Check(await EsperarAsync(() => v.Estado().Detecciones == antes + 1, 8000).ConfigureAwait(false),
                  "un .tmp que se renombra a .exe se detecta por el renombrado");

            // En una subcarpeta
            string sub = Path.Combine(carpeta, "sub", "profunda");
            Directory.CreateDirectory(sub);
            await Task.Delay(200).ConfigureAwait(false);
            File.WriteAllBytes(Path.Combine(sub, "otro.exe"), Marca.Concat(new byte[] { 5 }).ToArray());
            Check(await EsperarAsync(() => v.Estado().Detecciones == antes + 2, 8000).ConfigureAwait(false), "tambien en subcarpetas");

            Console.WriteLine();
        }
    }

    /// <summary>Fuente de cambios que el arnes dispara a mano.</summary>
    internal sealed class FuenteManual : IFuenteDeCambios
    {
        private Action<CambioDeArchivo>? _cambio;
        private Action<string>? _perder;

        public void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder) { _cambio = alCambiar; _perder = alPerder; }
        public void Emitir(string ruta, MotivoDeCambio m = MotivoDeCambio.Modificado) => _cambio!(new CambioDeArchivo(ruta, m));
        public void Perder(string motivo) => _perder!(motivo);
        public void Dispose() { }
    }

    internal sealed class MotorFalso : IMotorDeFirmas
    {
        private int _llamadas;
        public int Llamadas => Volatile.Read(ref _llamadas);
        public volatile bool Fallar;

        public string Nombre => "motor-falso";
        public Task<string> VersionAsync(CancellationToken ct = default) => Task.FromResult("falso");

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _llamadas);
            using var ms = new MemoryStream();
            await contenido.CopyToAsync(ms, ct).ConfigureAwait(false);
            if (Fallar) return ResultadoDeMotor.Fallo("motor apagado");
            return ms.ToArray().AsSpan().IndexOf(Encoding.ASCII.GetBytes("NEXO-MARCADOR-TIEMPO-REAL")) >= 0
                ? ResultadoDeMotor.Infectado("Prueba.TiempoReal")
                : ResultadoDeMotor.Limpio();
        }
    }

    internal sealed class ReportesEnMemoria : IReportWriter
    {
        private readonly List<NexoEvent> _eventos = new();
        public IReadOnlyList<NexoEvent> Eventos { get { lock (_eventos) return _eventos.ToList(); } }

        public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
        {
            lock (_eventos) _eventos.Add(evento);
            return Task.FromResult<NoteRef>(null!);
        }

        public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}
