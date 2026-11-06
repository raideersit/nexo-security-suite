using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;

namespace Nexo.Scan.Demo
{
    /// <summary>
    /// <see cref="MotorYara"/>: portable contra un yara FALSO (este mismo ejecutable, lanzado con «--yara-falso»), y
    /// contra el <c>yara64.exe</c> REAL si NEXO_YARA_EXE apunta a el (si no, se anota como omitida, no como pasada).
    /// </summary>
    public static partial class Program
    {
        private const string MarcaDeteccion = "NEXO-YARA-DEMO";

        // -------------------------------------------------------------------------------------------------------
        // El yara falso: habla como yara64.exe (--version; «reglas archivo» -> «Regla archivo» por deteccion; exit 1 en
        // error) y decide segun el CONTENIDO del archivo que recibe.
        // -------------------------------------------------------------------------------------------------------
        private static int YaraFalso(string[] args)
        {
            string[] a = args.Skip(1).ToArray();
            if (a.Length == 1 && a[0] == "--version") { Console.Out.Write("4.6.0-falso\r\n"); return 0; }

            string archivo = a[^1];
            string texto = File.ReadAllText(archivo, Encoding.Latin1);
            if (texto.Contains("FALLA")) { Console.Error.WriteLine("error scanning " + archivo + ": could not open file"); return 1; }
            if (texto.Contains("CUELGA")) { Thread.Sleep(TimeSpan.FromSeconds(60)); return 0; }
            if (texto.Contains("BASURA")) { Console.Out.WriteLine("algo raro que no es una deteccion"); return 0; }
            if (texto.Contains("ADVERT")) { Console.Error.WriteLine("warning: algo"); return 0; }
            if (texto.Contains("DOS")) { Console.Out.WriteLine("Regla_A " + archivo); Console.Out.WriteLine("Regla_B " + archivo); return 0; }
            if (texto.Contains(MarcaDeteccion)) { Console.Out.WriteLine("Regla_Demo " + archivo); return 0; }
            return 0;
        }

        private static OpcionesDeYara OpcionesFalsas(string reglas, string temporal)
        {
            string? yo = Environment.ProcessPath;
            if (yo is null) throw new InvalidOperationException("no se conoce la ruta del proceso");
            // Con «dotnet run» el proceso es el ejecutable propio; lanzado como «dotnet x.dll», es dotnet.
            bool esDotnet = Path.GetFileNameWithoutExtension(yo).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
            string[] prefijo = esDotnet
                ? new[] { System.Reflection.Assembly.GetEntryAssembly()!.Location, "--yara-falso" }
                : new[] { "--yara-falso" };
            return new OpcionesDeYara(yo, reglas, temporal) { ArgumentosPrevios = prefijo, Timeout = TimeSpan.FromSeconds(20) };
        }

        private static async Task<ResultadoDeMotor> YaraAsync(OpcionesDeYara o, string contenido, CancellationToken ct = default)
        {
            using var s = new MemoryStream(Encoding.Latin1.GetBytes(contenido));
            return await new MotorYara(o).AnalizarAsync(s, ct).ConfigureAwait(false);
        }

        private static int ArchivosEn(string carpeta) => Directory.Exists(carpeta) ? Directory.GetFiles(carpeta).Length : 0;

        private static async Task ProbarYaraAsync(string raiz)
        {
            Console.WriteLine("YARA (MotorYara)");
            Directory.CreateDirectory(raiz);
            string reglas = Path.Combine(raiz, "reglas.yar");
            File.WriteAllText(reglas, "// reglas de prueba (el yara falso no las lee)");
            // Una carpeta CON espacio: la ruta de la copia sale en la linea de YARA y hay que reconocerla igual.
            string tmp = Path.Combine(raiz, "copias temporales");
            OpcionesDeYara o = OpcionesFalsas(reglas, tmp);

            // Entradas malas en el constructor
            Check(Lanza<ArgumentException>(() => new MotorYara(o with { Ejecutable = "yara64.exe" })), "rechaza un ejecutable con ruta relativa");
            Check(Lanza<ArgumentException>(() => new MotorYara(o with { Reglas = "reglas.yar" })), "rechaza unas reglas con ruta relativa");
            Check(Lanza<ArgumentException>(() => new MotorYara(o with { CarpetaTemporal = "tmp" })), "rechaza una carpeta temporal relativa");
            Check(Lanza<ArgumentOutOfRangeException>(() => new MotorYara(o with { Timeout = TimeSpan.Zero })), "rechaza un tiempo maximo de cero");
            Check(Lanza<ArgumentOutOfRangeException>(() => new MotorYara(o with { MaximoDeBytes = 0 })), "rechaza un tope de tamano de cero");

            var motor = new MotorYara(o);
            Check(motor.Nombre == "YARA", "se llama YARA");

            string version = await motor.VersionAsync().ConfigureAwait(false);
            Check(version == "YARA 4.6.0-falso (reglas: reglas.yar)", "VersionAsync: la version de YARA y el nombre de las reglas", version);

            // Veredictos
            ResultadoDeMotor r = await YaraAsync(o, "un archivo cualquiera").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Limpio, "sin detecciones y codigo 0: limpio");
            Check(ArchivosEn(tmp) == 0, "no queda ninguna copia temporal tras un analisis limpio");

            r = await YaraAsync(o, "hola " + MarcaDeteccion + " fin").ConfigureAwait(false);
            Check(r is { Veredicto: VeredictoDeArchivo.Infectado, Firma: "YARA.Regla_Demo" }, "una deteccion: infectado, con el nombre de la regla", r.Firma);
            Check(ArchivosEn(tmp) == 0, "no queda ninguna copia temporal tras una deteccion");

            r = await YaraAsync(o, "DOS reglas").ConfigureAwait(false);
            Check(r is { Veredicto: VeredictoDeArchivo.Infectado, Firma: "YARA.Regla_A,Regla_B" }, "dos detecciones: las dos reglas, en una sola firma", r.Firma);

            // Todo lo dudoso es error, nunca limpio
            r = await YaraAsync(o, "FALLA").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error && r.Error!.Contains("codigo 1") && r.Error.Contains("could not open file"),
                  "codigo de salida 1: error con el mensaje de YARA (nunca limpio)", r.Error);
            r = await YaraAsync(o, "BASURA").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error && r.Error!.Contains("no reconocida"),
                  "salida que no es «regla + archivo»: error (ante la duda, nunca limpio)", r.Error);
            r = await YaraAsync(o, "ADVERT").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error, "codigo 0 pero con mensajes en stderr: error, no limpio", r.Error);
            Check(ArchivosEn(tmp) == 0, "tampoco queda copia tras los errores");

            // Interpretar sin proceso
            string ruta = Path.Combine(tmp, "x.bin");
            Check(MotorYara.Interpretar(0, "", "", ruta).Veredicto == VeredictoDeArchivo.Limpio, "Interpretar: salida vacia y codigo 0 = limpio");
            Check(MotorYara.Interpretar(2, "", "", ruta).Veredicto == VeredictoDeArchivo.Error, "Interpretar: cualquier codigo distinto de 0 = error");
            Check(MotorYara.Interpretar(0, "Regla " + ruta + "\r\n", "", ruta) is { Veredicto: VeredictoDeArchivo.Infectado, Firma: "YARA.Regla" },
                  "Interpretar: acepta saltos de linea de Windows");
            Check(MotorYara.Interpretar(0, "Con espacio " + ruta, "", ruta).Veredicto == VeredictoDeArchivo.Error,
                  "Interpretar: un nombre de regla con espacio no es una deteccion valida");
            Check(MotorYara.Interpretar(0, "Regla otra-ruta.bin", "", ruta).Veredicto == VeredictoDeArchivo.Error,
                  "Interpretar: una linea sobre otro archivo no se acepta");

            // Limites
            var corto = o with { Timeout = TimeSpan.FromSeconds(1) };
            var reloj = Stopwatch.StartNew();
            r = await YaraAsync(corto, "CUELGA").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error && r.Error!.Contains("tiempo de espera") && reloj.Elapsed < TimeSpan.FromSeconds(30),
                  "un YARA colgado se mata al agotar el tiempo: error", r.Error + " (" + (int)reloj.Elapsed.TotalSeconds + " s)");
            Check(ArchivosEn(tmp) == 0, "tras matar a YARA tampoco queda copia");

            var tope = o with { MaximoDeBytes = 1024 };
            r = await YaraAsync(tope, new string('a', 5000)).ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error && r.Error!.Contains("limite"), "un archivo mas grande que el tope: error, no limpio", r.Error);
            Check(ArchivosEn(tmp) == 0, "pasarse del tope tampoco deja copia");
            r = await YaraAsync(tope, new string('a', 1024)).ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Limpio, "justo en el tope si se analiza");

            using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(700)))
            {
                bool cancelo = false;
                try { await YaraAsync(o, "CUELGA", cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { cancelo = true; }
                Check(cancelo, "cancelar el analisis cancela (y mata a YARA)");
            }
            Check(ArchivosEn(tmp) == 0, "tras cancelar tampoco queda copia");

            // El ejecutable no existe
            var sinExe = o with { Ejecutable = Path.Combine(raiz, OperatingSystem.IsWindows() ? "no-existe.exe" : "no-existe") };
            r = await YaraAsync(sinExe, "x").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error, "sin ejecutable: error, no limpio", r.Error);
            Check(await LanzaAsync<MotorNoDisponibleException>(() => new MotorYara(sinExe).VersionAsync()).ConfigureAwait(false),
                  "VersionAsync sin ejecutable: MotorNoDisponibleException");
            Check(await LanzaAsync<MotorNoDisponibleException>(() => new MotorYara(o with { Reglas = Path.Combine(raiz, "nada.yar") }).VersionAsync()).ConfigureAwait(false),
                  "VersionAsync sin archivo de reglas: MotorNoDisponibleException");
            Check(ArchivosEn(tmp) == 0, "ni siquiera los fallos de arranque dejan copia");

            // Restos de una caida
            Directory.CreateDirectory(tmp);
            string viejo = Path.Combine(tmp, "nexo-yara-aaaaaaaaaaaaaaaaaaaaaaaa.bin");
            string reciente = Path.Combine(tmp, "nexo-yara-bbbbbbbbbbbbbbbbbbbbbbbb.bin");
            string ajeno = Path.Combine(tmp, "otra-cosa.bin");
            foreach (string f in new[] { viejo, reciente, ajeno }) File.WriteAllText(f, "x");
            File.SetLastWriteTimeUtc(viejo, DateTime.UtcNow.AddHours(-3));
            File.SetLastWriteTimeUtc(ajeno, DateTime.UtcNow.AddHours(-3));
            _ = new MotorYara(o);
            Check(!File.Exists(viejo) && File.Exists(reciente) && File.Exists(ajeno),
                  "al arrancar borra solo las copias viejas del motor (no las recientes, no archivos ajenos)");
            foreach (string f in Directory.GetFiles(tmp)) File.Delete(f);

            // Dentro del escaner, igual que clamd
            string carpetaEscaneo = Path.Combine(raiz, "a-escanear");
            Directory.CreateDirectory(carpetaEscaneo);
            File.WriteAllText(Path.Combine(carpetaEscaneo, "bueno.txt"), "nada");
            File.WriteAllText(Path.Combine(carpetaEscaneo, "malo.txt"), MarcaDeteccion);
            File.WriteAllText(Path.Combine(carpetaEscaneo, "roto.txt"), "FALLA");
            ResultadoDeEscaneo res = await new EscanerBajoDemanda(new MotorYara(o), new ReportesEnMemoria())
                .EscanearAsync(new[] { carpetaEscaneo }).ConfigureAwait(false);
            Check(res.Detecciones.Count == 1 && res.Detecciones[0].Firma == "YARA.Regla_Demo" && res.Analizados == 2
                  && res.Omitidos.Count == 1 && !res.CompletamenteLimpio,
                  "en el escaner: 1 deteccion, 1 omitido por error de YARA, y nunca «completamente limpio»",
                  $"{res.Detecciones.Count} detecciones, {res.Analizados} analizados, {res.Omitidos.Count} omitidos");
            Check(res.Motor == "YARA" && res.MotorVersion.StartsWith("YARA 4.6.0-falso", StringComparison.Ordinal), "el resultado dice que motor lo analizo", res.MotorVersion);

            await ProbarYaraRealAsync(raiz).ConfigureAwait(false);
        }

        // -------------------------------------------------------------------------------------------------------
        // El yara64.exe REAL. Solo si NEXO_YARA_EXE apunta a el; si no, se dice que se omitio.
        // -------------------------------------------------------------------------------------------------------
        private static async Task ProbarYaraRealAsync(string raiz)
        {
            string? exe = Environment.GetEnvironmentVariable("NEXO_YARA_EXE");
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            {
                Console.WriteLine("  [OMITIDA] contra el yara64.exe real (defina NEXO_YARA_EXE con su ruta)");
                return;
            }

            string reglas = Path.Combine(raiz, "real.yar");
            File.WriteAllText(reglas,
                "rule Prueba_Cadena : demo { meta: severidad = \"alta\" strings: $a = \"NEXO-EICAR-DEMO\" condition: $a }\r\n" +
                "rule Otra_Regla { strings: $b = \"otra-cosa\" condition: $b }\r\n");
            string rota = Path.Combine(raiz, "rota.yar");
            File.WriteAllText(rota, "rule X { condition: nope }");
            string tmp = Path.Combine(raiz, "copias reales");
            var o = new OpcionesDeYara(exe, reglas, tmp);

            string v = await new MotorYara(o).VersionAsync().ConfigureAwait(false);
            Check(v.StartsWith("YARA 4.", StringComparison.Ordinal), "REAL: VersionAsync", v);

            ResultadoDeMotor r = await YaraAsync(o, "nada que ver").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Limpio, "REAL: un contenido sin la cadena es limpio", r.Error);
            r = await YaraAsync(o, "hola NEXO-EICAR-DEMO fin").ConfigureAwait(false);
            Check(r is { Veredicto: VeredictoDeArchivo.Infectado, Firma: "YARA.Prueba_Cadena" }, "REAL: la cadena marcadora se detecta con su regla", r.Firma ?? r.Error);
            r = await YaraAsync(o, "NEXO-EICAR-DEMO y otra-cosa").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Infectado && r.Firma!.Contains("Prueba_Cadena") && r.Firma.Contains("Otra_Regla"),
                  "REAL: dos reglas a la vez", r.Firma ?? r.Error);
            r = await YaraAsync(o with { Reglas = rota }, "NEXO-EICAR-DEMO").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error && r.Error!.Contains("undefined identifier"),
                  "REAL: una regla rota es error con el motivo (nunca limpio)", r.Error);
            r = await YaraAsync(o with { Reglas = Path.Combine(raiz, "no-hay.yar") }, "x").ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error, "REAL: unas reglas que no existen son error", r.Error);
            Check(ArchivosEn(tmp) == 0, "REAL: no queda ninguna copia temporal");
        }

        private static bool Lanza<T>(Action a) where T : Exception
        {
            try { a(); return false; }
            catch (T) { return true; }
        }

        private static async Task<bool> LanzaAsync<T>(Func<Task> a) where T : Exception
        {
            try { await a().ConfigureAwait(false); return false; }
            catch (T) { return true; }
        }
    }
}
