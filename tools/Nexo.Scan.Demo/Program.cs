using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Cuarentena;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Firewall;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Scan.Demo
{
    /// <summary>
    /// Escaner bajo demanda y cuarentena, contra un clamd falso (ClamdFalso) que
    /// habla el protocolo real por TCP en loopback. No requiere ClamAV. Los
    /// archivos "infectados" solo contienen una cadena marcadora propia.
    /// </summary>
    public static partial class Program
    {
        private static int _fallos;
        private static readonly byte[] Marcador = Encoding.ASCII.GetBytes(ClamdFalso.Marcador);

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-scan-demo-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(raiz);

            try
            {
                await ProbarClienteAsync().ConfigureAwait(false);
                await ProbarEscanerAsync(Path.Combine(raiz, "escaner")).ConfigureAwait(false);
                await ProbarCuarentenaAsync(Path.Combine(raiz, "cuarentena")).ConfigureAwait(false);
                await ProbarIdentidadAsync(Path.Combine(raiz, "identidad")).ConfigureAwait(false);
            }
            finally
            {
                try { Directory.Delete(raiz, recursive: true); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    Console.WriteLine("  [AVISO] No se pudo borrar " + raiz + ": " + ex.GetType().Name);
                }
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

        private static MemoryStream Bytes(params byte[][] partes)
        {
            var ms = new MemoryStream();
            foreach (byte[] p in partes) ms.Write(p);
            ms.Position = 0;
            return ms;
        }

        private static byte[] Relleno(int n, byte b = (byte)'x') => Enumerable.Repeat(b, n).ToArray();

        // ============================================================
        //  1. CLIENTE DE CLAMD
        // ============================================================
        private static async Task ProbarClienteAsync()
        {
            Console.WriteLine("1. Cliente clamd: protocolo INSTREAM");

            using var servidor = new ClamdFalso();
            var cliente = new ClamdClient("127.0.0.1", servidor.Puerto, timeout: TimeSpan.FromSeconds(5), tamanoChunk: 1024);

            Check(await cliente.PingAsync().ConfigureAwait(false), "PING recibe PONG");
            Check((await cliente.VersionAsync().ConfigureAwait(false)).StartsWith("ClamAV", StringComparison.Ordinal),
                  "VERSION devuelve la version del motor");

            ResultadoDeMotor limpio = await cliente.AnalizarAsync(Bytes(Relleno(100))).ConfigureAwait(false);
            Check(limpio.Veredicto == VeredictoDeArchivo.Limpio, "un flujo limpio se reporta Limpio");

            ResultadoDeMotor malo = await cliente.AnalizarAsync(Bytes(Relleno(10), Marcador, Relleno(10))).ConfigureAwait(false);
            Check(malo.Veredicto == VeredictoDeArchivo.Infectado && malo.Firma == ClamdFalso.Firma,
                  "una deteccion devuelve el nombre de la firma", malo.ToString());

            // Fragmentacion: 10 000 bytes en trozos de 1 024 = 10 fragmentos; el servidor debe
            // reensamblar exactamente lo enviado (si el marco de longitud estuviera mal, no).
            byte[] grande = Relleno(10_000);
            await cliente.AnalizarAsync(Bytes(grande)).ConfigureAwait(false);
            Check(servidor.UltimosBytes == 10_000 && servidor.UltimosFragmentos == 10,
                  "el flujo se parte en fragmentos con longitud big-endian y llega completo",
                  $"bytes {servidor.UltimosBytes}, fragmentos {servidor.UltimosFragmentos}");

            // El marcador cruzando el limite entre dos fragmentos se detecta igual.
            ResultadoDeMotor cruzado = await cliente.AnalizarAsync(Bytes(Relleno(1024 - 10), Marcador, Relleno(50))).ConfigureAwait(false);
            Check(cruzado.Veredicto == VeredictoDeArchivo.Infectado, "la firma que cruza el limite de dos fragmentos se detecta");

            await cliente.AnalizarAsync(Bytes(Array.Empty<byte>())).ConfigureAwait(false);
            Check(servidor.UltimosBytes == 0 && servidor.UltimosFragmentos == 0, "un archivo vacio se envia como flujo vacio");

            // --- Todo lo dudoso es Error, jamas Limpio ---
            servidor.LimiteBytes = 2048;
            ResultadoDeMotor excede = await cliente.AnalizarAsync(Bytes(Relleno(20_000))).ConfigureAwait(false);
            Check(excede.Veredicto == VeredictoDeArchivo.Error, "si clamd rechaza por tamano, es Error (no Limpio)", excede.ToString());
            servidor.LimiteBytes = 0;

            servidor.Modo = ModoClamd.Basura;
            ResultadoDeMotor basura = await cliente.AnalizarAsync(Bytes(Relleno(10))).ConfigureAwait(false);
            Check(basura.Veredicto == VeredictoDeArchivo.Error, "una respuesta que no es protocolo clamd es Error", basura.ToString());

            servidor.Modo = ModoClamd.Caido;
            ResultadoDeMotor caido = await cliente.AnalizarAsync(Bytes(Relleno(10))).ConfigureAwait(false);
            Check(caido.Veredicto == VeredictoDeArchivo.Error, "si clamd cierra la conexion sin responder, es Error", caido.ToString());

            servidor.Modo = ModoClamd.Silencioso;
            var impaciente = new ClamdClient("127.0.0.1", servidor.Puerto, timeout: TimeSpan.FromMilliseconds(400));
            var reloj = Stopwatch.StartNew();
            ResultadoDeMotor mudo = await impaciente.AnalizarAsync(Bytes(Relleno(10))).ConfigureAwait(false);
            Check(mudo.Veredicto == VeredictoDeArchivo.Error && reloj.Elapsed < TimeSpan.FromSeconds(5),
                  "si clamd no contesta, vence el tiempo de espera y es Error", mudo.ToString());

            Check(ClamdClient.Interpretar("stream: OK\0").Veredicto == VeredictoDeArchivo.Limpio
                  && ClamdClient.Interpretar("stream:  FOUND").Veredicto == VeredictoDeArchivo.Error
                  && ClamdClient.Interpretar("").Veredicto == VeredictoDeArchivo.Error
                  && ClamdClient.Interpretar("OK").Veredicto == VeredictoDeArchivo.Error,
                  "solo ': OK' exacto es Limpio; una deteccion sin nombre o una respuesta vacia no");

            // --- Sin motor ---
            int libre;
            using (var temp = new ClamdFalso()) libre = temp.Puerto;   // se cierra al salir: puerto sin nadie
            var sinMotor = new ClamdClient("127.0.0.1", libre, timeout: TimeSpan.FromSeconds(2));
            Check(!await sinMotor.PingAsync().ConfigureAwait(false), "PING a un puerto sin clamd devuelve false");
            bool lanzo = false;
            try { await sinMotor.VersionAsync().ConfigureAwait(false); } catch (MotorNoDisponibleException) { lanzo = true; }
            Check(lanzo, "VERSION sin clamd lanza MotorNoDisponibleException con un mensaje util");
            Check((await sinMotor.AnalizarAsync(Bytes(Relleno(10))).ConfigureAwait(false)).Veredicto == VeredictoDeArchivo.Error,
                  "analizar sin clamd es Error");

            // --- Privacidad: nunca a otra maquina por omision ---
            bool rechazado = false;
            try { _ = new ClamdClient("192.168.1.50"); } catch (ArgumentException) { rechazado = true; }
            Check(rechazado, "rechaza apuntar a un host que no es local (no envia archivos fuera del equipo)");
            rechazado = false;
            try { _ = new ClamdClient("clamd.ejemplo.com"); } catch (ArgumentException) { rechazado = true; }
            Check(rechazado, "tampoco acepta un nombre de dominio");
            Check(new ClamdClient("localhost") is not null && new ClamdClient("::1") is not null,
                  "acepta localhost y ::1");
            Check(new ClamdClient("192.168.1.50", permitirRemoto: true) is not null,
                  "un host remoto solo se acepta con permitirRemoto explicito");

            Console.WriteLine();
        }

        // ============================================================
        //  2. ESCANER
        // ============================================================
        private static async Task ProbarEscanerAsync(string raiz)
        {
            Console.WriteLine("2. Escaner bajo demanda: «no pude leer» != «esta bien»");

            Directory.CreateDirectory(raiz);
            string limpios = Path.Combine(raiz, "docs");
            Directory.CreateDirectory(Path.Combine(limpios, "sub"));
            File.WriteAllBytes(Path.Combine(limpios, "a.txt"), Relleno(300));
            File.WriteAllBytes(Path.Combine(limpios, "b.bin"), Relleno(2000));
            File.WriteAllBytes(Path.Combine(limpios, "sub", "c.dat"), Relleno(50));
            string infectado = Path.Combine(limpios, "sub", "malo.exe");
            File.WriteAllBytes(infectado, Bytes(Relleno(20), Marcador).ToArray());

            using var servidor = new ClamdFalso();
            var cliente = new ClamdClient("127.0.0.1", servidor.Puerto, timeout: TimeSpan.FromSeconds(5));

            // --- Camino feliz ---
            var reportes = new ReportesEnMemoria();
            var escaner = new EscanerBajoDemanda(cliente, reportes);
            ResultadoDeEscaneo r = await escaner.EscanearAsync(new[] { limpios }).ConfigureAwait(false);

            Check(r.Analizados == 4, "analiza los 4 archivos, tambien los de subcarpetas", "analizados: " + r.Analizados);
            Check(r.Detecciones.Count == 1 && r.Detecciones[0].Ruta == infectado && r.Detecciones[0].Firma == ClamdFalso.Firma,
                  "detecta el infectado, con su firma y ruta");
            Check(r.Detecciones[0].Sha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(infectado))).ToLowerInvariant(),
                  "la deteccion lleva el SHA-256 del archivo");
            Check(!r.CompletamenteLimpio, "con una deteccion, no es 'completamente limpio'");
            Check(r.MotorVersion.StartsWith("ClamAV", StringComparison.Ordinal), "el resultado registra la version del motor");
            Check(reportes.Eventos.Count(e => e.Tipo == TipoEvento.AmenazaDetectada) == 1
                  && reportes.Eventos.Count(e => e.Tipo == TipoEvento.ResultadoEscaneo) == 1,
                  "emite un evento por deteccion y uno de resumen");
            Check(File.Exists(infectado), "escanear NO toca el archivo detectado (poner en cuarentena es otra accion)");

            // --- Limpio de verdad ---
            var reportes2 = new ReportesEnMemoria();
            ResultadoDeEscaneo r2 = await new EscanerBajoDemanda(cliente, reportes2)
                .EscanearAsync(new[] { Path.Combine(limpios, "a.txt") }).ConfigureAwait(false);
            Check(r2.CompletamenteLimpio && r2.Analizados == 1, "un archivo limpio y leido entero es 'completamente limpio'");

            // --- Lo que no se pudo analizar NO cuenta como limpio ---
            string grande = Path.Combine(raiz, "grande");
            Directory.CreateDirectory(grande);
            File.WriteAllBytes(Path.Combine(grande, "pequeno.txt"), Relleno(100));
            File.WriteAllBytes(Path.Combine(grande, "enorme.iso"), Relleno(5000));
            var reportes3 = new ReportesEnMemoria();
            ResultadoDeEscaneo r3 = await new EscanerBajoDemanda(cliente, reportes3, new OpcionesDeEscaneo { MaxBytes = 1000 })
                .EscanearAsync(new[] { grande }).ConfigureAwait(false);
            Check(r3.Analizados == 1 && r3.Omitidos.Count == 1 && r3.Omitidos[0].Contains("enorme.iso"),
                  "un archivo mayor que el limite se omite y se anota (no se envia al motor)");
            Check(!r3.CompletamenteLimpio, "con archivos omitidos NO es 'completamente limpio' aunque no haya detecciones");
            Check(reportes3.Eventos.Single(e => e.Tipo == TipoEvento.ResultadoEscaneo).Cuerpo?.Contains("NO se pudieron analizar") == true,
                  "la nota del escaneo dice cuantos archivos no se analizaron");

            string bloqueado = Path.Combine(grande, "bloqueado.dat");
            File.WriteAllBytes(bloqueado, Relleno(100));
            using (var cerrojo = new FileStream(bloqueado, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                ResultadoDeEscaneo r4 = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria())
                    .EscanearAsync(new[] { bloqueado }).ConfigureAwait(false);
                Check(r4.Analizados == 0 && r4.Omitidos.Count == 1 && !r4.CompletamenteLimpio,
                      "un archivo abierto en exclusiva se omite y se anota", string.Join("; ", r4.Omitidos));
            }

            ResultadoDeEscaneo r5 = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria())
                .EscanearAsync(new[] { Path.Combine(raiz, "no-existe") }).ConfigureAwait(false);
            Check(r5.Omitidos.Count == 1 && !r5.CompletamenteLimpio, "una ruta que no existe se anota, no se da por limpia");
            Check(r5.CarpetasNoLeidas.SequenceEqual(new[] { Path.Combine(raiz, "no-existe") }),
                  "y queda en CarpetasNoLeidas: el tiempo real no la da por revisada",
                  string.Join(" | ", r5.CarpetasNoLeidas));

            // --- Carpeta sin permisos: se omite y el resto sigue ---
            if (OperatingSystem.IsWindows())
            {
                string perm = Path.Combine(raiz, "permisos");
                Directory.CreateDirectory(Path.Combine(perm, "aaa-cerrada"));
                File.WriteAllBytes(Path.Combine(perm, "aaa-cerrada", "x.dat"), Relleno(10));
                File.WriteAllBytes(Path.Combine(perm, "zzz.dat"), Relleno(10));
                Directory.CreateDirectory(Path.Combine(perm, "zzz-abierta"));
                File.WriteAllBytes(Path.Combine(perm, "zzz-abierta", "y.dat"), Relleno(10));

                string cerrada = Path.Combine(perm, "aaa-cerrada");
                string usuario = Environment.UserDomainName + "\\" + Environment.UserName;
                try
                {
                    if (Icacls($"\"{cerrada}\" /deny \"{usuario}\":(OI)(CI)(RD,RX)") && SeNiega(cerrada))
                    {
                        ResultadoDeEscaneo r6 = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria())
                            .EscanearAsync(new[] { perm }).ConfigureAwait(false);
                        Check(r6.Analizados == 2, "una carpeta sin permisos no aborta el escaneo: sigue con las demas",
                              "analizados: " + r6.Analizados);
                        Check(r6.Omitidos.Any(o => o.Contains("aaa-cerrada")) && !r6.CompletamenteLimpio,
                              "y la carpeta cerrada queda anotada como no analizada");
                    }
                    else Console.WriteLine("  [AVISO] No se pudo bloquear la carpeta de prueba; no ejecutada.");
                }
                finally { Icacls($"\"{cerrada}\" /remove:d \"{usuario}\""); }
            }

            // --- Uniones: no se sale de lo que se pidio escanear ---
            if (OperatingSystem.IsWindows())
            {
                string fuera = Path.Combine(raiz, "fuera");
                string dentro = Path.Combine(raiz, "dentro");
                Directory.CreateDirectory(fuera);
                Directory.CreateDirectory(dentro);
                File.WriteAllBytes(Path.Combine(fuera, "ajeno.exe"), Bytes(Marcador).ToArray());
                File.WriteAllBytes(Path.Combine(dentro, "propio.txt"), Relleno(10));
                string union = Path.Combine(dentro, "union");
                if (CmdOk($"mklink /J \"{union}\" \"{fuera}\""))
                {
                    try
                    {
                        ResultadoDeEscaneo r7 = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria())
                            .EscanearAsync(new[] { dentro }).ConfigureAwait(false);
                        Check(r7.Analizados == 1 && r7.Detecciones.Count == 0,
                              "no entra en una union NTFS que apunta fuera de lo escaneado", "analizados: " + r7.Analizados);
                    }
                    finally { Directory.Delete(union, recursive: false); }   // solo la union, no el destino
                }
                else Console.WriteLine("  [AVISO] No se pudo crear la union de prueba; no ejecutada.");
            }

            // --- Exclusiones (la cuarentena no se escanea) ---
            ResultadoDeEscaneo r8 = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(),
                new OpcionesDeEscaneo { Excluir = new[] { Path.Combine(limpios, "sub") } })
                .EscanearAsync(new[] { limpios }).ConfigureAwait(false);
            Check(r8.Analizados == 2 && r8.Detecciones.Count == 0, "una carpeta excluida no se recorre");

            // --- Cancelacion ---
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            bool cancelado = false;
            try { await escaner.EscanearAsync(new[] { limpios }, ct: cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { cancelado = true; }
            Check(cancelado, "respeta la cancelacion");

            // --- El motor muere a mitad ---
            string muchos = Path.Combine(raiz, "muchos");
            Directory.CreateDirectory(muchos);
            for (int i = 0; i < 12; i++) File.WriteAllBytes(Path.Combine(muchos, $"f{i:00}.dat"), Relleno(10));
            using var fragil = new ClamdFalso { CaerseTras = 4 };       // VERSION + 3 archivos y se cae
            var rep9 = new ReportesEnMemoria();
            ResultadoDeEscaneo r9 = await new EscanerBajoDemanda(
                    new ClamdClient("127.0.0.1", fragil.Puerto, timeout: TimeSpan.FromSeconds(3)), rep9,
                    // Secuencial a proposito: los recuentos exactos de abajo solo valen asi (el caso en paralelo va aparte).
                    new OpcionesDeEscaneo { MaxErroresSeguidos = 3, Paralelismo = 1 })
                .EscanearAsync(new[] { muchos }).ConfigureAwait(false);
            Check(r9.Incompleto && r9.Analizados == 3 && !r9.CompletamenteLimpio,
                  "si el motor se cae, el escaneo se aborta como INCOMPLETO (no sigue 'limpiando' archivos)",
                  $"incompleto {r9.Incompleto}, analizados {r9.Analizados}, omitidos {r9.Omitidos.Count}");
            Check(r9.Omitidos.Count == 3, "y solo anota los archivos que fallaron, no los que no llego a intentar",
                  "omitidos: " + r9.Omitidos.Count);
            Check(rep9.Eventos.Single(e => e.Tipo == TipoEvento.ResultadoEscaneo).Cuerpo?.Contains("INCOMPLETO") == true,
                  "la nota lo dice: INCOMPLETO");

            // --- Paralelismo: mismo resultado que el secuencial, y el mismo rigor ante fallos ---
            string mezcla = Path.Combine(raiz, "mezcla");
            Directory.CreateDirectory(mezcla);
            for (int i = 0; i < 40; i++)
                File.WriteAllBytes(Path.Combine(mezcla, $"m{i:00}.dat"),
                    i % 10 == 3 ? Bytes(Relleno(32), Marcador, Relleno(32)).ToArray() : Relleno(50));
            File.WriteAllBytes(Path.Combine(mezcla, "grande.bin"), new byte[2000]);

            ResultadoDeEscaneo sec = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(),
                    new OpcionesDeEscaneo { MaxBytes = 1000, Paralelismo = 1 }).EscanearAsync(new[] { mezcla }).ConfigureAwait(false);
            ResultadoDeEscaneo par = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(),
                    new OpcionesDeEscaneo { MaxBytes = 1000, Paralelismo = 6 }).EscanearAsync(new[] { mezcla }).ConfigureAwait(false);
            Check(par.Analizados == sec.Analizados && par.Analizados == 40 && par.Detecciones.Count == 4,
                  "en paralelo analiza lo mismo que en secuencial",
                  $"secuencial {sec.Analizados}/{sec.Detecciones.Count}, paralelo {par.Analizados}/{par.Detecciones.Count}");
            Check(par.Detecciones.Select(d => d.Ruta).SequenceEqual(sec.Detecciones.Select(d => d.Ruta).OrderBy(x => x, StringComparer.Ordinal)),
                  "y las detecciones salen ordenadas y completas");
            Check(par.Omitidos.Count == 1 && par.Omitidos[0].Contains("grande.bin") && !par.CompletamenteLimpio,
                  "un archivo no analizable sigue contando como omitido en paralelo");
            ResultadoDeEscaneo desm = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(),
                    new OpcionesDeEscaneo { MaxBytes = 1000, Paralelismo = 500 }).EscanearAsync(new[] { mezcla }).ConfigureAwait(false);
            Check(desm.Analizados == 40 && desm.Detecciones.Count == 4, "un paralelismo desmesurado se limita y sigue funcionando");

            using var fragil2 = new ClamdFalso { CaerseTras = 6 };
            ResultadoDeEscaneo rp9 = await new EscanerBajoDemanda(
                    new ClamdClient("127.0.0.1", fragil2.Puerto, timeout: TimeSpan.FromSeconds(3)), new ReportesEnMemoria(),
                    new OpcionesDeEscaneo { MaxErroresSeguidos = 3, Paralelismo = 4 })
                .EscanearAsync(new[] { mezcla }).ConfigureAwait(false);
            Check(rp9.Incompleto && !rp9.CompletamenteLimpio && rp9.Analizados < 40,
                  "si el motor se cae con varios trabajadores, tambien queda INCOMPLETO",
                  $"incompleto {rp9.Incompleto}, analizados {rp9.Analizados}");

            using var ctsP = new CancellationTokenSource();
            ctsP.Cancel();
            bool canceladoP = false;
            try { await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(), new OpcionesDeEscaneo { Paralelismo = 4 })
                      .EscanearAsync(new[] { mezcla }, ct: ctsP.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { canceladoP = true; }
            Check(canceladoP, "respeta la cancelacion tambien en paralelo");

            // --- Sin motor al empezar: no se finge un escaneo ---
            int libre;
            using (var t = new ClamdFalso()) libre = t.Puerto;
            bool sinMotor = false;
            var rep10 = new ReportesEnMemoria();
            try
            {
                await new EscanerBajoDemanda(new ClamdClient("127.0.0.1", libre, timeout: TimeSpan.FromSeconds(2)), rep10)
                    .EscanearAsync(new[] { limpios }).ConfigureAwait(false);
            }
            catch (MotorNoDisponibleException) { sinMotor = true; }
            Check(sinMotor && rep10.Eventos.Count == 0,
                  "sin motor lanza MotorNoDisponibleException y no escribe un escaneo de '0 detecciones'");

            Console.WriteLine();
        }

        // ============================================================
        //  3. CUARENTENA
        // ============================================================
        private static async Task ProbarCuarentenaAsync(string raiz)
        {
            Console.WriteLine("3. Cuarentena: dos fases, cifrada, verificada y reversible");

            string datos = Path.Combine(raiz, "datos");
            string cuarentena = Path.Combine(raiz, "q");
            string sistema = Path.Combine(raiz, "sistema");
            Directory.CreateDirectory(datos);
            Directory.CreateDirectory(sistema);

            Deteccion Crear(string carpeta, string nombre, byte[]? contenido = null)
            {
                string ruta = Path.Combine(carpeta, nombre);
                File.WriteAllBytes(ruta, contenido ?? Bytes(Relleno(64), Marcador, Relleno(64)).ToArray());
                var fi = new FileInfo(ruta);
                return new Deteccion(ruta, ClamdFalso.Firma, fi.Length,
                    new DateTimeOffset(fi.LastWriteTimeUtc, TimeSpan.Zero),
                    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ruta))).ToLowerInvariant());
            }

            var reportes = new ReportesEnMemoria();
            var almacen = new AlmacenDeCuarentena(cuarentena, reportes, new[] { sistema });

            Deteccion d1 = Crear(datos, "malo1.exe");
            string original1 = File.ReadAllText(d1.Ruta, Encoding.Latin1);
            byte[] bytes1 = File.ReadAllBytes(d1.Ruta);

            // --- Planear no cambia nada ---
            VistaPreviaCuarentena v = almacen.Preparar(new[] { d1 });
            Check(v.HayCambios && v.Elementos.Count == 1, "la vista previa lista el archivo");
            Check(File.Exists(d1.Ruta) && !Directory.Exists(cuarentena) && reportes.Eventos.Count == 0,
                  "preparar no mueve nada, no crea la carpeta y no emite eventos");

            // Un nombre con salto de linea no puede anadir lineas falsas al plan que el usuario confirma
            // (encontrado con clamd real en Linux, 2026-11-02). La deteccion es sintetica: en Windows ese nombre
            // solo se crea por la API nativa.
            var trampa = new Deteccion(Path.Combine(datos, "factura\n  RECHAZADO: nada que ver.pdf.exe"), ClamdFalso.Firma, 68,
                DateTimeOffset.UtcNow, new string('0', 64));
            string plan = almacen.Preparar(new[] { d1, trampa }).Describir();
            Check(!plan.Split('\n').Any(l => l.StartsWith("  RECHAZADO: nada que ver", StringComparison.Ordinal))
                  && plan.Contains("factura\\n  RECHAZADO: nada que ver", StringComparison.Ordinal),
                  "un salto de linea en el nombre no anade lineas al plan: se ve escapado", plan);

            // --- Token ---
            VistaPreviaCuarentena otra = almacen.Preparar(new[] { Crear(datos, "otro.exe") });
            bool rechazado = false;
            try { await almacen.AplicarAsync(v, otra.Token).ConfigureAwait(false); } catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado && File.Exists(d1.Ruta), "rechaza aplicar con el token de OTRA vista previa");

            var caducado = TokenDeCambio.Emitir(VistaPreviaCuarentena.Lineas(new[] { d1 }),
                DateTimeOffset.Now - TokenDeCambio.Vigencia - TimeSpan.FromMinutes(1));
            rechazado = false;
            try { await almacen.AplicarAsync(v, caducado).ConfigureAwait(false); } catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado && File.Exists(d1.Ruta), "rechaza aplicar con un token caducado");

            // --- Aplicar ---
            ResultadoCuarentena r = await almacen.AplicarAsync(v, v.Token).ConfigureAwait(false);
            Check(r.Movidos.Count == 1 && r.Omitidos.Count == 0, "pone el archivo en cuarentena", string.Join("; ", r.Omitidos));
            Check(!File.Exists(d1.Ruta), "el original ya no esta en su sitio");

            ElementoDeCuarentena item = r.Movidos[0];
            string nxq = Path.Combine(cuarentena, item.Id + ".nxq");
            byte[] guardado = File.ReadAllBytes(nxq);
            Check(File.Exists(nxq) && File.Exists(Path.Combine(cuarentena, item.Id + ".json")), "hay copia cifrada y metadatos");
            Check(IndexOf(guardado, Marcador) < 0,
                  "el archivo cuarentenado NO contiene la firma en claro (ningun antivirus lo re-detecta)");
            Check(reportes.Eventos.Count == 1 && reportes.Eventos[0].Tipo == TipoEvento.ArchivoEnCuarentena,
                  "emite el evento de cuarentena");
            Check(almacen.Listar().Count == 1 && almacen.Listar()[0].Id == item.Id, "Listar muestra la entrada");

            // --- Restaurar ---
            ResultadoRestauracion rr = await almacen.RestaurarAsync(item.Id).ConfigureAwait(false);
            Check(rr.Exito && File.Exists(d1.Ruta), "restaura al sitio original", rr.Motivo);
            Check(File.ReadAllBytes(d1.Ruta).SequenceEqual(bytes1) && File.ReadAllText(d1.Ruta, Encoding.Latin1) == original1,
                  "lo restaurado es identico, byte a byte");
            Check(almacen.Listar().Count == 0 && !File.Exists(nxq), "tras restaurar, la entrada desaparece de la cuarentena");
            Check(reportes.Eventos.Last().Tipo == TipoEvento.ArchivoRestaurado, "emite el evento de restauracion");

            // --- Restaurar no pisa nada ---
            Deteccion d2 = Crear(datos, "malo2.exe");
            VistaPreviaCuarentena v2 = almacen.Preparar(new[] { d2 });
            ElementoDeCuarentena i2 = (await almacen.AplicarAsync(v2, v2.Token).ConfigureAwait(false)).Movidos[0];
            File.WriteAllText(d2.Ruta, "otra cosa que alguien puso ahi");
            ResultadoRestauracion pisa = await almacen.RestaurarAsync(i2.Id).ConfigureAwait(false);
            Check(!pisa.Exito && File.ReadAllText(d2.Ruta) == "otra cosa que alguien puso ahi",
                  "no restaura encima de un archivo que ya existe", pisa.Motivo);
            string alterno = Path.Combine(raiz, "recuperado", "malo2.exe");
            ResultadoRestauracion alt = await almacen.RestaurarAsync(i2.Id, alterno).ConfigureAwait(false);
            Check(alt.Exito && File.Exists(alterno), "pero si se puede restaurar a otro destino");

            // --- Identificadores hostiles ---
            foreach (string malo in new[] { "../../etc/passwd", "..\\..\\x", "", "NO-ES-UN-GUID", new string('a', 31) })
            {
                ResultadoRestauracion h = await almacen.RestaurarAsync(malo).ConfigureAwait(false);
                if (h.Exito || h.Motivo is null) { Check(false, "id hostil '" + malo + "' debio rechazarse"); }
            }
            Check((await almacen.RestaurarAsync("../../x").ConfigureAwait(false)).Motivo!.Contains("no valido")
                  && (await almacen.RestaurarAsync(new string('0', 32)).ConfigureAwait(false)).Motivo!.Contains("no existe"),
                  "ids con ruta o formato raro se rechazan antes de formar ninguna ruta; uno inexistente se informa");

            // --- TOCTOU: el archivo cambia despues de la vista previa ---
            Deteccion d3 = Crear(datos, "malo3.exe");
            VistaPreviaCuarentena v3 = almacen.Preparar(new[] { d3 });
            File.AppendAllText(d3.Ruta, "cambio posterior");
            ResultadoCuarentena r3 = await almacen.AplicarAsync(v3, v3.Token).ConfigureAwait(false);
            Check(r3.Movidos.Count == 0 && r3.Omitidos.Count == 1 && File.Exists(d3.Ruta),
                  "si el archivo cambio despues de la vista previa, no se mueve", string.Join("; ", r3.Omitidos));

            // El contenido cambia pero tamano y fecha se restauran (ataque): el SHA lo delata.
            Deteccion d3b = Crear(datos, "malo3b.exe", Bytes(Relleno(30), Marcador).ToArray());
            VistaPreviaCuarentena v3b = almacen.Preparar(new[] { d3b });
            byte[] otroMismoLargo = Relleno((int)d3b.Bytes, (byte)'Z');
            File.WriteAllBytes(d3b.Ruta, otroMismoLargo);
            File.SetLastWriteTimeUtc(d3b.Ruta, d3b.Modificado.UtcDateTime);
            ResultadoCuarentena r3b = await almacen.AplicarAsync(v3b, v3b.Token).ConfigureAwait(false);
            Check(r3b.Movidos.Count == 0 && File.Exists(d3b.Ruta),
                  "si cambia el contenido pero se conservan tamano y fecha, el SHA-256 lo detecta");

            // --- Archivos del sistema: no ---
            Deteccion dSys = Crear(sistema, "kernelx.dll");
            VistaPreviaCuarentena vSys = almacen.Preparar(new[] { dSys });
            Check(!vSys.HayCambios && vSys.Rechazos.Count == 1 && vSys.Rechazos[0].Contains("sistema"),
                  "se niega a mover un archivo de una carpeta del sistema y explica por que");

            // --- Lo que ya esta en la cuarentena ---
            Check(!almacen.Preparar(new[] { new Deteccion(Path.Combine(cuarentena, "x.nxq"), "f", 1, DateTimeOffset.Now, null) }).HayCambios,
                  "no vuelve a poner en cuarentena lo que ya esta dentro de la cuarentena");

            // --- Duplicados en la lista ---
            Check(almacen.Preparar(new[] { d3, d3 }).Elementos.Count == 1, "una ruta repetida se plan una sola vez");

            // --- Integridad: copia danada ---
            Deteccion d4 = Crear(datos, "malo4.exe");
            VistaPreviaCuarentena v4 = almacen.Preparar(new[] { d4 });
            ElementoDeCuarentena i4 = (await almacen.AplicarAsync(v4, v4.Token).ConfigureAwait(false)).Movidos[0];
            string nxq4 = Path.Combine(cuarentena, i4.Id + ".nxq");
            byte[] roto = File.ReadAllBytes(nxq4);
            roto[^3] ^= 0xFF;
            File.WriteAllBytes(nxq4, roto);
            ResultadoRestauracion danada = await almacen.RestaurarAsync(i4.Id).ConfigureAwait(false);
            Check(!danada.Exito && !File.Exists(d4.Ruta) && File.Exists(nxq4),
                  "una copia cuarentenada danada no se restaura (GCM) y no se borra", danada.Motivo);

            // --- Si no se puede retirar el original, se deshace ---
            if (OperatingSystem.IsWindows())
            {
                Deteccion d5 = Crear(datos, "malo5.exe");
                VistaPreviaCuarentena v5 = almacen.Preparar(new[] { d5 });
                int antes = Directory.GetFiles(cuarentena, "*.nxq").Length;
                using (var uso = new FileStream(d5.Ruta, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    ResultadoCuarentena r5 = await almacen.AplicarAsync(v5, v5.Token).ConfigureAwait(false);
                    Check(r5.Movidos.Count == 0 && r5.Omitidos.Count == 1 && File.Exists(d5.Ruta),
                          "si el original esta en uso y no se puede retirar, no se mueve", string.Join("; ", r5.Omitidos));
                    Check(Directory.GetFiles(cuarentena, "*.nxq").Length == antes,
                          "y se deshace la copia cifrada: no quedan duplicados a medias");
                }
            }

            // --- Solo lectura ---
            Deteccion d6 = Crear(datos, "malo6.exe");
            File.SetAttributes(d6.Ruta, FileAttributes.ReadOnly);
            VistaPreviaCuarentena v6 = almacen.Preparar(new[] { d6 });
            ResultadoCuarentena r6 = await almacen.AplicarAsync(v6, v6.Token).ConfigureAwait(false);
            Check(r6.Movidos.Count == 1 && !File.Exists(d6.Ruta), "un archivo de solo lectura tambien se retira");

            // --- Purga: solo lo que supero la retencion, con vista previa y token ---
            string cuarP = Path.Combine(raiz, "qp");
            var ahora = DateTimeOffset.Now;
            DateTimeOffset reloj = ahora;
            var repP = new ReportesEnMemoria();
            var almP = new AlmacenDeCuarentena(cuarP, repP, new[] { sistema }, () => reloj);

            Deteccion pv = Crear(datos, "purga-vieja.exe");
            Deteccion pn = Crear(datos, "purga-nueva.exe");
            reloj = ahora - AlmacenDeCuarentena.Retencion - TimeSpan.FromDays(1);
            VistaPreviaCuarentena vpv = almP.Preparar(new[] { pv });
            ElementoDeCuarentena viejo = (await almP.AplicarAsync(vpv, vpv.Token).ConfigureAwait(false)).Movidos[0];
            reloj = ahora - TimeSpan.FromDays(1);
            VistaPreviaCuarentena vpn = almP.Preparar(new[] { pn });
            ElementoDeCuarentena nuevo = (await almP.AplicarAsync(vpn, vpn.Token).ConfigureAwait(false)).Movidos[0];
            reloj = ahora;
            int eventosAntes = repP.Eventos.Count;

            VistaPreviaPurga pp = almP.PrepararPurga();
            Check(pp.Elementos.Count == 1 && pp.Elementos[0].Id == viejo.Id, "la vista previa de purga solo incluye lo vencido");
            Check(almP.Listar().Count == 2 && repP.Eventos.Count == eventosAntes, "preparar la purga no elimina nada ni emite eventos");

            VistaPreviaPurga vacia = new VistaPreviaPurga(Array.Empty<ElementoDeCuarentena>(),
                TokenDeCambio.Emitir(Array.Empty<string>(), ahora));
            rechazado = false;
            try { await almP.AplicarPurgaAsync(pp, vacia.Token).ConfigureAwait(false); } catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado && almP.Listar().Count == 2, "rechaza purgar con el token de otra vista previa");

            ResultadoPurga rpu = await almP.AplicarPurgaAsync(pp, pp.Token).ConfigureAwait(false);
            Check(rpu.Purgados.Count == 1 && rpu.Omitidos.Count == 0, "purga la entrada vencida", string.Join("; ", rpu.Omitidos));
            Check(almP.Listar().Count == 1 && almP.Listar()[0].Id == nuevo.Id
                  && !File.Exists(Path.Combine(cuarP, viejo.Id + ".nxq")) && !File.Exists(Path.Combine(cuarP, viejo.Id + ".json")),
                  "lo purgado desaparece del disco y lo reciente se conserva");
            Check(repP.Eventos.Count == eventosAntes + 1 && repP.Eventos[^1].Tipo == TipoEvento.CuarentenaPurgada,
                  "emite el evento de purga");
            Check(!(await almP.RestaurarAsync(viejo.Id).ConfigureAwait(false)).Exito, "lo purgado ya no se puede restaurar");
            Check(almP.PrepararPurga().HayCambios == false, "sin vencidos, la purga no propone nada");

            // Entre la vista previa y aplicar, una entrada vencida se restaura: no se purga.
            reloj = ahora + AlmacenDeCuarentena.Retencion + TimeSpan.FromDays(1);
            VistaPreviaPurga pr = almP.PrepararPurga();
            await almP.RestaurarAsync(nuevo.Id).ConfigureAwait(false);
            ResultadoPurga rpr = await almP.AplicarPurgaAsync(pr, pr.Token).ConfigureAwait(false);
            Check(rpr.Purgados.Count == 0 && rpr.Omitidos.Count == 1, "una entrada restaurada tras la vista previa se omite, no falla");

            Console.WriteLine();
        }

        // ------------------------------------------------------------
        private static int IndexOf(byte[] pajar, byte[] aguja)
            => pajar.AsSpan().IndexOf(aguja);

        private static bool SeNiega(string carpeta)
        {
            try { _ = Directory.GetFiles(carpeta); return false; }
            catch (UnauthorizedAccessException) { return true; }
        }

        private static bool Icacls(string args) => Ejecutar("icacls", args);
        private static bool CmdOk(string args) => Ejecutar("cmd", "/c " + args);

        private static bool Ejecutar(string exe, string args)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                })!;
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0;
            }
            catch (System.ComponentModel.Win32Exception) { return false; }
        }
    }

    internal sealed class ReportesEnMemoria : IReportWriter
    {
        public List<NexoEvent> Eventos { get; } = new();

        public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
        {
            Eventos.Add(evento);
            return Task.FromResult<NoteRef>(null!);
        }

        public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}
