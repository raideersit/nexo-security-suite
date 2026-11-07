using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;

namespace Nexo.Amsi.Demo
{
    internal static class Program
    {
        private static int _fallos;

        /// <summary>AMSI falso. Modo = como se comporta el «proveedor».</summary>
        private sealed class AmsiFalso : IBackendAmsi
        {
            public enum Modo { ConProveedor, SinProveedor, Roto }

            public Modo Comportamiento = Modo.ConProveedor;
            public uint CodigoParaMarcador = MotorAmsi.CodigoDetectado;
            public int Llamadas, LlamadasDeAutocomprobacion;
            public static readonly byte[] Marcador = Encoding.ASCII.GetBytes("MARCADOR-MALO");

            public RespuestaDeAmsi Escanear(byte[] datos, int longitud, string nombreDelContenido)
            {
                Llamadas++;
                if (nombreDelContenido == "nexo-autocomprobacion") LlamadasDeAutocomprobacion++;
                if (Comportamiento == Modo.Roto) return RespuestaDeAmsi.Fallo("AmsiScanBuffer fallo (HRESULT 0x80070057).");

                if (Comportamiento == Modo.ConProveedor)
                {
                    string comoUtf16 = Encoding.Unicode.GetString(datos, 0, longitud);
                    if (comoUtf16.Contains(MotorAmsi.CadenaDePrueba, StringComparison.Ordinal)) return RespuestaDeAmsi.Ok(MotorAmsi.CodigoDetectado);
                    if (Contiene(datos, longitud, Marcador)) return RespuestaDeAmsi.Ok(CodigoParaMarcador);
                }
                // SinProveedor: AMSI responde «no detectado» (1) a TODO, como Windows sin Defender.
                return RespuestaDeAmsi.Ok(1);
            }

            private static bool Contiene(byte[] d, int n, byte[] aguja)
                => d.AsSpan(0, n).IndexOf(aguja) >= 0;
        }

        /// <summary>Un motor con un veredicto fijo, para probar la combinacion.</summary>
        private sealed class MotorFijo : IMotorDeFirmas
        {
            private readonly ResultadoDeMotor _r;
            private readonly string _nombre;
            public int Llamadas;
            public MotorFijo(string nombre, ResultadoDeMotor r) { _nombre = nombre; _r = r; }
            public string Nombre => _nombre;
            public Task<string> VersionAsync(System.Threading.CancellationToken ct = default) => Task.FromResult(_nombre + " 1.0");
            public Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, System.Threading.CancellationToken ct = default)
            { Llamadas++; return Task.FromResult(_r); }
        }

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            await ProbarVeredictos().ConfigureAwait(false);
            await ProbarAutocomprobacion().ConfigureAwait(false);
            await ProbarCodigos().ConfigureAwait(false);
            await ProbarLimites().ConfigureAwait(false);
            ProbarCadenaNoEstaEnElBinario();
            await ProbarCombinado().ConfigureAwait(false);

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

        private static MemoryStream Flujo(string s) => new(Encoding.ASCII.GetBytes(s));
        private static MemoryStream Flujo(byte[] b) => new(b);

        private static async Task ProbarVeredictos()
        {
            Console.WriteLine("1. Veredictos con un proveedor que responde");
            var f = new AmsiFalso();
            var m = new MotorAmsi(f);

            ResultadoDeMotor limpio = await m.AnalizarAsync(Flujo("Write-Host hola")).ConfigureAwait(false);
            Check(limpio.Veredicto == VeredictoDeArchivo.Limpio, "un contenido normal es Limpio", limpio.Error);

            ResultadoDeMotor malo = await m.AnalizarAsync(Flujo(Encoding.ASCII.GetBytes("xx MARCADOR-MALO xx"))).ConfigureAwait(false);
            Check(malo.Veredicto == VeredictoDeArchivo.Infectado && malo.Firma == "AMSI.Detectado", "lo que el proveedor marca es Infectado (AMSI.Detectado)", malo.Veredicto + " " + malo.Error);

            Check(m.Nombre == "AMSI", "se llama AMSI");
            string v = await m.VersionAsync().ConfigureAwait(false);
            Check(v.Contains("AMSI"), "la version dice que el proveedor esta verificado", v);

            f.Llamadas = 0;
            ResultadoDeMotor vacio = await m.AnalizarAsync(new MemoryStream()).ConfigureAwait(false);
            Check(vacio.Veredicto == VeredictoDeArchivo.Limpio && f.Llamadas == 0, "un contenido vacio es Limpio sin molestar a AMSI");
        }

        private static async Task ProbarAutocomprobacion()
        {
            Console.WriteLine("2. Sin proveedor, un «no detectado» NO es «limpio»");

            var sin = new AmsiFalso { Comportamiento = AmsiFalso.Modo.SinProveedor };
            var m = new MotorAmsi(sin);
            ResultadoDeMotor r = await m.AnalizarAsync(Flujo("Write-Host hola")).ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error, "sin proveedor activo el resultado es Error (no concluyente), jamas Limpio", r.Veredicto.ToString());
            Check(r.Error is not null && r.Error.Contains("proveedor"), "y el motivo explica que no hay proveedor", r.Error);

            // Aunque el contenido tuviera el marcador, sin proveedor no se puede afirmar nada: sigue siendo Error.
            ResultadoDeMotor r2 = await m.AnalizarAsync(Flujo(Encoding.ASCII.GetBytes("MARCADOR-MALO"))).ConfigureAwait(false);
            Check(r2.Veredicto == VeredictoDeArchivo.Error, "tampoco inventa una deteccion", r2.Veredicto.ToString());

            bool lanzo = false;
            try { await m.VersionAsync().ConfigureAwait(false); } catch (MotorNoDisponibleException) { lanzo = true; }
            Check(lanzo, "VersionAsync lanza MotorNoDisponible (el servicio no suma un AMSI que no responde)");

            var roto = new AmsiFalso { Comportamiento = AmsiFalso.Modo.Roto };
            ResultadoDeMotor r3 = await new MotorAmsi(roto).AnalizarAsync(Flujo("hola")).ConfigureAwait(false);
            Check(r3.Veredicto == VeredictoDeArchivo.Error && r3.Error!.Contains("0x80070057"), "un fallo de AmsiScanBuffer es Error con su HRESULT", r3.Error);

            // La comprobacion se repite al caducar: si el proveedor se apaga a mitad de camino se nota.
            var ahora = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
            var f = new AmsiFalso();
            var m2 = new MotorAmsi(f, validez: TimeSpan.FromMinutes(5), reloj: () => ahora);
            ResultadoDeMotor a = await m2.AnalizarAsync(Flujo("uno")).ConfigureAwait(false);
            await m2.AnalizarAsync(Flujo("dos")).ConfigureAwait(false);
            Check(a.Veredicto == VeredictoDeArchivo.Limpio && f.LlamadasDeAutocomprobacion == 1, "dentro de la validez no se repite la autocomprobacion", "autocomprobaciones: " + f.LlamadasDeAutocomprobacion);

            f.Comportamiento = AmsiFalso.Modo.SinProveedor;
            ResultadoDeMotor aun = await m2.AnalizarAsync(Flujo("tres")).ConfigureAwait(false);
            Check(aun.Veredicto == VeredictoDeArchivo.Limpio, "dentro de la validez se confia en la ultima comprobacion (documentado: ventana de 5 min)");

            ahora += TimeSpan.FromMinutes(6);
            ResultadoDeMotor caducado = await m2.AnalizarAsync(Flujo("cuatro")).ConfigureAwait(false);
            Check(caducado.Veredicto == VeredictoDeArchivo.Error && f.LlamadasDeAutocomprobacion == 2, "pasada la validez se vuelve a comprobar y el proveedor apagado se detecta", caducado.Veredicto + " / " + f.LlamadasDeAutocomprobacion);

            // Una comprobacion fallida no se cachea: al volver el proveedor, funciona enseguida.
            f.Comportamiento = AmsiFalso.Modo.ConProveedor;
            ResultadoDeMotor vuelve = await m2.AnalizarAsync(Flujo("cinco")).ConfigureAwait(false);
            Check(vuelve.Veredicto == VeredictoDeArchivo.Limpio, "una comprobacion fallida no se recuerda: al volver el proveedor se recupera");
        }

        private static async Task ProbarCodigos()
        {
            Console.WriteLine("3. Cada codigo de AMSI");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(0)).Veredicto == VeredictoDeArchivo.Limpio, "0 (limpio) -> Limpio");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(1)).Veredicto == VeredictoDeArchivo.Limpio, "1 (no detectado) -> Limpio");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(32768)).Veredicto == VeredictoDeArchivo.Infectado, "32768 (detectado) -> Infectado");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(uint.MaxValue)).Veredicto == VeredictoDeArchivo.Infectado, "cualquier codigo >= 32768 -> Infectado (AmsiResultIsMalware)");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(16384)).Veredicto == VeredictoDeArchivo.Error, "16384 (bloqueado por el administrador) -> Error, no es malware ni limpio");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(20479)).Veredicto == VeredictoDeArchivo.Error, "20479 (fin del rango de administrador) -> Error");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(2)).Veredicto == VeredictoDeArchivo.Error, "2 (no definido) -> Error, nunca Limpio");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Ok(25000)).Veredicto == VeredictoDeArchivo.Error, "25000 (hueco sin definir) -> Error");
            Check(MotorAmsi.Interpretar(RespuestaDeAmsi.Fallo("x")).Veredicto == VeredictoDeArchivo.Error, "una respuesta fallida -> Error");

            // Un codigo desconocido tambien debe salir como Error cuando llega por el motor completo.
            var f = new AmsiFalso { CodigoParaMarcador = 7 };
            ResultadoDeMotor r = await new MotorAmsi(f).AnalizarAsync(Flujo(Encoding.ASCII.GetBytes("MARCADOR-MALO"))).ConfigureAwait(false);
            Check(r.Veredicto == VeredictoDeArchivo.Error, "un codigo desconocido por el motor completo es Error", r.Veredicto.ToString());
        }

        private static async Task ProbarLimites()
        {
            Console.WriteLine("4. Limites");
            var f = new AmsiFalso();
            var m = new MotorAmsi(f, maximoDeBytes: 1024);
            f.Llamadas = 0;
            ResultadoDeMotor grande = await m.AnalizarAsync(Flujo(new byte[2048])).ConfigureAwait(false);
            Check(grande.Veredicto == VeredictoDeArchivo.Error && f.Llamadas == 0, "pasarse del tope es Error y no se llama a AMSI", grande.Veredicto + " llamadas " + f.Llamadas);

            ResultadoDeMotor justo = await m.AnalizarAsync(Flujo(new byte[1024])).ConfigureAwait(false);
            Check(justo.Veredicto == VeredictoDeArchivo.Limpio, "justo en el tope se analiza");

            bool lanzo = false;
            try { _ = new MotorAmsi(f, 0); } catch (ArgumentOutOfRangeException) { lanzo = true; }
            Check(lanzo, "un tope de 0 se rechaza");
        }

        private static void ProbarCadenaNoEstaEnElBinario()
        {
            Console.WriteLine("5. La cadena de prueba no esta tal cual en el binario");
            // El GUID del texto oficial de prueba. Se arma aqui en pedazos para que ESTE binario tampoco lo contenga.
            string guid = string.Join("", new[] { "7e72c3ce", "-861b-", "4339-", "8740-", "0ac1484c", "1386" });
            Check(MotorAmsi.CadenaDePrueba.Contains(guid, StringComparison.Ordinal), "la cadena armada en ejecucion SI contiene el GUID oficial");

            string dll = typeof(MotorAmsi).Assembly.Location;
            byte[] bytes = File.ReadAllBytes(dll);
            Check(bytes.AsSpan().IndexOf(Encoding.ASCII.GetBytes(guid)) < 0, "el GUID no aparece en ASCII dentro de Nexo.Modules.Threats.dll");
            Check(bytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes(guid)) < 0, "ni en UTF-16 (como guarda .NET los literales)");

            string yo = typeof(Program).Assembly.Location;
            byte[] mis = File.ReadAllBytes(yo);
            Check(mis.AsSpan().IndexOf(Encoding.Unicode.GetBytes(guid)) < 0 && mis.AsSpan().IndexOf(Encoding.ASCII.GetBytes(guid)) < 0, "ni en este arnes");
        }

        private static async Task ProbarCombinado()
        {
            Console.WriteLine("6. Motor combinado");
            var limpio = new MotorFijo("A", ResultadoDeMotor.Limpio());
            var limpio2 = new MotorFijo("B", ResultadoDeMotor.Limpio());
            var malo = new MotorFijo("M", ResultadoDeMotor.Infectado("Firma.X"));
            var fallo = new MotorFijo("F", ResultadoDeMotor.Fallo("no pude"));

            ResultadoDeMotor r1 = await new MotorCombinado(limpio, limpio2).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r1.Veredicto == VeredictoDeArchivo.Limpio, "todos limpios -> Limpio");

            ResultadoDeMotor r2 = await new MotorCombinado(limpio, malo).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r2.Veredicto == VeredictoDeArchivo.Infectado && r2.Firma == "Firma.X", "uno que marca -> Infectado");

            ResultadoDeMotor r3 = await new MotorCombinado(limpio, fallo).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r3.Veredicto == VeredictoDeArchivo.Error && r3.Error!.Contains("F: no pude"), "uno que no pudo y ninguno marca -> Error (no Limpio), con quien fallo", r3.Veredicto + " " + r3.Error);

            ResultadoDeMotor r4 = await new MotorCombinado(fallo, malo).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r4.Veredicto == VeredictoDeArchivo.Infectado, "una deteccion cuenta aunque otro motor haya fallado");

            ResultadoDeMotor r5 = await new MotorCombinado(malo, new MotorFijo("N", ResultadoDeMotor.Infectado("Firma.Y"))).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r5.Firma == "Firma.X + Firma.Y", "las firmas de varios motores se juntan", r5.Firma);

            var comb = new MotorCombinado(limpio, limpio2);
            Check(comb.Nombre == "A+B", "el nombre une los de los motores", comb.Nombre);
            Check(await comb.VersionAsync().ConfigureAwait(false) == "A 1.0 | B 1.0", "la version une las de los motores");

            // Un flujo que no se puede rebobinar (el escaner lo entrega asi a veces) llega entero a cada motor.
            var visto = new List<int>();
            var lector = new MotorLeeTodo(visto);
            var lector2 = new MotorLeeTodo(visto);
            await new MotorCombinado(lector, lector2).AnalizarAsync(new FlujoSinBusqueda(Encoding.ASCII.GetBytes("12345"))).ConfigureAwait(false);
            Check(visto.SequenceEqual(new[] { 5, 5 }), "con un flujo sin rebobinar, cada motor recibe el contenido completo", string.Join(",", visto));

            bool lanzo = false;
            try { _ = new MotorCombinado(); } catch (ArgumentException) { lanzo = true; }
            Check(lanzo, "sin motores se rechaza");

            // Un motor que lanza MotorNoDisponible cuenta como Error de ese motor, no tumba al otro.
            var lanza = new MotorQueLanza();
            ResultadoDeMotor r6 = await new MotorCombinado(lanza, malo).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r6.Veredicto == VeredictoDeArchivo.Infectado, "un motor que lanza MotorNoDisponible no impide que otro detecte");
            ResultadoDeMotor r7 = await new MotorCombinado(lanza, limpio).AnalizarAsync(Flujo("x")).ConfigureAwait(false);
            Check(r7.Veredicto == VeredictoDeArchivo.Error, "y si nadie detecta, es Error", r7.Veredicto.ToString());
        }

        private sealed class MotorLeeTodo : IMotorDeFirmas
        {
            private readonly List<int> _visto;
            public MotorLeeTodo(List<int> visto) { _visto = visto; }
            public string Nombre => "L";
            public Task<string> VersionAsync(System.Threading.CancellationToken ct = default) => Task.FromResult("1");
            public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, System.Threading.CancellationToken ct = default)
            {
                using var ms = new MemoryStream();
                await contenido.CopyToAsync(ms, ct).ConfigureAwait(false);
                _visto.Add((int)ms.Length);
                return ResultadoDeMotor.Limpio();
            }
        }

        private sealed class MotorQueLanza : IMotorDeFirmas
        {
            public string Nombre => "Q";
            public Task<string> VersionAsync(System.Threading.CancellationToken ct = default) => throw new MotorNoDisponibleException("no esta");
            public Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, System.Threading.CancellationToken ct = default) => throw new MotorNoDisponibleException("no esta");
        }

        private sealed class FlujoSinBusqueda : Stream
        {
            private readonly MemoryStream _i;
            public FlujoSinBusqueda(byte[] d) { _i = new MemoryStream(d); }
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => _i.Read(buffer, offset, count);
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
