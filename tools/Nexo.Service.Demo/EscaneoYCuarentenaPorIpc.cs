using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Threats.Escaner;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static readonly byte[] Marca = Encoding.ASCII.GetBytes("NEXO-MARCADOR-PRUEBA-IPC");

        private static JsonElement R(Respuesta r) => r.Resultado!.Value;

        private static async Task<JsonElement> EsperarAsync(ClienteDePipe c, string id, string metodo = "escaneo.resultado")
        {
            for (int i = 0; i < 100; i++)
            {
                Respuesta r = await c.LlamarAsync(metodo, new { id }).ConfigureAwait(false);
                if (r.Exito && (metodo != "escaneo.resultado" || R(r).GetProperty("listo").GetBoolean())) return R(r);
                await Task.Delay(50).ConfigureAwait(false);
            }
            throw new TimeoutException("el escaneo no termino");
        }

        private static async Task ProbarEscaneoYCuarentena(string vault, string pipe, string raiz)
        {
            Console.WriteLine("6. Escaneo y cuarentena por el pipe");

            string datos = Path.Combine(raiz, "escaneo");
            Directory.CreateDirectory(datos);
            for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(datos, $"limpio{i}.txt"), "nada " + i);
            string malo1 = Path.Combine(datos, "malo1.exe");
            string malo2 = Path.Combine(datos, "malo2.exe");
            File.WriteAllBytes(malo1, Marca.Concat(new byte[] { 1 }).ToArray());
            File.WriteAllBytes(malo2, Marca.Concat(new byte[] { 2 }).ToArray());
            byte[] bytes1 = File.ReadAllBytes(malo1);

            using IHost host = Crear(vault, pipe);
            await host.StartAsync().ConfigureAwait(false);
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            // --- Estado del motor ---
            Check(R(await c.LlamarAsync("escaneo.estado").ConfigureAwait(false)).GetProperty("motor_disponible").GetBoolean(), "el motor aparece disponible");
            Motor.Disponible = false;
            Check(!R(await c.LlamarAsync("escaneo.estado").ConfigureAwait(false)).GetProperty("motor_disponible").GetBoolean(), "y cuando cae, no disponible");
            Respuesta sinMotor = await c.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
            Check(!sinMotor.Exito && sinMotor.Error!.Codigo == ModuloEscaneo.MotorNoDisponible, "sin motor no arranca un escaneo (no se finge)");
            Motor.Disponible = true;

            // --- Rutas no validas ---
            var malas = new (string Que, object P)[]
            {
                ("sin rutas", new { }),
                ("lista vacia", new { rutas = Array.Empty<string>() }),
                ("demasiadas rutas", new { rutas = Enumerable.Repeat(datos, 9).ToArray() }),
                ("ruta de red", new { rutas = new[] { @"\\servidor\recurso" } }),
                ("ruta de dispositivo", new { rutas = new[] { @"\\.\PhysicalDrive0" } }),
                ("ruta relativa", new { rutas = new[] { @"carpeta\x" } }),
                ("con '..'", new { rutas = new[] { datos + @"\..\otra" } }),
                ("con comodin", new { rutas = new[] { datos + @"\*.exe" } }),
                ("no es texto", new { rutas = new object[] { 5 } }),
                ("paralelo cero", new { rutas = new[] { datos }, paralelo = 0 }),
            };
            foreach ((string que, object p) in malas)
            {
                Respuesta r = await c.LlamarAsync("escaneo.iniciar", p).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.ParametrosInvalidos, "escaneo rechaza: " + que);
            }

            // --- Un escaneo de verdad ---
            Respuesta ini = await c.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos }, paralelo = 2 }).ConfigureAwait(false);
            Check(ini.Exito && R(ini).GetProperty("id").GetString()!.Length == 32, "iniciar devuelve un id de escaneo");
            string id = R(ini).GetProperty("id").GetString()!;
            JsonElement res = await EsperarAsync(c, id).ConfigureAwait(false);
            Check(res.GetProperty("analizados").GetInt32() == 5 && res.GetProperty("detecciones").GetArrayLength() == 2
                  && !res.GetProperty("completamente_limpio").GetBoolean(), "el resultado: 5 analizados y 2 detecciones");
            Check(File.Exists(malo1) && File.Exists(malo2), "escanear NO modifica nada");

            Respuesta noExiste = await c.LlamarAsync("escaneo.resultado", new { id = new string('0', 32) }).ConfigureAwait(false);
            Check(!noExiste.Exito && noExiste.Error!.Codigo == ModuloEscaneo.NoExiste, "un id de escaneo inventado no existe");
            Check(!(await c.LlamarAsync("escaneo.progreso", new { id = "../x" }).ConfigureAwait(false)).Exito, "un id mal formado se rechaza");

            // --- Un solo escaneo a la vez, y se puede cancelar ---
            Motor.Bloquear();
            Respuesta lento = await c.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
            string idLento = R(lento).GetProperty("id").GetString()!;
            await Task.Delay(200).ConfigureAwait(false);
            Respuesta ocupado = await c.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
            Check(!ocupado.Exito && ocupado.Error!.Codigo == ModuloEscaneo.Ocupado, "con un escaneo en curso, otro se rechaza");
            Check(!R(await c.LlamarAsync("escaneo.resultado", new { id = idLento }).ConfigureAwait(false)).GetProperty("listo").GetBoolean(),
                  "y el resultado aun no esta listo");
            await c.LlamarAsync("escaneo.cancelar", new { id = idLento }).ConfigureAwait(false);
            JsonElement prog = await EsperarAsync(c, idLento, "escaneo.progreso").ConfigureAwait(false);
            for (int i = 0; i < 100 && prog.GetProperty("estado").GetString() == "corriendo"; i++)
            {
                await Task.Delay(50).ConfigureAwait(false);
                prog = R(await c.LlamarAsync("escaneo.progreso", new { id = idLento }).ConfigureAwait(false));
            }
            Check(prog.GetProperty("estado").GetString() == "cancelado", "cancelar detiene el escaneo", prog.GetProperty("estado").GetString());
            Motor.Liberar();

            // --- Cuarentena: solo desde un escaneo del servicio ---
            Respuesta ajenaR = await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = id, rutas = new[] { @"C:\Windows\System32\kernel32.dll" } }).ConfigureAwait(false);
            Check(!ajenaR.Exito && ajenaR.Error!.Codigo == CodigoDeError.ParametrosInvalidos,
                  "NO se puede poner en cuarentena una ruta que ese escaneo no detecto (el cliente no elige archivos)");
            Check((await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = new string('1', 32) }).ConfigureAwait(false)).Error?.Codigo == ModuloEscaneo.NoExiste,
                  "ni de un escaneo que no existe");
            Check(!(await c.LlamarAsync("cuarentena.previsualizar", new { ruta = malo1 }).ConfigureAwait(false)).Exito,
                  "ni pasando una ruta propia en vez de un escaneo");

            Respuesta pv = await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = id }).ConfigureAwait(false);
            Check(pv.Exito && R(pv).GetProperty("elementos").GetInt32() == 2, "la vista previa propone las 2 detecciones");
            Check(File.Exists(malo1) && File.Exists(malo2) && !Directory.Exists(_carpetaQ) || Directory.GetFiles(_carpetaQ).Length == 0,
                  "y previsualizar no mueve nada");

            // Un token de OTRA accion no vale para esta.
            Respuesta pr0 = await c.LlamarAsync("cuarentena.previsualizar-purga").ConfigureAwait(false);
            Check(pr0.Exito && !R(pr0).GetProperty("hay_cambios").GetBoolean() && !R(pr0).TryGetProperty("token", out _),
                  "sin entradas vencidas, la purga no propone nada ni emite token");

            string tokenQ = R(pv).GetProperty("token").GetString()!;
            Respuesta ap = await c.LlamarAsync("cuarentena.aplicar", new { token = tokenQ, rutas = new[] { @"C:\Windows\notepad.exe" } }).ConfigureAwait(false);
            Check(ap.Exito && R(ap).GetProperty("movidos").GetArrayLength() == 2 && !File.Exists(malo1) && !File.Exists(malo2),
                  "aplicar retira los 2 archivos (y solo esos)");
            Check(File.Exists(Path.Combine(datos, "limpio0.txt")), "los archivos limpios siguen en su sitio");
            Check((await c.LlamarAsync("cuarentena.aplicar", new { token = tokenQ }).ConfigureAwait(false)).Error?.Codigo == ModuloFirewall.TokenInvalido,
                  "el token de cuarentena sirve una sola vez");

            Respuesta lis = await c.LlamarAsync("cuarentena.listar").ConfigureAwait(false);
            Check(R(lis).GetProperty("elementos").GetArrayLength() == 2, "listar muestra las 2 entradas");
            string idQ = R(lis).GetProperty("elementos")[0].GetProperty("id").GetString()!;
            string rutaOrig = R(lis).GetProperty("elementos")[0].GetProperty("ruta_original").GetString()!;

            // --- Restaurar: con token, solo a la ruta original ---
            Respuesta prr = await c.LlamarAsync("cuarentena.previsualizar-restauracion", new { id = idQ }).ConfigureAwait(false);
            string tokenR = R(prr).GetProperty("token").GetString()!;
            Check((await c.LlamarAsync("cuarentena.aplicar", new { token = tokenR }).ConfigureAwait(false)).Error?.Codigo == ModuloFirewall.TokenInvalido,
                  "un token de restauracion no sirve para 'aplicar' una cuarentena");

            prr = await c.LlamarAsync("cuarentena.previsualizar-restauracion", new { id = idQ }).ConfigureAwait(false);
            tokenR = R(prr).GetProperty("token").GetString()!;
            string intento = Path.Combine(raiz, "destino-elegido-por-el-cliente.exe");
            Respuesta rr = await c.LlamarAsync("cuarentena.restaurar", new { token = tokenR, destino = intento }).ConfigureAwait(false);
            Check(rr.Exito && R(rr).GetProperty("exito").GetBoolean() && File.Exists(rutaOrig),
                  "restaurar devuelve el archivo a su ruta original");
            Check(!File.Exists(intento), "y un 'destino' que mande el cliente se ignora: no hay escritura donde diga el cliente");
            Check(File.ReadAllBytes(rutaOrig).SequenceEqual(rutaOrig == malo1 ? bytes1 : File.ReadAllBytes(rutaOrig)), "el contenido restaurado es el original");

            Check((await c.LlamarAsync("cuarentena.previsualizar-restauracion", new { id = "../../x" }).ConfigureAwait(false)).Error?.Codigo == ModuloEscaneo.NoExiste,
                  "restaurar un id inventado o con '..' no existe");

            await host.StopAsync().ConfigureAwait(false);
            Console.WriteLine();
        }
    }

    /// <summary>Motor de pruebas: detecta una marca, y se puede caer o bloquear a voluntad.</summary>
    internal sealed class MotorFalso : IMotorDeFirmas
    {
        private volatile bool _disponible = true;
        private SemaphoreSlim? _puerta;

        public string Nombre => "motor-falso";
        public bool Disponible { get => _disponible; set => _disponible = value; }

        public void Bloquear() => _puerta = new SemaphoreSlim(0);
        public void Liberar() { var p = _puerta; _puerta = null; p?.Release(1000); }

        public Task<string> VersionAsync(CancellationToken ct = default)
            => _disponible ? Task.FromResult("falso 1.0") : throw new MotorNoDisponibleException("apagado");

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            SemaphoreSlim? p = _puerta;
            if (p is not null) await p.WaitAsync(ct).ConfigureAwait(false);

            using var ms = new MemoryStream();
            await contenido.CopyToAsync(ms, ct).ConfigureAwait(false);
            return ms.ToArray().AsSpan().IndexOf(Encoding.ASCII.GetBytes("NEXO-MARCADOR-PRUEBA-IPC")) >= 0
                ? ResultadoDeMotor.Infectado("Prueba.IPC")
                : ResultadoDeMotor.Limpio();
        }
    }
}
