using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Threats.Firewall;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static int _fallos;
        private static readonly AlmacenEnMemoria Almacen = new AlmacenEnMemoria();
        private static readonly bool EsAdmin =
            new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-service-demo-" + Guid.NewGuid().ToString("N"));
            string vault = Path.Combine(raiz, "vault");
            string pipe = "nexo-service-demo-" + Guid.NewGuid().ToString("N");

            try
            {
                await ProbarCicloDeVida(vault, pipe).ConfigureAwait(false);
                await ProbarPipeOcupado(Path.Combine(raiz, "vault2")).ConfigureAwait(false);
                ProbarManejador();
                await ProbarFirewallPorIpc(Path.Combine(raiz, "vault3"), "nexo-service-demo-" + Guid.NewGuid().ToString("N"), raiz).ConfigureAwait(false);
                ProbarPlanes();
            }
            finally
            {
                try { Directory.Delete(raiz, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }

            Console.WriteLine();
            Console.WriteLine(_fallos == 0
                ? "TODAS LAS VERIFICACIONES PASARON"
                : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static IHost Crear(string vault, string pipe)
        {
            HostApplicationBuilder b = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
            b.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Nexo:Vault"] = vault,
                ["Nexo:PipeName"] = pipe
            });
            // El firewall REAL no se toca nunca desde el arnes: el servicio recibe un almacen en memoria.
            b.Services.AddSingleton<IAlmacenDeFirewall>(Almacen);
            b.Services.AddHostedService<NexoWorker>();
            b.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(4));
            return b.Build();
        }

        private static IEnumerable<string> Notas(string vault)
            => Directory.Exists(vault)
                ? Directory.EnumerateFiles(vault, "*.md", SearchOption.AllDirectories).Where(f => !f.Contains("99 Sistema"))
                : Enumerable.Empty<string>();

        private static string LeerTodo(IEnumerable<string> archivos)
            => string.Concat(archivos.Select(f => File.ReadAllText(f, Encoding.UTF8)));

        // ============================================================
        private static async Task ProbarCicloDeVida(string vault, string pipe)
        {
            Console.WriteLine("1. El servicio arranca, habla por el pipe y para a tiempo");

            using IHost host = Crear(vault, pipe);
            await host.StartAsync().ConfigureAwait(false);

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false))
            {
                Respuesta ping = await c.LlamarAsync("ping").ConfigureAwait(false);
                Check(ping.Exito && ping.Resultado?.GetProperty("pong").GetBoolean() == true, "ping responde");
                Check(!string.IsNullOrEmpty(ping.Resultado?.GetProperty("version").GetString()), "informa su version");

                Respuesta estado = await c.LlamarAsync("estado").ConfigureAwait(false);
                Check(estado.Exito && estado.Resultado?.GetProperty("metodos").GetArrayLength() == 5,
                      "estado lista los metodos que expone: los basicos y los del firewall");

                foreach (string peligroso in new[] { "limpiar", "borrar", "firewall.bloquear", "cuarentena.restaurar", "ejecutar" })
                {
                    Respuesta r = await c.LlamarAsync(peligroso, new { ruta = @"C:\Windows\System32\config" }).ConfigureAwait(false);
                    Check(!r.Exito && r.Error!.Codigo == CodigoDeError.MetodoDesconocido,
                          "'" + peligroso + "' NO esta expuesto todavia (necesita vista previa y token)");
                }
            }

            string inicio = LeerTodo(Notas(vault));
            Check(inicio.Contains("servicio-iniciado") && inicio.Contains("ipc_activo: true"),
                  "deja una nota de arranque con el IPC activo");

            var reloj = Stopwatch.StartNew();
            await host.StopAsync().ConfigureAwait(false);
            Check(reloj.Elapsed < TimeSpan.FromSeconds(5), "para en menos de los 5 s que da el SCM", reloj.Elapsed.TotalSeconds.ToString("0.0") + " s");

            string fin = LeerTodo(Notas(vault));
            Check(fin.Contains("servicio-detenido") && fin.Contains("peticiones_ipc"), "deja una nota de parada");

            bool sigue = true;
            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
            }
            catch (TimeoutException) { sigue = false; }
            catch (IOException) { sigue = false; }
            Check(!sigue, "tras parar, el pipe ya no existe");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarPipeOcupado(string vault)
        {
            Console.WriteLine("2. Si el pipe no se puede abrir, no se finge");

            // Un nombre con separadores lo rechaza el servidor: es una configuracion mala.
            using IHost host = Crear(vault, "mal/nombre");
            try
            {
                await host.StartAsync().ConfigureAwait(false);
                await Task.Delay(500).ConfigureAwait(false);
                await host.StopAsync().ConfigureAwait(false);
            }
            catch (Exception) { /* el anfitrion puede abortar: lo que importa es lo que NO queda escrito */ }

            Check(!LeerTodo(Notas(vault)).Contains("ipc_activo: true"),
                  "una configuracion de pipe invalida nunca deja una nota que diga que el IPC esta activo");

            Console.WriteLine();
        }

        // ============================================================
        private static void ProbarManejador()
        {
            Console.WriteLine("3. Manejador");

            var t0 = new DateTimeOffset(2026, 10, 22, 12, 0, 0, TimeSpan.Zero);
            var ahora = t0;
            var m = new ManejadorDelServicio("9.9.9", reloj: () => ahora);
            ahora = t0.AddSeconds(125);
            object? estado = m.ManejarAsync("estado", null, CancellationToken.None).GetAwaiter().GetResult();
            Check(JsonSerializer.SerializeToElement(estado).GetProperty("activo_segundos").GetInt64() == 125, "estado calcula el tiempo activo con el reloj inyectado");

            Console.WriteLine();
        }
    }
}
