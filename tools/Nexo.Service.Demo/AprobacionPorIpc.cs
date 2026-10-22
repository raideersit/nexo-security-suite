using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static string _aprobacion = "ninguna";

        private static async Task ProbarAprobacion(string vault, string pipe, string raiz)
        {
            Console.WriteLine("12. Aprobacion fuera de banda: aplicar exige permisos elevados (UAC)");

            // --- La politica en si ---
            Check(PoliticaDeAprobacion.Desde(null, out _).ExigeElevacion, "sin configurar, la politica es ELEVADA (lo seguro por omision)");
            Check(!PoliticaDeAprobacion.Desde("ninguna", out string? a0).ExigeElevacion && a0 is null, "'ninguna' la desactiva, y es una decision explicita");
            Check(PoliticaDeAprobacion.Desde("NINGUNA ", out _) == PoliticaDeAprobacion.Ninguna, "sin distinguir mayusculas ni espacios");
            PoliticaDeAprobacion rara = PoliticaDeAprobacion.Desde("tal-vez", out string? avisoRara);
            Check(rara.ExigeElevacion && avisoRara is not null && avisoRara.Contains("tal-vez"),
                  "un valor que no se reconoce cuenta como ELEVADA (una errata no quita la proteccion) y se avisa");

            string datos = Path.Combine(raiz, "aprobacion");
            Directory.CreateDirectory(datos);
            string malo = Path.Combine(datos, "malo.exe");
            File.WriteAllBytes(malo, Marca.Concat(new byte[] { 4 }).ToArray());
            string app = Path.Combine(datos, "app-aprobacion.exe");
            File.WriteAllBytes(app, new byte[] { 0x4D, 0x5A });

            _aprobacion = "elevada";
            try
            {
                using IHost host = Crear(vault, pipe);
                await host.StartAsync().ConfigureAwait(false);
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

                // Previsualizar y leer NO piden aprobacion: solo aplicar.
                Respuesta fw = await c.LlamarAsync("firewall.previsualizar", new { tipo = "regla", ruta = app, accion = "bloquear" }).ConfigureAwait(false);
                Check(fw.Exito && R(fw).GetProperty("hay_cambios").GetBoolean(), "previsualizar sigue disponible sin elevar");
                Check((await c.LlamarAsync("firewall.estado").ConfigureAwait(false)).Exito
                      && (await c.LlamarAsync("cuarentena.listar").ConfigureAwait(false)).Exito, "y leer el estado tambien");

                string tokenFw = R(fw).GetProperty("token").GetString()!;
                Respuesta ini = await c.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
                JsonElementFix res = new JsonElementFix(await EsperarAsync(c, R(ini).GetProperty("id").GetString()!).ConfigureAwait(false));
                Respuesta pq = await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = R(ini).GetProperty("id").GetString() }).ConfigureAwait(false);
                string tokenQ = R(pq).GetProperty("token").GetString()!;

                if (!EsAdmin)
                {
                    // Sin elevar: aplicar se rechaza y NO toca nada.
                    Respuesta a1 = await c.LlamarAsync("firewall.aplicar", new { token = tokenFw }).ConfigureAwait(false);
                    Check(!a1.Exito && a1.Error!.Codigo == PoliticaDeAprobacion.AprobacionRequerida, "firewall.aplicar sin elevar pide aprobacion (UAC)", a1.Error?.Mensaje);
                    Check(Almacen.Reglas.All(r => r.RutaApp != app), "y no cambia el firewall");

                    Respuesta a2 = await c.LlamarAsync("cuarentena.aplicar", new { token = tokenQ }).ConfigureAwait(false);
                    Check(!a2.Exito && a2.Error!.Codigo == PoliticaDeAprobacion.AprobacionRequerida && File.Exists(malo),
                          "cuarentena.aplicar sin elevar pide aprobacion y no mueve el archivo");

                    Respuesta a3 = await c.LlamarAsync("limpieza.aplicar", new { token = new string('a', 64) }).ConfigureAwait(false);
                    Check(!a3.Exito && a3.Error!.Codigo == PoliticaDeAprobacion.AprobacionRequerida, "limpieza.aplicar tambien");

                    Respuesta a4 = await c.LlamarAsync("cuarentena.restaurar", new { token = new string('b', 64) }).ConfigureAwait(false);
                    Check(!a4.Exito && a4.Error!.Codigo == PoliticaDeAprobacion.AprobacionRequerida, "y cuarentena.restaurar");

                    Respuesta a5 = await c.LlamarAsync("cuarentena.purgar", new { token = new string('c', 64) }).ConfigureAwait(false);
                    Check(!a5.Exito && a5.Error!.Codigo == PoliticaDeAprobacion.AprobacionRequerida, "y cuarentena.purgar");

                    // La aprobacion se exige ANTES de mirar el token: un token falso da 'aprobacion', no 'token invalido'.
                    Respuesta falso = await c.LlamarAsync("firewall.aplicar", new { token = new string('d', 64) }).ConfigureAwait(false);
                    Check(falso.Error?.Codigo == PoliticaDeAprobacion.AprobacionRequerida,
                          "la aprobacion se comprueba antes que el token (no se gasta ni se revela nada del plan)");

                    Check(Almacen.Reglas.All(r => r.RutaApp != app) && File.Exists(malo), "ningun rechazo modifico nada");
                    Console.WriteLine("  [NOTA]  Camino elevado (aplicar con UAC aceptado) SIN PROBAR en esta ejecucion: ejecuta el arnes como administrador.");
                }
                else
                {
                    Respuesta a1 = await c.LlamarAsync("firewall.aplicar", new { token = tokenFw }).ConfigureAwait(false);
                    Check(a1.Exito && R(a1).GetProperty("aplicados").GetInt32() == 2, "elevado, firewall.aplicar se ejecuta");
                    Respuesta a2 = await c.LlamarAsync("cuarentena.aplicar", new { token = tokenQ }).ConfigureAwait(false);
                    Check(a2.Exito && !File.Exists(malo), "elevado, cuarentena.aplicar se ejecuta");
                }

                await host.StopAsync().ConfigureAwait(false);
            }
            finally { _aprobacion = "ninguna"; }

            // --- El modo 'ninguna' queda anotado: no pasa desapercibido ---
            bool avisoEnNota = LeerTodo(Notas(Path.Combine(raiz, "vault10"))).Contains("Aprobacion en modo 'ninguna'");
            Check(avisoEnNota, "el modo 'ninguna' deja un aviso en la nota de arranque (no se desactiva en silencio)");

            Console.WriteLine();
        }
    }
}
