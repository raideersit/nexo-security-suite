using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ipc.Demo
{
    internal static class Program
    {
        private static int _fallos;

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            await ProbarBasico().ConfigureAwait(false);
            await ProbarEntradasMalas().ConfigureAwait(false);
            await ProbarFallosDelManejador().ConfigureAwait(false);
            await ProbarLimites().ConfigureAwait(false);
            ProbarAcl();

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

        private static string NombreUnico() => "nexo-ipc-demo-" + Guid.NewGuid().ToString("N");

        private static readonly TimeSpan Espera = TimeSpan.FromSeconds(5);

        // ============================================================
        private static async Task ProbarBasico()
        {
            Console.WriteLine("1. Peticion y respuesta");

            string nombre = NombreUnico();
            await using var servidor = new ServidorDePipe(nombre, new ManejadorDePrueba());
            servidor.Iniciar();

            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false);
            Respuesta ping = await c.LlamarAsync("ping").ConfigureAwait(false);
            Check(ping.Exito && ping.Resultado?.GetProperty("pong").GetBoolean() == true, "ping responde");
            Check(ping.Id == "1", "la respuesta lleva el id de la peticion");

            Respuesta eco = await c.LlamarAsync("eco", new { texto = "hola ñandú" }).ConfigureAwait(false);
            Check(eco.Exito && eco.Resultado?.GetProperty("texto").GetString() == "hola ñandú", "los parametros viajan intactos (UTF-8)");

            Respuesta desconocido = await c.LlamarAsync("no-existe").ConfigureAwait(false);
            Check(!desconocido.Exito && desconocido.Error!.Codigo == CodigoDeError.MetodoDesconocido,
                  "un metodo desconocido devuelve su codigo de error");

            Respuesta invalido = await c.LlamarAsync("eco", new { otro = 1 }).ConfigureAwait(false);
            Check(!invalido.Exito && invalido.Error!.Codigo == CodigoDeError.ParametrosInvalidos,
                  "los parametros invalidos devuelven su codigo (ErrorDeComando)");

            Check((await c.LlamarAsync("ping").ConfigureAwait(false)).Exito, "la conexion sigue usable tras los errores");

            bool nombreMalo = false;
            try { _ = new ServidorDePipe(@"..\pipe", new ManejadorDePrueba()); } catch (ArgumentException) { nombreMalo = true; }
            Check(nombreMalo, "rechaza un nombre de pipe con separadores");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarEntradasMalas()
        {
            Console.WriteLine("2. Entradas malas: el servidor no se cae ni se confunde");

            string nombre = NombreUnico();
            await using var servidor = new ServidorDePipe(nombre, new ManejadorDePrueba());
            servidor.Iniciar();

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                Respuesta r = await c.EnviarAsync(Encoding.UTF8.GetBytes("{esto no es json")).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.PeticionInvalida, "JSON roto: error, no excepcion");
                Check((await c.LlamarAsync("ping").ConfigureAwait(false)).Exito, "y la conexion sigue viva");

                r = await c.EnviarAsync(Encoding.UTF8.GetBytes("{\"id\":\"7\"}")).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.PeticionInvalida, "sin metodo: peticion invalida");

                r = await c.EnviarAsync(Encoding.UTF8.GetBytes("{\"id\":\"7\",\"method\":\"" + new string('x', 200) + "\"}")).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.PeticionInvalida, "metodo demasiado largo: peticion invalida");

                r = await c.EnviarAsync(new byte[] { 0xFF, 0xFE, 0xFD }).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.PeticionInvalida, "bytes que no son UTF-8: peticion invalida");
            }

            // Cabecera con un tamano enorme: el servidor cierra, no reserva memoria.
            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                byte[] cab = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(cab, int.MaxValue);
                await c.Flujo.WriteAsync(cab).ConfigureAwait(false);
                await c.Flujo.FlushAsync().ConfigureAwait(false);
                Check(await SeCierra(c.Flujo).ConfigureAwait(false), "un tamano declarado enorme cierra la conexion");
            }

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                await c.Flujo.WriteAsync(new byte[4]).ConfigureAwait(false);   // longitud 0
                await c.Flujo.FlushAsync().ConfigureAwait(false);
                Check(await SeCierra(c.Flujo).ConfigureAwait(false), "un mensaje de longitud cero cierra la conexion");
            }

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                byte[] cab = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(cab, -5);
                await c.Flujo.WriteAsync(cab).ConfigureAwait(false);
                await c.Flujo.FlushAsync().ConfigureAwait(false);
                Check(await SeCierra(c.Flujo).ConfigureAwait(false), "un tamano negativo cierra la conexion");
            }

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                byte[] cab = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(cab, 100);
                await c.Flujo.WriteAsync(cab).ConfigureAwait(false);
                await c.Flujo.WriteAsync(new byte[10]).ConfigureAwait(false);   // promete 100 y manda 10
                c.Flujo.Dispose();
            }

            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
                Check((await c.LlamarAsync("ping").ConfigureAwait(false)).Exito,
                      "tras todo eso el servidor sigue atendiendo a clientes normales");

            bool lanza = false;
            try { await Tramas.EscribirAsync(new MemoryStream(), new byte[Tramas.MaxBytes + 1], CancellationToken.None).ConfigureAwait(false); }
            catch (Tramas.ViolacionDeProtocoloException) { lanza = true; }
            Check(lanza, "el cliente tampoco puede enviar un mensaje por encima del maximo");

            Console.WriteLine();
        }

        /// <summary>True si el otro lado cierra (lectura de 0 bytes o error) en un plazo razonable.</summary>
        private static async Task<bool> SeCierra(Stream s)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            try { return await s.ReadAsync(new byte[16], cts.Token).ConfigureAwait(false) == 0; }
            catch (IOException) { return true; }
            catch (OperationCanceledException) { return false; }
        }

        // ============================================================
        private static async Task ProbarFallosDelManejador()
        {
            Console.WriteLine("3. Fallos del manejador: contenidos y sin filtrar detalles");

            string nombre = NombreUnico();
            await using var servidor = new ServidorDePipe(nombre, new ManejadorDePrueba(),
                new OpcionesDeServidor { TiempoPorPeticion = TimeSpan.FromMilliseconds(400) });
            servidor.Iniciar();

            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false);

            Respuesta boom = await c.LlamarAsync("explota").ConfigureAwait(false);
            Check(!boom.Exito && boom.Error!.Codigo == CodigoDeError.ErrorInterno, "una excepcion se convierte en error interno");
            Check(!boom.Error!.Mensaje.Contains("secreto") && !boom.Error.Mensaje.Contains("C:\\"),
                  "y el mensaje NO filtra la excepcion original (rutas, estado interno)", boom.Error.Mensaje);
            Check((await c.LlamarAsync("ping").ConfigureAwait(false)).Exito, "el servidor sigue en pie tras la excepcion");

            var reloj = Stopwatch.StartNew();
            Respuesta lento = await c.LlamarAsync("dormir").ConfigureAwait(false);
            Check(!lento.Exito && lento.Error!.Codigo == CodigoDeError.Tiempo && reloj.Elapsed < TimeSpan.FromSeconds(3),
                  "un manejador que no acaba se corta por tiempo", $"{lento.Error?.Codigo} en {reloj.Elapsed.TotalSeconds:0.0} s");
            Check((await c.LlamarAsync("ping").ConfigureAwait(false)).Exito, "y la conexion sigue usable");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarLimites()
        {
            Console.WriteLine("4. Limites: inactividad, concurrencia y parada");

            // Inactividad
            string n1 = NombreUnico();
            await using (var s1 = new ServidorDePipe(n1, new ManejadorDePrueba(),
                             new OpcionesDeServidor { TiempoInactivo = TimeSpan.FromMilliseconds(400) }))
            {
                s1.Iniciar();
                await using ClienteDePipe callado = await ClienteDePipe.ConectarAsync(n1, Espera).ConfigureAwait(false);
                Check(await SeCierra(callado.Flujo).ConfigureAwait(false), "un cliente que no dice nada es desconectado por inactividad");
            }

            // Mas clientes que huecos: todos acaban atendidos, sin abrir instancias sin limite.
            string n2 = NombreUnico();
            await using (var s2 = new ServidorDePipe(n2, new ManejadorDePrueba(),
                             new OpcionesDeServidor { MaxConexiones = 3 }))
            {
                s2.Iniciar();
                var tareas = Enumerable.Range(0, 20).Select(async i =>
                {
                    await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(n2, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                    Respuesta r = await c.LlamarAsync("eco", new { texto = "c" + i }).ConfigureAwait(false);
                    return r.Resultado?.GetProperty("texto").GetString() == "c" + i;
                }).ToList();
                bool[] ok = await Task.WhenAll(tareas).ConfigureAwait(false);
                Check(ok.All(x => x), "20 clientes con solo 3 huecos: todos reciben SU respuesta", ok.Count(x => x) + " de 20");
                Check(s2.Atendidas == 20, "y se atienden exactamente 20 peticiones", s2.Atendidas.ToString());
            }

            // Parada rapida con clientes colgados
            string n3 = NombreUnico();
            var s3 = new ServidorDePipe(n3, new ManejadorDePrueba());
            s3.Iniciar();
            await using ClienteDePipe a = await ClienteDePipe.ConectarAsync(n3, Espera).ConfigureAwait(false);
            await using ClienteDePipe b = await ClienteDePipe.ConectarAsync(n3, Espera).ConfigureAwait(false);
            _ = await a.LlamarAsync("ping").ConfigureAwait(false);
            var reloj = Stopwatch.StartNew();
            await s3.DisposeAsync().ConfigureAwait(false);
            Check(reloj.Elapsed < TimeSpan.FromSeconds(4), "detener con clientes conectados tarda menos de lo que tolera el SCM",
                  $"{reloj.Elapsed.TotalSeconds:0.0} s");
            Check(await SeCierra(b.Flujo).ConfigureAwait(false), "y los clientes conectados quedan desconectados");

            Console.WriteLine();
        }

        // ============================================================
        private static void ProbarAcl()
        {
            Console.WriteLine("5. ACL del pipe");

            using var pipe = NamedPipeServerStreamAcl.Create(NombreUnico(), PipeDirection.InOut, 2,
                PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, SeguridadDePipe.Crear());
            PipeSecurity seg = pipe.GetAccessControl();
            var reglas = seg.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();

            PipeAccessRule? De(WellKnownSidType t, AccessControlType tipo)
                => reglas.FirstOrDefault(r => r.IdentityReference.Equals(new SecurityIdentifier(t, null)) && r.AccessControlType == tipo);

            Check(De(WellKnownSidType.LocalSystemSid, AccessControlType.Allow)?.PipeAccessRights.HasFlag(PipeAccessRights.FullControl) == true,
                  "SYSTEM tiene control total");
            Check(De(WellKnownSidType.BuiltinAdministratorsSid, AccessControlType.Allow)?.PipeAccessRights.HasFlag(PipeAccessRights.FullControl) == true,
                  "los Administradores tienen control total");
            PipeAccessRule? inter = De(WellKnownSidType.InteractiveSid, AccessControlType.Allow);
            Check(inter is not null && inter.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite),
                  "el usuario interactivo puede leer y escribir");
            Check(inter is not null && !inter.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance)
                  && !inter.PipeAccessRights.HasFlag(PipeAccessRights.ChangePermissions)
                  && !inter.PipeAccessRights.HasFlag(PipeAccessRights.TakeOwnership),
                  "pero NO crear instancias del pipe ni cambiar sus permisos (nadie puede suplantar al servicio)");
            Check(De(WellKnownSidType.NetworkSid, AccessControlType.Deny) is not null, "la red esta denegada de forma explicita");
            Check(De(WellKnownSidType.WorldSid, AccessControlType.Allow) is null
                  && De(WellKnownSidType.AuthenticatedUserSid, AccessControlType.Allow) is null
                  && De(WellKnownSidType.BuiltinUsersSid, AccessControlType.Allow) is null,
                  "Everyone, Usuarios autenticados y Users NO tienen acceso");

            Console.WriteLine();
        }
    }

    /// <summary>Manejador de prueba con un comportamiento por metodo.</summary>
    internal sealed class ManejadorDePrueba : IManejadorDeComandos
    {
        public async Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
        {
            switch (metodo)
            {
                case "ping":
                    return new { pong = true };

                case "eco":
                    if (parametros is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty("texto", out JsonElement t))
                        return new { texto = t.GetString() };
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'texto'");

                case "explota":
                    throw new InvalidOperationException("secreto: C:\\Users\\alguien\\clave.txt");

                case "dormir":
                    await Task.Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
                    return null;

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }
    }
}
