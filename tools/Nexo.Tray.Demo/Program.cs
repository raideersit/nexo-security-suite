using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Firewall;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static class Program
    {
        private static int _fallos;
        private static readonly byte[] Marca = Encoding.ASCII.GetBytes("NEXO-MARCADOR-PRUEBA-BANDEJA");
        private static readonly bool EsAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-tray-demo-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(raiz);
            try
            {
                ProbarModelo();
                await ProbarContraElServicio(raiz).ConfigureAwait(false);
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

        // ============================================================
        private static InstantaneaDelServicio Conectada(bool tr = true, bool cobertura = true, bool motorCaido = false,
                                                         long perdidos = 0, params DeteccionVista[] det)
            => new InstantaneaDelServicio(true, "1.0", tr, cobertura, motorCaido, perdidos, 0, det, null, null);

        private static void ProbarModelo()
        {
            Console.WriteLine("1. Modelo de la bandeja (sin pantalla)");

            var m = new ModeloDeBandeja();
            Check(m.Estado == EstadoDeBandeja.Desconectado && m.Texto.Contains("sin conexion"), "al empezar no se sabe nada: DESCONECTADO");

            m.Actualizar(InstantaneaDelServicio.SinConexion("x"));
            Check(m.Estado == EstadoDeBandeja.Desconectado, "sin conexion no es 'normal'");

            m.Actualizar(Conectada());
            Check(m.Estado == EstadoDeBandeja.Normal && m.Texto == "Nexo: todo en orden", "con todo en orden: NORMAL");

            m.Actualizar(Conectada(tr: false));
            Check(m.Estado == EstadoDeBandeja.Atencion && m.Texto.Contains("apagado"), "tiempo real apagado: ATENCION (no 'todo en orden')");
            m.Actualizar(Conectada(motorCaido: true));
            Check(m.Estado == EstadoDeBandeja.Atencion && m.Texto.Contains("motor"), "motor caido: ATENCION");
            m.Actualizar(Conectada(cobertura: false, perdidos: 3));
            Check(m.Estado == EstadoDeBandeja.Atencion && m.Texto.Contains("cobertura incompleta"), "cobertura incompleta: ATENCION, con cuantos");

            var d1 = new DeteccionVista(@"C:\x\a.exe", "Firma.A", 100, "aaa");
            var d2 = new DeteccionVista(@"C:\x\b.exe", "Firma.B", 200, "bbb");
            var nuevas = m.Actualizar(Conectada(det: d1));
            Check(m.Estado == EstadoDeBandeja.Alerta && m.Texto.Contains("1 deteccion sin revisar") && nuevas.Count == 1,
                  "una deteccion: ALERTA y se avisa de ella");
            Check(m.Actualizar(Conectada(det: d1)).Count == 0, "la misma deteccion en la siguiente consulta NO se vuelve a notificar");
            Check(m.Actualizar(Conectada(det: new[] { d1, d2 })).Count == 1 && m.Texto.Contains("2 detecciones"), "una segunda si es nueva, y el texto pasa a plural");

            Check(m.Actualizar(Conectada(det: new DeteccionVista(d1.Ruta, d1.Firma, d1.Bytes, "otro-hash"))).Count == 1,
                  "la misma ruta con OTRO contenido es una deteccion nueva");

            m.Actualizar(Conectada(det: new[] { d1, d2 }));
            m.MarcarRevisadas();
            Check(m.SinRevisar.Count == 0 && m.Estado == EstadoDeBandeja.Atencion && m.Texto.Contains("sin resolver"),
                  "al abrir la revision dejan de ser alerta, pero NO se muestra 'todo en orden' mientras sigan sin resolver");

            m.Actualizar(Conectada());
            Check(m.Estado == EstadoDeBandeja.Normal, "cuando se resuelven (ya no estan), vuelve a NORMAL");
            Check(m.Actualizar(Conectada(det: d1)).Count == 1, "y si una reaparece, se avisa otra vez");

            // Una deteccion no se pierde aunque haya otros problemas: la alerta manda sobre la atencion.
            m.Actualizar(Conectada(tr: false, det: d2));
            Check(m.Estado == EstadoDeBandeja.Alerta, "una deteccion sin revisar manda sobre 'tiempo real apagado'");

            // Sin conexion no se notifica nada aunque haya datos viejos.
            var m2 = new ModeloDeBandeja();
            m2.Actualizar(Conectada(det: d1));
            Check(m2.Actualizar(new InstantaneaDelServicio(false, null, false, false, false, 0, 0, new[] { d2 }, null, "x")).Count == 0,
                  "una consulta sin conexion no genera notificaciones");

            var larga = new ModeloDeBandeja();
            larga.Actualizar(Conectada(cobertura: false, perdidos: 123456789012345));
            Check(larga.Texto.Length <= 63, "el texto cabe en el limite del icono (63)", larga.Texto.Length.ToString());

            Check(AccionesDelServicio.EsTokenValido(new string('a', 64)) && !AccionesDelServicio.EsTokenValido("corto")
                  && !AccionesDelServicio.EsTokenValido(new string('A', 64)) && !AccionesDelServicio.EsTokenValido(new string('a', 63) + "\"")
                  && !AccionesDelServicio.EsTokenValido(null), "solo se aceptan tokens de 64 hexadecimales (nada que inyectar en una linea de comandos)");

            Console.WriteLine();
        }

        // ============================================================
        private sealed class LanzadorFalso : ILanzadorElevado
        {
            public readonly List<(TipoDeAccion, string)> Llamadas = new();
            public bool Resultado = true;
            public bool Lanzar(TipoDeAccion tipo, string token) { Llamadas.Add((tipo, token)); return Resultado; }
        }

        private static IHost Servicio(string vault, string pipe, string aprobacion, ManualFuente? fuente, string carpetaQ)
        {
            HostApplicationBuilder b = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
            b.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Nexo:Vault"] = vault, ["Nexo:PipeName"] = pipe, ["Nexo:Cuarentena"] = carpetaQ,
                ["Nexo:Aprobacion:Modo"] = aprobacion,
                ["Nexo:TiempoReal:Activo"] = fuente is null ? "false" : "true",
                ["Nexo:TiempoReal:Raices"] = fuente is null ? "" : carpetaQ + "-sin-uso"
            });
            b.Services.AddSingleton<IAlmacenDeFirewall>(new AlmacenVacio());
            b.Services.AddSingleton<IMotorDeFirmas>(new MotorFalso());
            if (fuente is not null) b.Services.AddSingleton<IFuenteDeCambios>(fuente);
            b.Services.AddHostedService<NexoWorker>();
            return b.Build();
        }

        private static async Task ProbarContraElServicio(string raiz)
        {
            Console.WriteLine("2. La bandeja contra el servicio real (en el mismo proceso)");

            string pipe = "nexo-tray-demo-" + Guid.NewGuid().ToString("N");
            TimeSpan espera = TimeSpan.FromSeconds(5);

            // --- Sin servicio ---
            var sw = Stopwatch.StartNew();
            InstantaneaDelServicio sin = await ConsultorDelServicio.ConsultarAsync(pipe, TimeSpan.FromMilliseconds(600)).ConfigureAwait(false);
            Check(!sin.Conectado && sin.Error!.Contains("no esta en marcha") && sw.Elapsed < TimeSpan.FromSeconds(3),
                  "sin servicio, la consulta dice 'desconectado' y no se cuelga", sin.Error);
            var mSin = new ModeloDeBandeja();
            mSin.Actualizar(sin);
            Check(mSin.Estado == EstadoDeBandeja.Desconectado, "y la bandeja se pone en DESCONECTADO");

            // --- Servicio con el tiempo real apagado ---
            string vault1 = Path.Combine(raiz, "vault1");
            using (IHost h1 = Servicio(vault1, pipe, "ninguna", null, Path.Combine(raiz, "q1")))
            {
                await h1.StartAsync().ConfigureAwait(false);
                InstantaneaDelServicio i = await ConsultorDelServicio.ConsultarAsync(pipe, espera).ConfigureAwait(false);
                var m = new ModeloDeBandeja();
                m.Actualizar(i);
                Check(i.Conectado && !i.TiempoRealActivo && m.Estado == EstadoDeBandeja.Atencion,
                      "con el tiempo real apagado (por omision) la bandeja avisa ATENCION, no 'todo en orden'", m.Texto);
                await h1.StopAsync().ConfigureAwait(false);
            }

            // --- Servicio con el tiempo real encendido y una amenaza ---
            string carpeta = Path.Combine(raiz, "vigilada");
            Directory.CreateDirectory(carpeta);
            string malo = Path.Combine(carpeta, "descargado.exe");
            File.WriteAllBytes(malo, Marca.Concat(new byte[] { 1 }).ToArray());

            string pipe2 = "nexo-tray-demo-" + Guid.NewGuid().ToString("N");
            var fuente = new ManualFuente();
            var lanzador = new LanzadorFalso();
            using (IHost h = Servicio(Path.Combine(raiz, "vault2"), pipe2, "elevada", fuente, Path.Combine(raiz, "q2")))
            {
                await h.StartAsync().ConfigureAwait(false);

                var modelo = new ModeloDeBandeja();
                modelo.Actualizar(await ConsultorDelServicio.ConsultarAsync(pipe2, espera).ConfigureAwait(false));
                Check(modelo.Estado == EstadoDeBandeja.Normal, "con el tiempo real encendido y sin amenazas: NORMAL", modelo.Texto);

                fuente.Emitir(malo);
                IReadOnlyList<DeteccionVista> nuevas = Array.Empty<DeteccionVista>();
                for (int k = 0; k < 120 && nuevas.Count == 0; k++)
                {
                    await Task.Delay(50).ConfigureAwait(false);
                    nuevas = modelo.Actualizar(await ConsultorDelServicio.ConsultarAsync(pipe2, espera).ConfigureAwait(false));
                }
                Check(nuevas.Count == 1 && nuevas[0].Ruta == malo && modelo.Estado == EstadoDeBandeja.Alerta,
                      "una amenaza detectada por el servicio llega a la bandeja: ALERTA y una notificacion");

                // --- Previsualizar: la bandeja solo muestra lo que preparo el servicio ---
                PlanPropuesto plan = await AccionesDelServicio.PrevisualizarCuarentenaAsync(pipe2, "tiempo-real", espera).ConfigureAwait(false);
                Check(plan.HayCambios && plan.Token is { Length: 64 } && plan.Descripcion.Contains("Prueba.Bandeja"),
                      "el plan viene del servicio (con su descripcion y token), no lo construye la bandeja");
                Check(File.Exists(malo), "previsualizar no toca el archivo");

                // --- Aplicar con aprobacion elevada ---
                if (!EsAdmin)
                {
                    ResultadoDeAplicar sinUac = await AccionesDelServicio.AplicarAsync(pipe2, TipoDeAccion.Cuarentena, plan.Token!, espera).ConfigureAwait(false);
                    Check(!sinUac.Exito && sinUac.NecesitaElevacion && File.Exists(malo),
                          "sin elevar, el servicio pide aprobacion (UAC) y la bandeja lo distingue de un fallo");

                    lanzador.Resultado = true;
                    ResultadoDeAplicar c1 = await AccionesDelServicio.AplicarConAprobacionAsync(pipe2, TipoDeAccion.Cuarentena, plan.Token!, lanzador, espera).ConfigureAwait(false);
                    Check(c1.Exito && c1.NecesitaElevacion && lanzador.Llamadas.Count == 1
                          && lanzador.Llamadas[0] == (TipoDeAccion.Cuarentena, plan.Token!),
                          "si hace falta UAC, abre el proceso elevado con el MISMO token (el plan seguia vigente)");
                    Check(File.Exists(malo), "y mientras el usuario no apruebe, el archivo sigue donde estaba");

                    lanzador.Resultado = false;
                    ResultadoDeAplicar c2 = await AccionesDelServicio.AplicarConAprobacionAsync(pipe2, TipoDeAccion.Cuarentena, plan.Token!, lanzador, espera).ConfigureAwait(false);
                    Check(!c2.Exito && c2.NecesitaElevacion && c2.Mensaje.Contains("No se aprobo") && File.Exists(malo),
                          "si el usuario cancela el UAC, no se aplica nada y se dice");
                    Console.WriteLine("  [NOTA]  Aplicar CON el UAC aceptado SIN PROBAR en esta ejecucion: ejecuta el arnes como administrador.");
                }
                else
                {
                    ResultadoDeAplicar r = await AccionesDelServicio.AplicarConAprobacionAsync(pipe2, TipoDeAccion.Cuarentena, plan.Token!, lanzador, espera).ConfigureAwait(false);
                    Check(r.Exito && !r.NecesitaElevacion && lanzador.Llamadas.Count == 0 && !File.Exists(malo),
                          "elevado, se aplica directamente (sin lanzar otro proceso) y el archivo va a cuarentena");
                }

                Check(!(await AccionesDelServicio.AplicarAsync(pipe2, TipoDeAccion.Cuarentena, "no-es-un-token", espera).ConfigureAwait(false)).Exito,
                      "un token mal formado ni siquiera se envia al servicio");

                // --- El ejecutable: cableado real con --una-vez ---
                string salida = Path.Combine(raiz, "una-vez.json");
                int codigo = EjecutarBandeja($"--una-vez --salida \"{salida}\" --pipe {pipe2}");
                JsonElement js = JsonDocument.Parse(File.ReadAllText(salida)).RootElement;
                Check(codigo == 0 && js.GetProperty("conectado").GetBoolean() && js.GetProperty("estado").GetString() != "Desconectado",
                      "nexo-tray --una-vez se conecta al servicio y calcula el estado", js.ToString());

                // --- La bandeja de verdad: arranca, se queda viva y no se duplica ---
                string dll = typeof(ModeloDeBandeja).Assembly.Location;
                using Process? viva = Process.Start(new ProcessStartInfo("dotnet", "\"" + dll + "\" --pipe " + pipe2) { UseShellExecute = false, CreateNoWindow = true });
                try
                {
                    await Task.Delay(4000).ConfigureAwait(false);
                    Check(viva is { HasExited: false } && viva.Responding,
                          "la bandeja arranca, crea su icono y se queda viva y respondiendo (consultando al servicio)");

                    using Process? segunda = Process.Start(new ProcessStartInfo("dotnet", "\"" + dll + "\" --pipe " + pipe2) { UseShellExecute = false, CreateNoWindow = true });
                    bool salio = segunda!.WaitForExit(8000);
                    Check(salio && segunda.ExitCode == 0 && viva is { HasExited: false }, "una segunda bandeja no se duplica: sale y deja la primera");
                    if (!salio) segunda.Kill(true);
                }
                finally
                {
                    if (viva is { HasExited: false }) { viva.Kill(true); viva.WaitForExit(5000); }
                }

                await h.StopAsync().ConfigureAwait(false);
            }

            string salida2 = Path.Combine(raiz, "una-vez-sin.json");
            int codigo2 = EjecutarBandeja($"--una-vez --salida \"{salida2}\" --pipe {pipe2}");
            JsonElement js2 = JsonDocument.Parse(File.ReadAllText(salida2)).RootElement;
            Check(codigo2 == 1 && !js2.GetProperty("conectado").GetBoolean() && js2.GetProperty("estado").GetString() == "Desconectado",
                  "con el servicio parado, el ejecutable sale con error y reporta DESCONECTADO");

            Console.WriteLine();
        }

        /// <summary>Ejecuta la bandeja real (el dll junto al arnes) en modo --una-vez.</summary>
        private static int EjecutarBandeja(string argumentos)
        {
            string dll = typeof(ModeloDeBandeja).Assembly.Location;
            using var p = Process.Start(new ProcessStartInfo("dotnet", "\"" + dll + "\" " + argumentos)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            })!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(30000)) { p.Kill(true); return -1; }
            return p.ExitCode;
        }
    }

    internal sealed class ManualFuente : IFuenteDeCambios
    {
        private Action<CambioDeArchivo>? _c;
        public void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder) => _c = alCambiar;
        public void Emitir(string ruta) => _c!(new CambioDeArchivo(ruta, MotivoDeCambio.Modificado));
        public void Dispose() { }
    }

    internal sealed class MotorFalso : IMotorDeFirmas
    {
        public string Nombre => "motor-falso";
        public Task<string> VersionAsync(CancellationToken ct = default) => Task.FromResult("falso");

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            using var ms = new MemoryStream();
            await contenido.CopyToAsync(ms, ct).ConfigureAwait(false);
            return ms.ToArray().AsSpan().IndexOf(Encoding.ASCII.GetBytes("NEXO-MARCADOR-PRUEBA-BANDEJA")) >= 0
                ? ResultadoDeMotor.Infectado("Prueba.Bandeja") : ResultadoDeMotor.Limpio();
        }
    }

    internal sealed class AlmacenVacio : IAlmacenDeFirewall
    {
        public IReadOnlyList<ReglaDeFirewall> Enumerar() => Array.Empty<ReglaDeFirewall>();
        public void Agregar(ReglaDeFirewall regla) { }
        public void Eliminar(string nombre) { }
        public void Habilitar(string nombre, bool habilitada) { }
        public IReadOnlyList<PoliticaDePerfil> LeerPoliticas() => Array.Empty<PoliticaDePerfil>();
    }
}
