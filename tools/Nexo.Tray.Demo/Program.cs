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
    internal static partial class Program
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
                ProbarResumenDeAcciones();
                await ProbarExitoQueDevuelveElServicio().ConfigureAwait(false);
                await ProbarSenuelosEnLaBandeja().ConfigureAwait(false);
                await ProbarCopiaEnLaBandeja().ConfigureAwait(false);
                ProbarUbicacionSegura(raiz);
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

        /// <summary>Un servicio de mentira que contesta «aplicar» con lo que se le diga.</summary>
        private sealed class ServicioQueContesta : Nexo.Ipc.IManejadorDeComandos
        {
            public object? Respuesta;
            public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct) => Task.FromResult(Respuesta);
        }

        // En la VPN y en las carpetas protegidas la LLAMADA va bien aunque Windows no aplique el cambio: manda el «exito» de la respuesta.
        private static async Task ProbarExitoQueDevuelveElServicio()
        {
            Console.WriteLine("Aplicar: el «exito» que devuelve el servicio manda");
            string pipe = "nexo-tray-exito-" + Guid.NewGuid().ToString("N");
            var falso = new ServicioQueContesta();
            await using var servidor = new Nexo.Ipc.ServidorDePipe(pipe, falso);
            servidor.Iniciar();
            TimeSpan espera = TimeSpan.FromSeconds(5);
            string token = new string('a', 64);

            falso.Respuesta = new { exito = false, mensaje = "Windows aceptó la orden, pero el ajuste no cambió.", modo_final = 0, destino = "activar" };
            ResultadoDeAplicar r = await AccionesDelServicio.AplicarAsync(pipe, TipoDeAccion.CarpetasProtegidas, token, espera).ConfigureAwait(false);
            Check(!r.Exito && !r.NecesitaElevacion && r.Mensaje.StartsWith("No se pudo:"), "carpetas protegidas: llamada correcta pero «exito: false» = NO aplicado", r.Mensaje);
            falso.Respuesta = new { exito = true, mensaje = "Listo.", modo_final = 1, destino = "activar" };
            Check((await AccionesDelServicio.AplicarAsync(pipe, TipoDeAccion.CarpetasProtegidas, token, espera).ConfigureAwait(false)).Exito, "con «exito: true», aplicado");
            falso.Respuesta = new { exito = false, mensaje = "WireGuard falló." };
            Check(!(await AccionesDelServicio.AplicarAsync(pipe, TipoDeAccion.Vpn, token, espera).ConfigureAwait(false)).Exito, "VPN: igual");
        }

        // Lo que la ventana y la bandeja le cuentan a quien acaba de aplicar una accion. Visto en la ventana real (2026-11-05):
        // la limpieza simulada decia «36149 archivos limpiados», un archivo era «1 archivos» y «2 omitidos» no decia por que.
        private static void ProbarResumenDeAcciones()
        {
            Console.WriteLine("Resumen de lo aplicado");
            static string R(TipoDeAccion t, string json) { using JsonDocument d = JsonDocument.Parse(json); return AccionesDelServicio.Resumir(t, d.RootElement.Clone()); }

            string r = R(TipoDeAccion.Limpieza, "{\"eliminados\":36149,\"bytes_liberados\":16431000000,\"modo\":\"simulado\",\"omitidos\":[],\"omitidos_total\":0}");
            Check(r.StartsWith("SIMULACION:", StringComparison.Ordinal) && r.Contains("No se borro nada") && !r.Contains("limpiados"),
                  "limpieza simulada: lo dice y NO dice «limpiados»", r);
            r = R(TipoDeAccion.Limpieza, "{\"eliminados\":2311,\"bytes_liberados\":1932735283,\"modo\":\"papelera\",\"omitidos\":[],\"omitidos_total\":0}");
            Check(r.StartsWith("2311 archivos limpiados (1.8 GB).", StringComparison.Ordinal), "limpieza a la Papelera: «limpiados»", r);
            r = R(TipoDeAccion.Limpieza, "{\"eliminados\":3,\"bytes_liberados\":10,\"omitidos\":[],\"omitidos_total\":0}");
            Check(r.StartsWith("3 archivos limpiados", StringComparison.Ordinal), "sin «modo» (un servicio antiguo): se lee como una limpieza normal", r);
            Check(R(TipoDeAccion.Limpieza, "{\"eliminados\":1,\"bytes_liberados\":10,\"modo\":\"papelera\",\"omitidos\":[]}").StartsWith("1 archivo limpiado", StringComparison.Ordinal),
                  "uno: «1 archivo limpiado»");

            Check(R(TipoDeAccion.Cuarentena, "{\"movidos\":[\"a\"],\"omitidos\":[]}") == "1 archivo en cuarentena. ", "uno en cuarentena: singular");
            Check(R(TipoDeAccion.Cuarentena, "{\"movidos\":[\"a\",\"b\"],\"omitidos\":[]}") == "2 archivos en cuarentena. ", "dos en cuarentena: plural");
            Check(R(TipoDeAccion.Firewall, "{\"aplicados\":1,\"omitidos\":[]}") == "1 cambio aplicado. ", "un cambio de firewall: singular");
            Check(AccionesDelServicio.MetodoDeAplicar(TipoDeAccion.CarpetasProtegidas) == "cfa.aplicar", "carpetas protegidas: se aplica con «cfa.aplicar»");
            Check(Enum.TryParse("carpetasprotegidas", ignoreCase: true, out TipoDeAccion tcfa) && tcfa == TipoDeAccion.CarpetasProtegidas, "la bandeja elevada entiende «--aplicar CarpetasProtegidas»");
            r = R(TipoDeAccion.CarpetasProtegidas, "{\"exito\":false,\"mensaje\":\"Windows aceptó la orden, pero el ajuste no cambió.\"}");
            Check(r.StartsWith("No se pudo: Windows aceptó", StringComparison.Ordinal), "carpetas protegidas sin aplicar: lo dice (nunca «activado»)", r);
            Check(R(TipoDeAccion.CarpetasProtegidas, "{\"exito\":true,\"mensaje\":\"Listo.\"}") == "Listo.", "carpetas protegidas aplicadas: el mensaje del servicio");

            r = R(TipoDeAccion.Firewall, "{\"aplicados\":0,\"omitidos\":[\"necesita administrador\",\"necesita administrador\"]}");
            Check(r == "0 cambios aplicados. 2 omitidos. El primero: necesita administrador", "omitidos: cuantos y el primer motivo", r);
            r = R(TipoDeAccion.Firewall, "{\"aplicados\":0,\"omitidos\":[\"ya existe\"]}");
            Check(r == "0 cambios aplicados. 1 omitido. Motivo: ya existe", "un omitido: «Motivo:»", r);
            r = R(TipoDeAccion.Firewall, "{\"aplicados\":0,\"omitidos\":[{\"x\":1}]}");
            Check(r == "0 cambios aplicados. 1 omitido.", "omitidos que no son texto: solo la cuenta, sin romper", r);
            r = R(TipoDeAccion.Firewall, "{\"aplicados\":0,\"omitidos\":[\"" + new string('m', 500) + "\"]}");
            Check(r.Length < 260 && r.EndsWith("...", StringComparison.Ordinal), "un motivo larguisimo se recorta", r.Length + " caracteres");
            Check(R(TipoDeAccion.Restauracion, "{\"exito\":true}") == "Archivo restaurado.", "restaurar: sin cambios");
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

            // Cobertura: sin cifra inventada de archivos; con carpetas por revisar, cuantas (hallazgo 2026-11-02).
            var pr = new ModeloDeBandeja();
            pr.Actualizar(Conectada(cobertura: false, perdidos: 2577) with { PorRevisar = new[] { @"C:\a", @"C:\b" } });
            Check(pr.Estado == EstadoDeBandeja.Atencion && pr.Texto.Contains("2 carpetas por revisar") && !pr.Texto.Contains("2577"),
                  "cobertura incompleta: dice cuantas CARPETAS hay por revisar, no un numero de eventos", pr.Texto);

            Check(AccionesDelServicio.RutasParaRevisar(new[] { @"C:\u\Downloads\x", @"C:\u\Downloads", @"C:\u\Downloads2", @"c:\U\downloads\", "" })
                      .SequenceEqual(new[] { @"C:\u\Downloads", @"C:\u\Downloads2" }),
                  "las rutas a revisar se reducen: sin duplicados ni subcarpetas de otra (Downloads2 no es subcarpeta de Downloads)");
            Check(AccionesDelServicio.RutasParaRevisar(Enumerable.Range(0, 20).Select(i => @"C:\d" + i)).Count == AccionesDelServicio.MaxRutasPorEscaneo,
                  "y como mucho las que acepta un escaneo (el resto queda para otra pasada)");
            Check(!AccionesDelServicio.ResumirRevision(0, 3, false).Contains("sin detecciones y se pudo")
                  && AccionesDelServicio.ResumirRevision(0, 0, true).Contains("INCOMPLETA")
                  && AccionesDelServicio.ResumirRevision(0, 0, false).Contains("se pudo analizar todo"),
                  "el resumen de la revision nunca dice 'limpio' si algo no se analizo o quedo a medias");

            Check(AccionesDelServicio.EsTokenValido(new string('a', 64)) && !AccionesDelServicio.EsTokenValido("corto")
                  && !AccionesDelServicio.EsTokenValido(new string('A', 64)) && !AccionesDelServicio.EsTokenValido(new string('a', 63) + "\"")
                  && !AccionesDelServicio.EsTokenValido(null), "solo se aceptan tokens de 64 hexadecimales (nada que inyectar en una linea de comandos)");

            Console.WriteLine();
        }

        // ============================================================
        private static void ProbarUbicacionSegura(string raiz)
        {
            Console.WriteLine("1b. Solo se eleva desde una ubicacion que el usuario no pueda modificar");

            string propia = Path.Combine(raiz, "bandeja");
            Directory.CreateDirectory(propia);
            string exePropio = Path.Combine(propia, "nexo-tray.exe");
            File.WriteAllBytes(exePropio, new byte[] { 0x4D, 0x5A });

            Check(!UbicacionSegura.EsSegura(exePropio, out string m1) && m1.Length > 0,
                  "un .exe en una carpeta del usuario NO es seguro (el usuario, o un proceso suyo, lo puede reemplazar)", m1);

            string sistema = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            if (File.Exists(sistema))
                Check(UbicacionSegura.EsSegura(sistema, out string m2), "un ejecutable de System32 si es seguro (solo lo modifican Administradores/SYSTEM)", m2);

            string? pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string? algo = Directory.Exists(pf)
                ? Directory.EnumerateFiles(pf, "*.exe", new EnumerationOptions
                    { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }).FirstOrDefault()
                : null;
            if (algo is not null)
                Check(UbicacionSegura.EsSegura(algo, out string m3), "y uno bajo Program Files tambien", m3 + " " + algo);

            Check(!UbicacionSegura.EsSegura(Path.Combine(propia, "no-existe.exe"), out string m4) && m4.Contains("no se pudo comprobar"),
                  "si no se puede comprobar, se asume que NO es seguro", m4);

            // Escribir en la carpeta es lo que importa aunque el .exe fuera solo de lectura.
            File.SetAttributes(exePropio, FileAttributes.ReadOnly);
            Check(!UbicacionSegura.EsSegura(exePropio, out _), "marcar el archivo como solo lectura no lo hace seguro: la carpeta sigue siendo del usuario");
            File.SetAttributes(exePropio, FileAttributes.Normal);

            // El lanzador real se NIEGA a elevar desde una ubicacion insegura, sin abrir ningun UAC.
            var real = new Nexo.Ui.Tray.LanzadorElevado("pipe-de-prueba", exePropio);
            bool lanzo = real.Lanzar(TipoDeAccion.Cuarentena, new string('a', 64));
            Check(!lanzo && real.UltimoMotivo is not null && real.UltimoMotivo.Contains("ubicacion que el usuario puede modificar"),
                  "el lanzador elevado se niega desde una ubicacion que el usuario puede modificar (sin mostrar ningun UAC)", real.UltimoMotivo);
            Check(!new Nexo.Ui.Tray.LanzadorElevado("p", exePropio).Lanzar(TipoDeAccion.Cuarentena, "no-valido")
                  && new Nexo.Ui.Tray.LanzadorElevado("p", exePropio).UltimoMotivo is null,
                  "y un token mal formado se rechaza antes de mirar nada");

            Console.WriteLine();
        }

        // ============================================================
        private sealed class LanzadorFalso : ILanzadorElevado
        {
            public readonly List<(TipoDeAccion, string)> Llamadas = new();
            public bool Resultado = true;
            public string? UltimoMotivo { get; set; }
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
