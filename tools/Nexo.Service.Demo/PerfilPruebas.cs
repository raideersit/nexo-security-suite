using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Perfiles;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static SenalesDeActividad SenP(EstadoDePantalla p = EstadoDePantalla.Libre, FuenteDeEnergia e = FuenteDeEnergia.Corriente)
            => new(e, null, null, p, null);

        public static async Task ProbarPerfilDelServicio()
        {
            Console.WriteLine("Perfiles de actividad del servicio (§2az): estado, puerta, copia y escaneo programado");

            var ahora = new DateTimeOffset(2026, 11, 11, 10, 0, 0, TimeSpan.Zero);
            SenalesDeActividad sen = SenP();
            bool romper = false;
            var m = new ModuloPerfil(() => romper ? throw new InvalidOperationException("roto") : sen, TimeSpan.FromHours(1), TimeSpan.FromMilliseconds(5), () => ahora);
            Check(m.Intervalo == ModuloPerfil.IntervaloMinimo, "un intervalo menor que el mínimo se sube a 2 s");
            Check(m.Metodos.SequenceEqual(new[] { "perfil.estado" }), "un solo método, de lectura: no hay forma de cambiar el perfil por el pipe");

            // Sin ninguna lectura: no hay perfil, y la puerta está abierta.
            var e0 = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(e0.GetProperty("activo").GetBoolean() && e0.GetProperty("perfil").ValueKind == JsonValueKind.Null && !e0.GetProperty("pospone_tareas_pesadas").GetBoolean() && m.Puerta.Permite("t", ahora),
                  "sin lecturas: sin perfil, no pospone y la puerta está abierta");

            // Juego: se pospone.
            sen = SenP(EstadoDePantalla.JuegoD3D);
            m.UnaVuelta();
            var e1 = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(e1.GetProperty("perfil").GetString() == "JuegoOVideo" && e1.GetProperty("pospone_tareas_pesadas").GetBoolean() && e1.GetProperty("motivos").GetArrayLength() == 1
                  && e1.GetProperty("maximo_espera_horas").GetDouble() == 1, "con un juego: JuegoOVideo, pospone, con motivo y con el máximo de espera", e1.GetRawText());
            Check(!m.Puerta.Permite("copia", ahora), "y la puerta se cierra");
            var e1b = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(e1b.GetProperty("pospuestas").GetArrayLength() == 1 && e1b.GetProperty("pospuestas")[0].GetProperty("tarea").GetString() == "copia" && !e1b.GetProperty("pospuestas")[0].GetProperty("forzada").GetBoolean(),
                  "el estado lista lo pospuesto, aún sin forzar");

            // Máximo de espera: nunca queda parado para siempre.
            ahora = ahora.AddMinutes(59);
            Check(!m.Puerta.Permite("copia", ahora), "a los 59 min de espera todavía se pospone");
            ahora = ahora.AddMinutes(2);
            Check(m.Puerta.Permite("copia", ahora), "pasada la hora (el máximo), corre aunque siga el juego");
            var e1c = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(e1c.GetProperty("pospuestas")[0].GetProperty("forzada").GetBoolean(), "y el estado dice que se forzó");
            m.Puerta.Terminada("copia");
            Check(!m.Puerta.Permite("copia", ahora), "tras terminar, la siguiente espera empieza de cero");
            m.Puerta.Terminada("copia");

            // Salida con histéresis.
            sen = SenP();
            for (int i = 1; i < SelectorDePerfil.LecturasParaSalir; i++) m.UnaVuelta();
            Check((await PedirSenuelos(m, "perfil.estado", null)).R!.Value.GetProperty("perfil").GetString() == "JuegoOVideo", "dos lecturas Normales: sigue en JuegoOVideo (no parpadea)");
            m.UnaVuelta();
            var e2 = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(e2.GetProperty("perfil").GetString() == "Normal" && !e2.GetProperty("pospone_tareas_pesadas").GetBoolean() && m.Puerta.Permite("copia", ahora) && e2.GetProperty("pospuestas").GetArrayLength() == 0,
                  "a la tercera, Normal: la puerta se abre y no queda nada pospuesto");

            // Una lectura que falla nunca deja tareas paradas.
            sen = SenP(EstadoDePantalla.JuegoD3D);
            m.UnaVuelta();
            Check(!m.Puerta.Permite("x", ahora), "(con juego la puerta está cerrada)");
            m.Puerta.Terminada("x");
            romper = true;
            m.UnaVuelta();
            var e3 = (await PedirSenuelos(m, "perfil.estado", null)).R!.Value;
            Check(m.Puerta.Permite("x", ahora) && !e3.GetProperty("pospone_tareas_pesadas").GetBoolean() && e3.GetProperty("aviso").GetString()!.Contains("no se pospone nada"),
                  "una lectura fallida abre la puerta y lo dice (no deja la copia parada por no saber)");
            romper = false;
            m.UnaVuelta();
            Check((await PedirSenuelos(m, "perfil.estado", null)).R!.Value.GetProperty("aviso").ValueKind == JsonValueKind.Null, "la siguiente lectura buena borra el aviso");

            // Wi-Fi abierto: se mira como mucho una vez por minuto, y no cambia el perfil.
            {
                int consultas = 0; bool? abierto = false; bool lanzar = false;
                var t = new DateTimeOffset(2026, 11, 11, 11, 0, 0, TimeSpan.Zero);
                var w = new ModuloPerfil(() => SenP(), reloj: () => t, wifiAbierto: () => { consultas++; return lanzar ? throw new InvalidOperationException("sin WLAN") : abierto; });
                w.UnaVuelta();
                var f0 = (await PedirSenuelos(w, "perfil.estado", null)).R!.Value;
                Check(consultas == 1 && !f0.GetProperty("wifi_abierto").GetBoolean() && f0.GetProperty("wifi_leido").GetBoolean(), "Wi-Fi cerrado: se leyó (wifi_leido) y no hay aviso");
                abierto = true;
                t = t.AddSeconds(30); w.UnaVuelta();
                Check(consultas == 1 && !(await PedirSenuelos(w, "perfil.estado", null)).R!.Value.GetProperty("wifi_abierto").GetBoolean(), "a los 30 s no se vuelve a preguntar (como mucho 1 vez por minuto)");
                t = t.AddSeconds(31); w.UnaVuelta();
                var f1 = (await PedirSenuelos(w, "perfil.estado", null)).R!.Value;
                Check(consultas == 2 && f1.GetProperty("wifi_abierto").GetBoolean() && f1.GetProperty("perfil").GetString() == "Normal" && !f1.GetProperty("pospone_tareas_pesadas").GetBoolean(),
                      "pasado el minuto: Wi-Fi abierto, y el perfil sigue Normal (es un aviso de seguridad, no de rendimiento)");
                lanzar = true;
                t = t.AddSeconds(61); w.UnaVuelta();
                var f2 = (await PedirSenuelos(w, "perfil.estado", null)).R!.Value;
                Check(!f2.GetProperty("wifi_abierto").GetBoolean() && !f2.GetProperty("wifi_leido").GetBoolean() && f2.GetProperty("aviso").ValueKind == JsonValueKind.Null,
                      "si la lectura del Wi-Fi falla: sin aviso, «wifi_leido» = false (no se sabe) y el perfil sigue funcionando");
                abierto = null; lanzar = false;
                t = t.AddSeconds(61); w.UnaVuelta();
                Check(!(await PedirSenuelos(w, "perfil.estado", null)).R!.Value.GetProperty("wifi_leido").GetBoolean(), "null (servicio WLAN parado): también «no se sabe»");

                var sin = new ModuloPerfil(() => SenP(), reloj: () => t);
                sin.UnaVuelta();
                var f3 = (await PedirSenuelos(sin, "perfil.estado", null)).R!.Value;
                Check(!f3.GetProperty("wifi_abierto").GetBoolean() && !f3.GetProperty("wifi_leido").GetBoolean(), "sin lector de Wi-Fi: nunca hay aviso ni se aparenta haberlo leído");
            }

            // La regla sobre lecturas construidas (lo que el HP real no puede provocar: servicio WLAN parado, red abierta...).
            {
                var V = typeof(Nexo.Modules.Threats.Vulnerabilidades.InstantaneaDeWifi).Namespace;
                Nexo.Modules.Threats.Vulnerabilidades.InstantaneaDeWifi W(Nexo.Modules.Threats.Vulnerabilidades.EstadoDeLecturaWifi e, Nexo.Modules.Threats.Vulnerabilidades.ConexionActual? c)
                    => new(e, new[] { new Nexo.Modules.Threats.Vulnerabilidades.AdaptadorWifi("wifi", Array.Empty<Nexo.Modules.Threats.Vulnerabilidades.PerfilCrudo>(), c) });
                var E = Nexo.Modules.Threats.Vulnerabilidades.EstadoDeLecturaWifi.Correcta;
                Check(NexoWorker.WifiAbiertoDe(W(E, new Nexo.Modules.Threats.Vulnerabilidades.ConexionActual("casa", false, 1, 0))) == true, "conexión con la seguridad desactivada: Wi-Fi abierto");
                Check(NexoWorker.WifiAbiertoDe(W(E, new Nexo.Modules.Threats.Vulnerabilidades.ConexionActual("casa", true, 7, 4))) == false, "conexión cifrada: no es abierto");
                Check(NexoWorker.WifiAbiertoDe(W(E, null)) == false, "sin conexión activa: no es abierto");
                Check(NexoWorker.WifiAbiertoDe(W(Nexo.Modules.Threats.Vulnerabilidades.EstadoDeLecturaWifi.ServicioNoActivo, null)) is null, "servicio WLAN parado: «no se sabe» (null), no «cerrado»");
                Check(NexoWorker.WifiAbiertoDe(W(Nexo.Modules.Threats.Vulnerabilidades.EstadoDeLecturaWifi.Error, null)) is null, "error de lectura: «no se sabe»");
                Check(NexoWorker.WifiAbiertoDe(new Nexo.Modules.Threats.Vulnerabilidades.InstantaneaDeWifi(Nexo.Modules.Threats.Vulnerabilidades.EstadoDeLecturaWifi.SinAdaptador, Array.Empty<Nexo.Modules.Threats.Vulnerabilidades.AdaptadorWifi>())) == false, "sin adaptador Wi-Fi: false (un hecho, no un fallo)");
                _ = V;
            }

            // El lector REAL de Wi-Fi (este equipo), cruzado con netsh.
            {
                bool? real = NexoWorker.WifiAbiertoAhora();
                var psi = new System.Diagnostics.ProcessStartInfo("netsh.exe", "wlan show interfaces") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var pr = System.Diagnostics.Process.Start(psi)!;
                string net = pr.StandardOutput.ReadToEnd(); pr.WaitForExit();
                // «Estado» (es) / «State» (en): conectado si alguna línea de estado dice conectado/connected (y no desconectado/disconnected).
                bool conectado = net.Split((char)10).Any(l => { string x = l.Trim().ToLowerInvariant(); return (x.StartsWith("estado") || x.StartsWith("state")) && (x.Contains("conectado") || x.Contains("connected")) && !x.Contains("desconectado") && !x.Contains("disconnected"); });
                bool abiertaNetsh = conectado && net.Split((char)10).Any(l => { string x = l.Trim().ToLowerInvariant(); return (x.StartsWith("autenticaci") || x.StartsWith("authentication")) && (x.Contains("abierta") || x.Contains("open")); });
                Console.WriteLine("      INFO: Nexo dice Wi-Fi abierto = " + (real?.ToString() ?? "no se sabe") + "; netsh: conectado=" + conectado + ", abierta=" + abiertaNetsh);
                Check(real is not null && real == abiertaNetsh, "el lector real de Wi-Fi coincide con netsh (conectado: " + conectado + ")");
            }

            // Apagado.
            var ap = await PedirSenuelos(new ModuloPerfilApagado(), "perfil.estado", null);
            Check(ap.Ok && !ap.R!.Value.GetProperty("activo").GetBoolean() && ap.R.Value.GetProperty("nota").GetString()!.Contains("Nexo:Perfiles:Activo"), "apagado: lo dice y dice dónde activarlo");

            // --- La copia automática respeta la puerta; la manual, no ---
            {
                int llamadas = 0;
                var t = new DateTimeOffset(2026, 11, 11, 8, 0, 0, TimeSpan.Zero);
                DecisionDePerfil? perfil = new DecisionDePerfil(Perfil.JuegoOVideo, true, false, new[] { "juego" }, Array.Empty<string>());
                var puerta = new PuertaDeTareasPesadas(() => perfil, TimeSpan.FromHours(2));
                var w = new EscritorFalso();
                var c = new ModuloCopia(() => (new[] { Path.GetTempPath() }, Array.Empty<CarpetaSinSenuelo>()), @"X:\c", 3, TimeSpan.FromHours(1), w,
                    copiar: (cfg, tt, ct) => { llamadas++; return new ResultadoDeCopia(true, null, new Instantanea("i" + llamadas, tt, Array.Empty<EntradaDeCopia>(), Array.Empty<OmitidoEnCopia>(), false, null), 0, 0, 0, false, null); },
                    destinoDisponible: _ => true, reloj: () => t) { Puerta = puerta };
                await c.VueltaAsync(CancellationToken.None);
                Check(llamadas == 0, "copia automática con un juego: no arranca");
                t = t.AddMinutes(90); await c.VueltaAsync(CancellationToken.None);
                Check(llamadas == 0, "a los 90 min de espera (máximo 2 h): sigue sin arrancar");
                t = t.AddMinutes(31); await c.VueltaAsync(CancellationToken.None);
                Check(llamadas == 1, "pasado el máximo, la copia corre aunque siga el juego");
                t = t.AddMinutes(61); await c.VueltaAsync(CancellationToken.None);
                Check(llamadas == 1, "(la siguiente vuelve a esperar desde cero)");
                perfil = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());
                await c.VueltaAsync(CancellationToken.None);
                Check(llamadas == 2, "en cuanto el perfil es Normal, copia");

                // La copia a mano nunca espera.
                perfil = new DecisionDePerfil(Perfil.JuegoOVideo, true, false, new[] { "juego" }, Array.Empty<string>());
                t = t.AddMinutes(10);
                var h = await PedirSenuelos(c, "copia.hacer", null);
                Check(h.Ok && llamadas == 3, "«Copiar ahora» (a mano) corre aunque haya un juego: quien lo pide quiere la copia");
            }

            // --- El escaneo programado: espera de a un minuto y se detiene en el máximo ---
            {
                string raiz = Path.Combine(Path.GetTempPath(), "nexo-perfil-esc-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(raiz);
                try
                {
                    var t = new DateTimeOffset(2026, 11, 11, 8, 0, 0, TimeSpan.Zero);
                    DecisionDePerfil? perfil = new DecisionDePerfil(Perfil.Bateria, true, false, new[] { "batería" }, Array.Empty<string>());
                    var puerta = new PuertaDeTareasPesadas(() => perfil, TimeSpan.FromMinutes(5));
                    var esperas = new List<TimeSpan>();
                    Motor.Disponible = true;
                    await using var esc = new ModuloEscaneoProgramado(Motor, new GrabadorDeReportes(), new[] { raiz }, TimeSpan.FromHours(24), Path.Combine(raiz, "e.json"),
                        reloj: () => t, esperar: (d, ct) => { esperas.Add(d); t = t.Add(d); return Task.CompletedTask; }) { Puerta = puerta };
                    await esc.EsperarPuertaAsync(CancellationToken.None);
                    Check(esperas.Count == 5 && esperas.All(d => d == TimeSpan.FromMinutes(1)), "con batería el escaneo espera de a 1 min y arranca al llegar al máximo (5 esperas)", esperas.Count.ToString());

                    esperas.Clear();
                    puerta.Terminada("escaneo-programado");
                    perfil = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());
                    await esc.EsperarPuertaAsync(CancellationToken.None);
                    Check(esperas.Count == 0, "con perfil Normal el escaneo arranca sin esperar");

                    // El BUCLE real (no solo EsperarPuertaAsync): espera por la puerta, escanea, y deja la puerta limpia.
                    {
                        var t2 = new DateTimeOffset(2026, 11, 11, 8, 0, 0, TimeSpan.Zero);
                        DecisionDePerfil? pf = new DecisionDePerfil(Perfil.JuegoOVideo, true, false, new[] { "juego" }, Array.Empty<string>());
                        var puerta3 = new PuertaDeTareasPesadas(() => pf, TimeSpan.FromMinutes(3));
                        var esperas3 = new List<TimeSpan>();
                        var largo = new TaskCompletionSource();
                        await using var b = new ModuloEscaneoProgramado(Motor, new GrabadorDeReportes(), new[] { raiz }, TimeSpan.FromHours(24), Path.Combine(raiz, "e3.json"),
                            esperaInicial: TimeSpan.FromMinutes(2), reloj: () => t2,
                            esperar: (d, ct) =>
                            {
                                lock (esperas3) esperas3.Add(d);
                                if (d >= TimeSpan.FromHours(1)) { largo.TrySetResult(); return Task.Delay(Timeout.Infinite, ct); }
                                t2 = t2.Add(d);
                                return Task.CompletedTask;
                            }) { Puerta = puerta3 };
                        b.Iniciar();
                        Task listo = await Task.WhenAny(largo.Task, Task.Delay(TimeSpan.FromSeconds(20)));
                        Check(listo == largo.Task, "el bucle completa un escaneo y vuelve a esperar al día siguiente");
                        int minutos; lock (esperas3) minutos = esperas3.Count(d => d == TimeSpan.FromMinutes(1));
                        Check(minutos == 3, "el bucle esperó por la puerta de a 1 min hasta el máximo (3 min) antes de escanear", minutos.ToString());
                        Check(puerta3.Pospuestas(t2).Count == 0, "y al terminar el escaneo la puerta queda limpia (sin «escaneo-programado» pospuesto)");
                    }

                    // Una cancelación durante la espera no se queda colgada.
                    perfil = new DecisionDePerfil(Perfil.JuegoOVideo, true, false, new[] { "juego" }, Array.Empty<string>());
                    puerta.Terminada("escaneo-programado");
                    using var cts = new CancellationTokenSource();
                    var esc2 = new ModuloEscaneoProgramado(Motor, new GrabadorDeReportes(), new[] { raiz }, TimeSpan.FromHours(24), Path.Combine(raiz, "e2.json"),
                        reloj: () => t, esperar: (d, ct) => { cts.Cancel(); return Task.CompletedTask; }) { Puerta = puerta };
                    bool cancelo = false;
                    try { await esc2.EsperarPuertaAsync(cts.Token); } catch (OperationCanceledException) { cancelo = true; }
                    Check(cancelo, "si se cancela (apagado del servicio) mientras espera, sale limpiamente");
                    await esc2.DisposeAsync();
                }
                finally { try { Directory.Delete(raiz, true); } catch { } }
            }
        }
    }
}
