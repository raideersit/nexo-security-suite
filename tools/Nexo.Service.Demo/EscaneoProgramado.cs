using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Escaner;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static JsonElement J(object? o) => JsonSerializer.SerializeToElement(o);

        private static async Task<JsonElement> EstadoProgramado(ModuloEscaneoProgramado m)
            => J(await m.ManejarAsync("escaneo-programado.estado", null, CancellationToken.None).ConfigureAwait(false));

        private static async Task ProbarEscaneoProgramado(string raiz)
        {
            Console.WriteLine("13. Escaneo programado");

            string datos = Path.Combine(raiz, "programado");
            string limpia = Path.Combine(datos, "limpia");
            string sucia = Path.Combine(datos, "sucia");
            Directory.CreateDirectory(limpia);
            Directory.CreateDirectory(sucia);
            File.WriteAllText(Path.Combine(limpia, "a.txt"), "nada");
            File.WriteAllBytes(Path.Combine(sucia, "malo.exe"), Marca.Concat(new byte[] { 9 }).ToArray());
            string estadoArchivo = Path.Combine(datos, "estado", "escaneo-programado.json");

            var ahora = new DateTimeOffset(2026, 11, 4, 10, 0, 0, TimeSpan.Zero);
            Func<DateTimeOffset> reloj = () => ahora;
            TimeSpan dia = TimeSpan.FromHours(24), reintento = TimeSpan.FromHours(1), inicial = TimeSpan.FromMinutes(2);
            var reportes = new GrabadorDeReportes();
            Motor.Disponible = true;

            ModuloEscaneoProgramado Nuevo(IEnumerable<string> raices, string? estado = null)
                => new ModuloEscaneoProgramado(Motor, reportes, raices, dia, estado ?? estadoArchivo, reintento: reintento, esperaInicial: inicial, reloj: reloj);

            // --- Nunca se ha ejecutado: no se presenta como «al dia» ---
            await using (var m = Nuevo(new[] { limpia }))
            {
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("activo").GetBoolean() && e.GetProperty("ultimo_resultado").GetString() == "nunca" && e.GetProperty("vencido").GetBoolean(),
                      "sin ningun escaneo previo el estado dice «nunca» y «vencido» (no «al dia»)", e.ToString());
                Check(m.CalcularEspera() == inicial, "el primer escaneo espera un rato tras arrancar (no compite con el arranque)");
            }

            // --- Carpeta limpia: completo, se guarda, avisa al tiempo real ---
            int avisos = 0;
            await using (var m = Nuevo(new[] { limpia }))
            {
                m.EscaneoCompleto += (_, _, _) => avisos++;
                await m.EjecutarUnaVezAsync(CancellationToken.None).ConfigureAwait(false);
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("ultimo_resultado").GetString() == "limpio" && !e.GetProperty("vencido").GetBoolean() && e.GetProperty("analizados").GetInt32() == 1,
                      "una carpeta limpia termina «limpio», no vencido y con lo analizado", e.ToString());
                Check(avisos == 1, "un escaneo completo avisa (el tiempo real da por revisadas esas carpetas)");
                Check(File.Exists(estadoArchivo), "se guarda cuando termino el ultimo escaneo completo");
                Check(m.CalcularEspera() == dia, "tras uno completo, el siguiente es a un intervalo");
            }

            // --- Persistencia: tras reiniciar se respeta lo que falta, y lo vencido se ejecuta ya ---
            ahora += TimeSpan.FromHours(10);
            await using (var m = Nuevo(new[] { limpia }))
            {
                m.CargarEstado();
                Check(m.CalcularEspera() == TimeSpan.FromHours(14), "tras reiniciar, espera lo que faltaba del intervalo (no empieza de cero)", m.CalcularEspera().ToString());
            }
            ahora += TimeSpan.FromHours(20); // ya paso el dia: el equipo estuvo apagado
            await using (var m = Nuevo(new[] { limpia }))
            {
                m.CargarEstado();
                Check(m.CalcularEspera() == TimeSpan.Zero, "si el equipo estuvo apagado y el escaneo vencio, se ejecuta al volver (no espera otro dia)");
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("vencido").GetBoolean(), "y mientras tanto el estado dice «vencido»");
            }
            ahora = new DateTimeOffset(2026, 11, 4, 10, 0, 0, TimeSpan.Zero);

            // --- Reloj atrasado: un «ultimo completo» en el futuro no pospone indefinidamente ---
            string futuro = Path.Combine(datos, "estado", "futuro.json");
            File.WriteAllText(futuro, JsonSerializer.Serialize(new { ultimo_completo = ahora.AddDays(400).ToString("o") }));
            await using (var m = Nuevo(new[] { limpia }, futuro))
            {
                m.CargarEstado();
                Check(m.CalcularEspera() <= dia, "con un registro «del futuro» (reloj atrasado) nunca se espera mas de un intervalo", m.CalcularEspera().ToString());
            }

            // --- Detecciones: cuentan como completo, se ven y se pueden llevar a cuarentena ---
            string estadoDet = Path.Combine(datos, "estado", "det.json");
            await using (var m = Nuevo(new[] { limpia, sucia }, estadoDet))
            {
                await m.EjecutarUnaVezAsync(CancellationToken.None).ConfigureAwait(false);
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("ultimo_resultado").GetString() == "con_detecciones" && e.GetProperty("detecciones").GetInt32() == 1,
                      "con un archivo malicioso el resultado es «con_detecciones» (nunca «limpio»)", e.ToString());
                JsonElement d = J(await m.ManejarAsync("escaneo-programado.detecciones", null, CancellationToken.None).ConfigureAwait(false));
                Check(d.GetProperty("id_escaneo").GetString() == "programado" && d.GetProperty("detecciones").GetArrayLength() == 1
                      && d.GetProperty("detecciones")[0].GetProperty("ruta").GetString()!.EndsWith("malo.exe", StringComparison.Ordinal),
                      "la deteccion se lista con su ruta y el id con que la cuarentena la encuentra");
                Check(m.Obtener("programado") is { } r && r.Detecciones.Count == 1 && m.Obtener("otro") is null && m.Obtener("tiempo-real") is null,
                      "la cuarentena solo recibe el resultado con ESE id");
                Check(File.Exists(Path.Combine(sucia, "malo.exe")), "detectar NO borra ni mueve nada");
            }

            // --- Motor caido: fallido, NO cuenta como hecho, se reintenta pronto ---
            string estadoFallo = Path.Combine(datos, "estado", "fallo.json");
            await using (var m = Nuevo(new[] { limpia }, estadoFallo))
            {
                Motor.Disponible = false;
                await m.EjecutarUnaVezAsync(CancellationToken.None).ConfigureAwait(false);
                Motor.Disponible = true;
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("ultimo_resultado").GetString() == "fallido" && e.GetProperty("vencido").GetBoolean() && e.GetProperty("motivo").GetString()!.Contains("motor"),
                      "con el motor caido el resultado es «fallido» y sigue «vencido» (no «limpio»)", e.ToString());
                Check(e.GetProperty("ultimo_completo").ValueKind == JsonValueKind.Null && !File.Exists(estadoFallo),
                      "un escaneo fallido NO se guarda como hecho");
                Check(m.CalcularEspera() == reintento, "y se reintenta a la hora, no a las 24 h", m.CalcularEspera().ToString());
            }

            // --- Carpeta que no existe: incompleto, no cuenta como revisada ---
            string estadoInc = Path.Combine(datos, "estado", "inc.json");
            await using (var m = Nuevo(new[] { limpia, Path.Combine(datos, "no-existe") }, estadoInc))
            {
                int completos = 0;
                m.EscaneoCompleto += (_, _, _) => completos++;
                await m.EjecutarUnaVezAsync(CancellationToken.None).ConfigureAwait(false);
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("ultimo_resultado").GetString() == "incompleto" && e.GetProperty("vencido").GetBoolean(),
                      "si una carpeta no se pudo leer el resultado es «incompleto» y sigue vencido", e.ToString());
                Check(!File.Exists(estadoInc) && completos == 0, "un escaneo incompleto no se guarda como hecho ni da por revisado nada");
                Check(m.CalcularEspera() == reintento, "y se reintenta pronto");
            }

            // --- Registro ilegible: se dice, no se oculta ---
            string roto = Path.Combine(datos, "estado", "roto.json");
            File.WriteAllText(roto, "{ esto no es json");
            await using (var m = Nuevo(new[] { limpia }, roto))
            {
                m.CargarEstado();
                JsonElement e = await EstadoProgramado(m).ConfigureAwait(false);
                Check(e.GetProperty("aviso").ValueKind == JsonValueKind.String && e.GetProperty("ultimo_resultado").GetString() == "nunca" && m.CalcularEspera() == inicial,
                      "un registro corrupto se trata como «nunca» y se avisa", e.ToString());
            }

            // --- El bucle de verdad: espera la espera inicial y luego escanea solo ---
            var esperas = new List<TimeSpan>();
            string estadoBucle = Path.Combine(datos, "estado", "bucle.json");
            await using (var m = new ModuloEscaneoProgramado(Motor, reportes, new[] { limpia }, dia, estadoBucle, reintento: reintento,
                                                             esperaInicial: inicial, reloj: reloj,
                                                             esperar: async (t, ct) =>
                                                             {
                                                                 int n; lock (esperas) { esperas.Add(t); n = esperas.Count; }
                                                                 if (n > 1) await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
                                                             }))
            {
                m.Iniciar();
                JsonElement e = default;
                for (int i = 0; i < 100; i++)
                {
                    e = await EstadoProgramado(m).ConfigureAwait(false);
                    if (e.GetProperty("ultimo_resultado").GetString() == "limpio") break;
                    await Task.Delay(50).ConfigureAwait(false);
                }
                Check(e.GetProperty("ultimo_resultado").GetString() == "limpio", "el servicio escanea por su cuenta, sin que nadie lo pida", e.ToString());
                for (int i = 0; i < 100; i++) { lock (esperas) if (esperas.Count >= 2) break; await Task.Delay(20).ConfigureAwait(false); }
                bool dosEsperas; TimeSpan p, s;
                lock (esperas) { dosEsperas = esperas.Count >= 2; p = esperas.ElementAtOrDefault(0); s = esperas.ElementAtOrDefault(1); }
                Check(dosEsperas && p == inicial, "la primera espera es la inicial");
                Check(dosEsperas && s == dia, "y despues de uno completo espera un intervalo");
            }

            // --- Carpetas que el servicio no aceptaria ---
            IReadOnlyList<string> validas = ModuloEscaneoProgramado.Validar(new[]
            {
                @"C:\datos\ok", @"\\servidor\recurso", "relativa\\ruta", @"C:\a\..\b", @"C:\*", ""
            }, out IReadOnlyList<string> rechazadas);
            Check(validas.Count == 1 && rechazadas.Count == 5,
                  "se rechazan rutas de red, relativas, con «..», con comodines y vacias (mismas reglas que el pipe)",
                  "validas=" + validas.Count + " rechazadas=" + rechazadas.Count);

            // --- Nada que cambie la configuracion por el pipe ---
            await using (var m = Nuevo(new[] { limpia }))
            {
                Check(m.Metodos.SequenceEqual(new[] { "escaneo-programado.estado", "escaneo-programado.detecciones" }),
                      "el pipe solo ofrece leer: no hay metodos para activarlo, apagarlo ni cambiar carpetas o intervalo");
                bool rechazo = false;
                try { await m.ManejarAsync("escaneo-programado.configurar", null, CancellationToken.None).ConfigureAwait(false); }
                catch (ErrorDeComando) { rechazo = true; }
                Check(rechazo, "un metodo que cambie la configuracion se rechaza");
            }

            // --- Apagado: lo dice claramente ---
            var apagado = new ModuloEscaneoProgramadoApagado();
            JsonElement ea = J(await apagado.ManejarAsync("escaneo-programado.estado", null, CancellationToken.None).ConfigureAwait(false));
            Check(!ea.GetProperty("activo").GetBoolean() && ea.GetProperty("vencido").GetBoolean(), "apagado, el estado dice «no activo» y «vencido» (no «al dia»)");
            Console.WriteLine();
        }
    }
}
