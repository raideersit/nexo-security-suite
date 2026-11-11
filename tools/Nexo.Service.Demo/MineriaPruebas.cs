using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Criptojacking;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static MuestraDeMineria MuestraM(double cpu, bool procesosLeidos = true, bool conexionesLeidas = true, IReadOnlyList<ConexionDeProceso>? con = null)
            => new(DateTimeOffset.Now,
                   procesosLeidos ? new[] { new ProcesoMuestreado(100, "minero", @"C:\Users\x\AppData\Local\Temp\m.exe", cpu, false) } : Array.Empty<ProcesoMuestreado>(),
                   procesosLeidos, con ?? Array.Empty<ConexionDeProceso>(), conexionesLeidas,
                   procesosLeidos ? null : "sin permiso", conexionesLeidas ? null : "tabla ilegible");

        public static async Task ProbarMineriaDelServicio()
        {
            Console.WriteLine("Anti-criptojacking del servicio (§2aw): estado, rachas, no evaluado y fallos");
            Func<MuestraDeMineria> tomar = () => MuestraM(2);

            // Intervalo mínimo y estado inicial: nada observado todavía NO es «sin sospechas».
            var m = new ModuloMineria(() => tomar(), intervalo: TimeSpan.FromMilliseconds(10));
            Check(m.Intervalo == ModuloMineria.IntervaloMinimo, "un intervalo menor que el mínimo se sube a 2 s");
            var listaConIp = new ListaDePools(new[] { "203.0.113.9" }, Array.Empty<string>());
            m.PrepararParaPruebas(listaConIp);
            var e0 = (await PedirSenuelos(m, "mineria.estado", null)).R!.Value;
            Check(e0.GetProperty("activo").GetBoolean() && e0.GetProperty("muestras").GetInt32() == 0 && e0.GetProperty("observando").GetBoolean() && !e0.GetProperty("sin_sospechas").GetBoolean(),
                  "sin muestras: observando y NO «sin sospechas»");

            // Pocas muestras limpias: sigue observando (todavía no se pudo ver una racha).
            for (int i = 0; i < VigilanteDeMineria.MuestrasSostenidas - 1; i++) await m.UnaVueltaAsync(CancellationToken.None);
            var e1 = (await PedirSenuelos(m, "mineria.estado", null)).R!.Value;
            Check(e1.GetProperty("muestras").GetInt32() == 7 && e1.GetProperty("observando").GetBoolean() && !e1.GetProperty("sin_sospechas").GetBoolean(), "con 7 de 8 muestras limpias aún no se dice «sin sospechas»");
            await m.UnaVueltaAsync(CancellationToken.None);
            var e2 = (await PedirSenuelos(m, "mineria.estado", null)).R!.Value;
            Check(!e2.GetProperty("observando").GetBoolean() && e2.GetProperty("sin_sospechas").GetBoolean() && e2.GetProperty("completo").GetBoolean() && e2.GetProperty("hallazgos").GetArrayLength() == 0,
                  "con 8 muestras limpias y completas: «sin sospechas»");

            // Racha de CPU alta en segundo plano: aparece un hallazgo y se acaba «sin sospechas».
            tomar = () => MuestraM(90);
            for (int i = 0; i < VigilanteDeMineria.MuestrasSostenidas; i++) await m.UnaVueltaAsync(CancellationToken.None);
            var e3 = (await PedirSenuelos(m, "mineria.estado", null)).R!.Value;
            Check(e3.GetProperty("hallazgos").GetArrayLength() == 1 && !e3.GetProperty("sin_sospechas").GetBoolean() && e3.GetProperty("severidad_maxima").GetString() == "Media",
                  "8 muestras al 90 % de CPU (en Temp): un hallazgo y NO «sin sospechas»", e3.GetRawText());
            var h = e3.GetProperty("hallazgos")[0];
            Check(h.GetProperty("recomendacion").GetString()!.Length > 0 && h.GetProperty("detalle").GetString()!.Length > 0, "el hallazgo trae detalle y recomendación");

            // Sin lista de servidores el núcleo dice «no evaluado»: nunca «sin sospechas» (solo mira CPU y puertos).
            var mv = new ModuloMineria(() => MuestraM(2));
            mv.PrepararParaPruebas(ListaDePools.Vacia);
            for (int i = 0; i < 9; i++) await mv.UnaVueltaAsync(CancellationToken.None);
            var ev = (await PedirSenuelos(mv, "mineria.estado", null)).R!.Value;
            Check(!ev.GetProperty("sin_sospechas").GetBoolean() && !ev.GetProperty("completo").GetBoolean()
                  && ev.GetProperty("no_evaluado").EnumerateArray().Any(x => x.GetString()!.Contains("lista")), "sin lista de servidores: «no evaluado» (solo CPU y puertos), nunca «sin sospechas»", ev.GetRawText());

            // Lo que no se pudo leer es «no evaluado», nunca «sin sospechas».
            var m2 = new ModuloMineria(() => MuestraM(2, procesosLeidos: false));
            m2.PrepararParaPruebas(ListaDePools.Vacia);
            for (int i = 0; i < 9; i++) await m2.UnaVueltaAsync(CancellationToken.None);
            var e4 = (await PedirSenuelos(m2, "mineria.estado", null)).R!.Value;
            Check(!e4.GetProperty("completo").GetBoolean() && !e4.GetProperty("sin_sospechas").GetBoolean() && e4.GetProperty("no_evaluado").GetArrayLength() >= 1,
                  "procesos ilegibles: «no evaluado» y NO «sin sospechas»", e4.GetRawText());

            // Pool conocido + CPU sostenida = crítica.
            var pool = new ListaDePools(new[] { "203.0.113.9" }, Array.Empty<string>());
            var m3 = new ModuloMineria(() => MuestraM(90, con: new[] { new ConexionDeProceso(100, "203.0.113.9", 443) }));
            m3.PrepararParaPruebas(pool);
            for (int i = 0; i < VigilanteDeMineria.MuestrasSostenidas; i++) await m3.UnaVueltaAsync(CancellationToken.None);
            var e5 = (await PedirSenuelos(m3, "mineria.estado", null)).R!.Value;
            Check(e5.GetProperty("severidad_maxima").GetString() == "Critica" && e5.GetProperty("lista_ips").GetInt32() == 1, "CPU sostenida + conexión a un pool de la lista: crítica", e5.GetRawText());

            // Un fallo al muestrear no tumba el módulo y se dice; la siguiente muestra buena lo borra.
            bool romper = true;
            var m4 = new ModuloMineria(() => romper ? throw new InvalidOperationException("roto") : MuestraM(2));
            m4.PrepararParaPruebas(ListaDePools.Vacia);
            await m4.UnaVueltaAsync(CancellationToken.None);
            var e6 = (await PedirSenuelos(m4, "mineria.estado", null)).R!.Value;
            Check(e6.GetProperty("aviso").GetString()!.Contains("falló") && !e6.GetProperty("sin_sospechas").GetBoolean() && e6.GetProperty("muestras").GetInt32() == 0, "una muestra que falla se avisa y no cuenta");
            romper = false;
            await m4.UnaVueltaAsync(CancellationToken.None);
            // Con 8 buenas (y lista con IP) y una fallida al final: ya no se dice «sin sospechas».
            var m6 = new ModuloMineria(() => romper ? throw new InvalidOperationException("roto") : MuestraM(2));
            m6.PrepararParaPruebas(listaConIp);
            for (int i = 0; i < 8; i++) await m6.UnaVueltaAsync(CancellationToken.None);
            bool antes = (await PedirSenuelos(m6, "mineria.estado", null)).R!.Value.GetProperty("sin_sospechas").GetBoolean();
            romper = true;
            await m6.UnaVueltaAsync(CancellationToken.None);
            bool despues = (await PedirSenuelos(m6, "mineria.estado", null)).R!.Value.GetProperty("sin_sospechas").GetBoolean();
            Check(antes && !despues, "8 muestras buenas dan «sin sospechas», pero una muestra fallida después lo quita");
            romper = false;
            var e7 = (await PedirSenuelos(m4, "mineria.estado", null)).R!.Value;
            Check(e7.GetProperty("aviso").ValueKind == JsonValueKind.Null && e7.GetProperty("muestras").GetInt32() == 1, "la siguiente muestra buena borra el aviso");

            // Bucle real: la lista que falla al cargar NO impide vigilar, y se avisa.
            int vueltas = 0;
            var m5 = new ModuloMineria(() => { Interlocked.Increment(ref vueltas); return MuestraM(2); },
                                       _ => throw new System.IO.IOException("sin lista"), esperar: async (t, ct) => await Task.Delay(5, ct));
            m5.Iniciar();
            for (int i = 0; i < 200 && Volatile.Read(ref vueltas) < 3; i++) await Task.Delay(10);
            var e8 = (await PedirSenuelos(m5, "mineria.estado", null)).R!.Value;
            await m5.DisposeAsync();
            Check(vueltas >= 3 && e8.GetProperty("aviso").GetString()!.Contains("no se pudo cargar"), "si la lista no carga se sigue vigilando y se avisa", e8.GetRawText());

            // Contrato: el JSON REAL del servicio lo lee la ventana igual que el servicio lo dice.
            static Nexo.Ui.Desktop.Nucleo.RespuestaCruda Cruda(JsonElement e) => new(true, null, e);
            var lc = Nexo.Ui.Desktop.Nucleo.LectorDeMineriaDelServicio.Leer(Cruda(e3));
            Check(lc.Valor is { Muestras: 16 } && lc.Valor.Analisis.Hallazgos.Count == 1 && lc.Valor.Analisis.Hallazgos[0].Severidad == Nexo.Reports.Model.Severidad.Media && lc.Valor.Analisis.Completo,
                  "la ventana lee el estado real con un hallazgo (y, con lista y 16 muestras, como completo)", lc.Error ?? e3.GetRawText());
            var lc2 = Nexo.Ui.Desktop.Nucleo.LectorDeMineriaDelServicio.Leer(Cruda(e5));
            Check(lc2.Valor is { } v2 && v2.Analisis.Hallazgos.Single().Severidad == Nexo.Reports.Model.Severidad.Critica, "la ventana lee el hallazgo crítico real", lc2.Error);
            var lc3 = Nexo.Ui.Desktop.Nucleo.LectorDeMineriaDelServicio.Leer(Cruda(e0));
            Check(lc3.Valor is { Muestras: 0 } v3 && v3.Analisis.NoEvaluado.Any(x => x.Contains("ninguna muestra")), "sin muestras: la ventana lo lee como «no evaluado»", lc3.Error);
            var ap0 = Nexo.Ui.Desktop.Nucleo.LectorDeMineriaDelServicio.Leer(Cruda((await PedirSenuelos(new ModuloMineriaApagado(), "mineria.estado", null)).R!.Value));
            Check(ap0.Valor is { Nota: not null } && ap0.Valor.Nota.Contains("Nexo:Mineria:Activo"), "apagado: la ventana lo lee como apagado, con la nota");

            // Método desconocido y apagado.
            Check(!(await PedirSenuelos(m, "mineria.detener", null)).Ok, "no existe ningún método para detener o cambiar nada por el pipe");
            var ap = new ModuloMineriaApagado();
            var ea = await PedirSenuelos(ap, "mineria.estado", null);
            Check(ea.Ok && !ea.R!.Value.GetProperty("activo").GetBoolean() && ea.R.Value.GetProperty("nota").GetString()!.Contains("Nexo:Mineria:Activo"), "apagado: lo dice y dice dónde activarlo");
        }
    }
}
