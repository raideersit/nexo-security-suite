using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static async Task<bool> EsperarDeteccionesAsync(ClienteDePipe c, int n)
        {
            for (int i = 0; i < 160; i++)
            {
                Respuesta r = await c.LlamarAsync("tiempo-real.detecciones").ConfigureAwait(false);
                if (r.Exito && R(r).GetProperty("detecciones").GetArrayLength() >= n) return true;
                await Task.Delay(50).ConfigureAwait(false);
            }
            return false;
        }

        private static async Task ProbarTiempoReal(string vault, string pipe, string raiz)
        {
            Console.WriteLine("7. Tiempo real por el pipe (solo lectura)");

            // Cuarentena propia: no se comparte con la prueba 6 (que cuenta sus entradas).
            string qAnterior = _carpetaQ;
            _carpetaQ = Path.Combine(raiz, "cuarentena-tr");

            // --- Apagado por omision ---
            string pipeOff = pipe + "-off";
            using (IHost off = Crear(Path.Combine(raiz, "vault-off"), pipeOff))
            {
                await off.StartAsync().ConfigureAwait(false);
                await using ClienteDePipe co = await ClienteDePipe.ConectarAsync(pipeOff, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                Respuesta e0 = await co.LlamarAsync("tiempo-real.estado").ConfigureAwait(false);
                Check(e0.Exito && !R(e0).GetProperty("activo").GetBoolean() && !R(e0).GetProperty("cobertura_completa").GetBoolean(),
                      "por omision el tiempo real esta APAGADO, y el servicio lo dice (no finge cobertura)");
                await off.StopAsync().ConfigureAwait(false);
            }

            // --- Encendido, con una fuente de cambios manual ---
            string carpeta = Path.Combine(raiz, "vigilada");
            Directory.CreateDirectory(carpeta);
            var fuente = new FuenteManualSvc();

            using IHost host = Crear(vault, pipe, fuente);
            await host.StartAsync().ConfigureAwait(false);
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            Respuesta e1 = await c.LlamarAsync("tiempo-real.estado").ConfigureAwait(false);
            Check(R(e1).GetProperty("activo").GetBoolean() && R(e1).GetProperty("cobertura_completa").GetBoolean(),
                  "encendido, con cobertura completa mientras no se pierda nada");
            Check(R(e1).GetProperty("nota").GetString()!.Contains("DESPUES"),
                  "y siempre advierte que detecta DESPUES de escribirse (no previene)");

            // No hay forma de apagarlo ni de reconfigurarlo por el pipe.
            foreach (string m in new[] { "tiempo-real.desactivar", "tiempo-real.detener", "tiempo-real.iniciar", "tiempo-real.configurar", "tiempo-real.excluir" })
            {
                Respuesta r = await c.LlamarAsync(m, new { raiz = @"C:\" }).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.MetodoDesconocido, "'" + m + "' no existe: la proteccion no se apaga por el pipe");
            }

            // --- Un archivo malo aparece ---
            string malo = Path.Combine(carpeta, "recien-descargado.exe");
            File.WriteAllBytes(malo, Marca.Concat(new byte[] { 3 }).ToArray());
            fuente.Emitir(malo);
            Check(await EsperarDeteccionesAsync(c, 1).ConfigureAwait(false), "un archivo malo que cambia se detecta solo");
            Check(File.Exists(malo), "y NO se toca: el tiempo real solo avisa");

            bool hayNota = false;
            for (int i = 0; i < 100 && !hayNota; i++)
            {
                string notas = LeerTodo(Notas(vault));
                hayNota = notas.Contains("amenaza-detectada") && notas.Contains("Prueba.IPC");
                if (!hayNota) await Task.Delay(50).ConfigureAwait(false);
            }
            Check(hayNota, "deja la nota de deteccion en el vault");

            // --- Se excluye a si mismo: la cuarentena y el vault no se analizan ---
            string dentroDeQ = Path.Combine(_carpetaQ, "x.exe");
            Directory.CreateDirectory(_carpetaQ);
            File.WriteAllBytes(dentroDeQ, Marca.ToArray());
            fuente.Emitir(dentroDeQ);
            fuente.Emitir(Path.Combine(vault, "nota.exe"));
            await Task.Delay(2200).ConfigureAwait(false);
            Check(R(await c.LlamarAsync("tiempo-real.detecciones").ConfigureAwait(false)).GetProperty("detecciones").GetArrayLength() == 1,
                  "no se analiza a si mismo: la carpeta de cuarentena y el vault quedan fuera (sin bucles)");

            // --- Cobertura honesta ---
            fuente.Perder("buffer desbordado");
            Respuesta e2 = await c.LlamarAsync("tiempo-real.estado").ConfigureAwait(false);
            string[] porRevisar = R(e2).GetProperty("por_revisar").EnumerateArray().Select(x => x.GetString()!).ToArray();
            Check(R(e2).GetProperty("desbordes_de_fuente").GetInt64() == 1 && R(e2).GetProperty("perdidos").GetInt64() == 0
                  && porRevisar.Length > 0 && !R(e2).GetProperty("cobertura_completa").GetBoolean(),
                  "si la fuente pierde eventos se cuenta el desborde (sin inventar archivos), las raices quedan por revisar y la cobertura no es completa");

            // Un escaneo bajo demanda COMPLETO de lo que esta por revisar devuelve la cobertura (hallazgo 2026-11-02).
            // La raiz vigilada tiene que EXISTIR: una carpeta inexistente el escaner la anota como «no leida» y, con razon, no se da por revisada.
            foreach (string p in porRevisar) Directory.CreateDirectory(p);
            Respuesta ini = await c.LlamarAsync("escaneo.iniciar", new { rutas = porRevisar }).ConfigureAwait(false);
            bool listo = false;
            for (int i = 0; ini.Exito && i < 200 && !listo; i++)
            {
                await Task.Delay(50).ConfigureAwait(false);
                Respuesta res = await c.LlamarAsync("escaneo.resultado", new { id = R(ini).GetProperty("id").GetString() }).ConfigureAwait(false);
                listo = res.Exito && R(res).GetProperty("listo").GetBoolean();
            }
            Respuesta e3 = await c.LlamarAsync("tiempo-real.estado").ConfigureAwait(false);
            Check(listo && R(e3).GetProperty("por_revisar").GetArrayLength() == 0 && R(e3).GetProperty("cobertura_completa").GetBoolean()
                  && R(e3).GetProperty("desbordes_de_fuente").GetInt64() == 1,
                  "tras escanear lo que estaba por revisar, la cobertura vuelve a ser completa (el contador historico se conserva)",
                  ini.Exito ? R(e3).ToString() : ini.Error!.Mensaje);

            // --- A cuarentena por el flujo de siempre, con el id 'tiempo-real' ---
            Respuesta pv = await c.LlamarAsync("cuarentena.previsualizar", new { escaneo = ModuloTiempoReal.IdDeEscaneo }).ConfigureAwait(false);
            Check(pv.Exito && R(pv).GetProperty("elementos").GetInt32() == 1, "las detecciones del tiempo real se pueden llevar a cuarentena (vista previa y token)");
            Check(File.Exists(malo), "previsualizar no mueve nada");

            Respuesta ajena = await c.LlamarAsync("cuarentena.previsualizar",
                new { escaneo = ModuloTiempoReal.IdDeEscaneo, rutas = new[] { dentroDeQ } }).ConfigureAwait(false);
            Check(!ajena.Exito, "y sigue sin poder pedirse un archivo que el vigilante no detecto");

            Respuesta ap = await c.LlamarAsync("cuarentena.aplicar", new { token = R(pv).GetProperty("token").GetString() }).ConfigureAwait(false);
            Check(ap.Exito && R(ap).GetProperty("movidos").GetArrayLength() == 1 && !File.Exists(malo), "aplicar retira el archivo detectado");

            var sw = System.Diagnostics.Stopwatch.StartNew();
            await host.StopAsync().ConfigureAwait(false);
            Check(sw.Elapsed < TimeSpan.FromSeconds(5), "al parar el servicio, el vigilante se cierra a tiempo", sw.Elapsed.TotalSeconds.ToString("0.0") + " s");

            _carpetaQ = qAnterior;
            Console.WriteLine();
        }
    }

    internal sealed class FuenteManualSvc : IFuenteDeCambios
    {
        private Action<CambioDeArchivo>? _cambio;
        private Action<string>? _perder;
        public void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder) { _cambio = alCambiar; _perder = alPerder; }
        public void Emitir(string ruta) => _cambio!(new CambioDeArchivo(ruta, MotivoDeCambio.Modificado));
        public void Perder(string motivo) => _perder!(motivo);
        public void Dispose() { }
    }
}
