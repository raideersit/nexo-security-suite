using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Amsi;

namespace Nexo.Amsi.Windows.Demo
{
    /// <summary>
    /// AMSI real. Nada se escribe a disco: la cadena de prueba oficial de AMSI se arma en memoria (escribirla en un archivo
    /// haria que Defender lo bloquee, como paso con un archivo de codigo fuente durante el desarrollo).
    /// </summary>
    internal static class Program
    {
        private static int _fallos;

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            Console.WriteLine("1. Contexto de AMSI (capa nativa)");
            ContextoAmsi? ctx = ContextoAmsi.Abrir("NexoPrueba", out string? motivo);
            Check(ctx is not null, "AmsiInitialize abre un contexto", motivo);
            if (ctx is null) return Terminar();

            using (ctx)
            {
                byte[] prueba = Encoding.Unicode.GetBytes(MotorAmsi.CadenaDePrueba);
                RespuestaNativaAmsi r = ctx.Escanear(prueba, prueba.Length, "nexo-prueba");
                Check(r.Exito, "AmsiScanBuffer responde sin error", r.Motivo);
                Console.WriteLine("      INFO: codigo para la cadena de prueba oficial = " + r.Codigo + (r.Codigo >= MotorAmsi.CodigoDetectado ? " (detectado)" : " (NO detectado)"));
                Check(r.Exito && r.Codigo >= MotorAmsi.CodigoDetectado,
                      "el proveedor marca la cadena de prueba oficial (hay un proveedor activo)",
                      "Sin esto AMSI no sirve: Defender apagado o ausente. Nexo lo trataria como NO CONCLUYENTE.");

                byte[] limpio = Encoding.Unicode.GetBytes("Write-Host 'hola'");
                RespuestaNativaAmsi rl = ctx.Escanear(limpio, limpio.Length, "nexo-prueba");
                Check(rl.Exito && rl.Codigo < MotorAmsi.CodigoDetectado, "un script inofensivo no se marca", "codigo " + rl.Codigo + " " + rl.Motivo);

                RespuestaNativaAmsi ra = ctx.Escanear(new byte[0], 0, "vacio");
                Console.WriteLine("      INFO: un buffer vacio -> exito=" + ra.Exito + " codigo=" + ra.Codigo + " (Nexo no lo envia: lo da por limpio antes)");
            }

            Console.WriteLine("2. MotorAmsi sobre el AMSI real");
            using var backend = new BackendAmsiWindows();
            var motor = new MotorAmsi(backend);

            string version;
            try { version = await motor.VersionAsync().ConfigureAwait(false); Check(true, "la autocomprobacion pasa: " + version); }
            catch (MotorNoDisponibleException ex) { Check(false, "la autocomprobacion pasa", ex.Message); return Terminar(); }

            ResultadoDeMotor limpioR = await motor.AnalizarAsync(new MemoryStream(Encoding.Unicode.GetBytes("Get-Date"))).ConfigureAwait(false);
            Check(limpioR.Veredicto == VeredictoDeArchivo.Limpio, "un script inofensivo es Limpio", limpioR.Veredicto + " " + limpioR.Error);

            ResultadoDeMotor malo = await motor.AnalizarAsync(new MemoryStream(Encoding.Unicode.GetBytes(MotorAmsi.CadenaDePrueba))).ConfigureAwait(false);
            Check(malo.Veredicto == VeredictoDeArchivo.Infectado && malo.Firma == "AMSI.Detectado", "la cadena de prueba (solo en memoria) es Infectado", malo.Veredicto + " " + malo.Error);

            // Y tambien dentro de un contenido mas grande, como llegaria en un archivo real.
            string relleno = new string('x', 5000);
            ResultadoDeMotor dentro = await motor.AnalizarAsync(new MemoryStream(Encoding.Unicode.GetBytes(relleno + MotorAmsi.CadenaDePrueba + relleno))).ConfigureAwait(false);
            Console.WriteLine("      INFO: la cadena de prueba enterrada entre 10000 caracteres -> " + dentro.Veredicto);

            Console.WriteLine("3. Varios hilos a la vez (el contexto se comparte)");
            int[] resultados = new int[4];
            await Task.WhenAll(Enumerable.Range(0, 4).Select(h => Task.Run(async () =>
            {
                for (int i = 0; i < 25; i++)
                {
                    ResultadoDeMotor x = await motor.AnalizarAsync(new MemoryStream(Encoding.Unicode.GetBytes("Get-Date " + h + "-" + i))).ConfigureAwait(false);
                    if (x.Veredicto == VeredictoDeArchivo.Limpio) resultados[h]++;
                }
            }))).ConfigureAwait(false);
            Check(resultados.All(n => n == 25), "100 analisis desde 4 hilos: todos Limpio y sin errores", string.Join(",", resultados));

            Console.WriteLine("4. Combinado con un motor que siempre dice Limpio");
            var comb = new MotorCombinado(new Fijo(), motor);
            ResultadoDeMotor c = await comb.AnalizarAsync(new MemoryStream(Encoding.Unicode.GetBytes(MotorAmsi.CadenaDePrueba))).ConfigureAwait(false);
            Check(c.Veredicto == VeredictoDeArchivo.Infectado, "aunque el otro motor no vea nada, AMSI lo marca", c.Veredicto + " " + c.Error);
            Check(comb.Nombre == "Fijo+AMSI", "el nombre combinado es Fijo+AMSI", comb.Nombre);

            return Terminar();
        }

        private sealed class Fijo : IMotorDeFirmas
        {
            public string Nombre => "Fijo";
            public Task<string> VersionAsync(System.Threading.CancellationToken ct = default) => Task.FromResult("1");
            public Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, System.Threading.CancellationToken ct = default) => Task.FromResult(ResultadoDeMotor.Limpio());
        }

        private static int Terminar()
        {
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
    }
}
