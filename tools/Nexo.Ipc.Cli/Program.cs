using System;
using System.Text.Json;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ipc.Cli
{
    /// <summary>
    /// Cliente generico del pipe del servicio, para probar a mano (sustituye al rpc.exe suelto de la VM).
    ///   nexo-rpc &lt;pipe&gt; &lt;metodo&gt; [json]
    ///   nexo-rpc &lt;pipe&gt; flujo &lt;previsualizar&gt; &lt;aplicar&gt; [json]
    /// El json admite comillas simples en vez de dobles (mas comodo en PowerShell).
    /// El modo "flujo" llama al metodo de vista previa, toma el "token" de la respuesta y se lo pasa al
    /// metodo de aplicar en la MISMA conexion. Si aplicar exige UAC (-32040) lo imprime tal cual: el cliente
    /// no eleva nada; hay que lanzarlo desde una consola elevada.
    /// </summary>
    internal static class Program
    {
        private static readonly TimeSpan Espera = TimeSpan.FromSeconds(5);

        private static async Task<int> Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("uso: nexo-rpc <pipe> <metodo> [json]  |  nexo-rpc <pipe> flujo <previsualizar> <aplicar> [json]");
                return 64;
            }

            try
            {
                await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(args[0], Espera).ConfigureAwait(false);

                if (args[1] == "flujo")
                {
                    if (args.Length < 4) { Console.Error.WriteLine("flujo necesita <previsualizar> y <aplicar>"); return 64; }
                    object? parametros = Parsear(args.Length > 4 ? args[4] : null);

                    Respuesta prev = await c.LlamarAsync(args[2], parametros).ConfigureAwait(false);
                    Console.WriteLine("previsualizar -> " + Texto(prev));
                    if (!prev.Exito || prev.Resultado is not { } r || !r.TryGetProperty("token", out JsonElement t)) return prev.Exito ? 2 : 1;

                    Respuesta ap = await c.LlamarAsync(args[3], new { token = t.GetString() }).ConfigureAwait(false);
                    Console.WriteLine("aplicar -> " + Texto(ap));
                    return ap.Exito ? 0 : 1;
                }

                Respuesta resp = await c.LlamarAsync(args[1], Parsear(args.Length > 2 ? args[2] : null)).ConfigureAwait(false);
                Console.WriteLine(Texto(resp));
                return resp.Exito ? 0 : 1;
            }
            catch (TimeoutException)
            {
                Console.Error.WriteLine("El servicio no esta escuchando en el pipe '" + args[0] + "'.");
                return 3;
            }
        }

        private static object? Parsear(string? json) =>
            string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<JsonElement>(json.Replace('\'', '"'));

        private static string Texto(Respuesta r) =>
            r.Error is { } e ? "ERROR " + e.Codigo + " " + e.Mensaje : r.Resultado?.GetRawText() ?? "null";
    }
}
