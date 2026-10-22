using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static async Task ProbarIdentidadDelLlamador(string vault, string pipe, string raiz)
        {
            Console.WriteLine("9. El servicio no actua como SYSTEM por quien llama: falla cerrado");

            string qAnterior = _carpetaQ;
            _carpetaQ = Path.Combine(raiz, "cuarentena-id");

            string datos = Path.Combine(raiz, "escaneo-id");
            Directory.CreateDirectory(datos);
            string malo = Path.Combine(datos, "malo.exe");
            File.WriteAllBytes(malo, Marca.Concat(new byte[] { 8 }).ToArray());

            using IHost host = Crear(vault, pipe);
            await host.StartAsync().ConfigureAwait(false);

            // Un cliente que SOLO deja identificarlo: el servicio sabe quien es, pero no puede usar sus permisos.
            await using ClienteDePipe ident = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10), nivel: TokenImpersonationLevel.Identification).ConfigureAwait(false);
            // Uno que si deja actuar en su nombre (el cliente normal).
            await using ClienteDePipe normal = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            Respuesta noPuede = await ident.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
            Check(!noPuede.Exito && noPuede.Error!.Codigo == AccesoComoLlamador.SinIdentidad,
                  "escanear con un cliente que no deja suplantarlo se RECHAZA (no se escanea como SYSTEM)", noPuede.Error?.Mensaje);
            Check(noPuede.Error!.Mensaje.Contains("SYSTEM"), "y el error explica por que");

            // Lo que no toca archivos con permisos del llamador sigue funcionando con Identification.
            Check((await ident.LlamarAsync("ping").ConfigureAwait(false)).Exito
                  && (await ident.LlamarAsync("firewall.estado").ConfigureAwait(false)).Exito
                  && (await ident.LlamarAsync("cuarentena.listar").ConfigureAwait(false)).Exito
                  && (await ident.LlamarAsync("tiempo-real.estado").ConfigureAwait(false)).Exito,
                  "lo que no actua sobre archivos del usuario (ping, estado, listar) sigue funcionando");

            // Con suplantacion todo normal: se escanea, se previsualiza, y el TOKEN no se gasta si falla la identidad.
            Respuesta ini = await normal.LlamarAsync("escaneo.iniciar", new { rutas = new[] { datos } }).ConfigureAwait(false);
            string id = R(ini).GetProperty("id").GetString()!;
            JsonElementFix res = new JsonElementFix(await EsperarAsync(normal, id).ConfigureAwait(false));
            Check(res.Detecciones == 1, "con un cliente que deja suplantarlo, el escaneo funciona igual");

            Respuesta pv = await normal.LlamarAsync("cuarentena.previsualizar", new { escaneo = id }).ConfigureAwait(false);
            string token = R(pv).GetProperty("token").GetString()!;

            Respuesta aplicarIdent = await ident.LlamarAsync("cuarentena.aplicar", new { token }).ConfigureAwait(false);
            Check(!aplicarIdent.Exito && aplicarIdent.Error!.Codigo == AccesoComoLlamador.SinIdentidad && File.Exists(malo),
                  "poner en cuarentena con un cliente sin suplantacion se rechaza y el archivo NO se toca");

            Respuesta aplicarOk = await normal.LlamarAsync("cuarentena.aplicar", new { token }).ConfigureAwait(false);
            Check(aplicarOk.Exito && R(aplicarOk).GetProperty("movidos").GetArrayLength() == 1 && !File.Exists(malo),
                  "el rechazo por identidad NO gasto el token: el mismo token sirve despues con la identidad correcta");

            // Restaurar, igual
            string idQ = R(await normal.LlamarAsync("cuarentena.listar").ConfigureAwait(false)).GetProperty("elementos")[0].GetProperty("id").GetString()!;
            Respuesta prIdent = await ident.LlamarAsync("cuarentena.previsualizar-restauracion", new { id = idQ }).ConfigureAwait(false);
            Check(!prIdent.Exito && prIdent.Error!.Codigo == AccesoComoLlamador.SinIdentidad, "previsualizar una restauracion sin identidad utilizable se rechaza");

            string tokenR = R(await normal.LlamarAsync("cuarentena.previsualizar-restauracion", new { id = idQ }).ConfigureAwait(false)).GetProperty("token").GetString()!;
            Respuesta restIdent = await ident.LlamarAsync("cuarentena.restaurar", new { token = tokenR }).ConfigureAwait(false);
            Check(!restIdent.Exito && restIdent.Error!.Codigo == AccesoComoLlamador.SinIdentidad && !File.Exists(malo),
                  "restaurar sin identidad utilizable se rechaza y no escribe nada");
            Respuesta restOk = await normal.LlamarAsync("cuarentena.restaurar", new { token = tokenR }).ConfigureAwait(false);
            Check(restOk.Exito && R(restOk).GetProperty("exito").GetBoolean() && File.Exists(malo), "y con la identidad correcta restaura (el token seguia vigente)");

            _carpetaQ = qAnterior;
            await host.StopAsync().ConfigureAwait(false);
            Console.WriteLine();
        }

        private readonly struct JsonElementFix
        {
            private readonly System.Text.Json.JsonElement _e;
            public JsonElementFix(System.Text.Json.JsonElement e) => _e = e;
            public int Detecciones => _e.GetProperty("detecciones").GetArrayLength();
        }
    }
}
