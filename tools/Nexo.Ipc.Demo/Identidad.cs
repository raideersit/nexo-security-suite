using System;
using System.Security.Principal;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Ipc.Demo
{
    internal static partial class Program
    {
        public static ContextoDeLlamada? CopiaGuardada;

        private static async Task ProbarIdentidad()
        {
            Console.WriteLine("6. Identidad del llamador (para no actuar como SYSTEM por el)");

            using WindowsIdentity yo = WindowsIdentity.GetCurrent();
            string miSid = yo.User!.Value;

            string nombre = NombreUnico();
            await using var servidor = new ServidorDePipe(nombre, new ManejadorDePrueba());
            servidor.Iniciar();

            // --- Cliente que deja suplantarlo ---
            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera).ConfigureAwait(false))
            {
                Respuesta r = await c.LlamarAsync("quien").ConfigureAwait(false);
                var q = r.Resultado!.Value;
                Check(q.GetProperty("hay_contexto").GetBoolean(), "el manejador recibe el contexto del llamador");
                Check(q.GetProperty("sid").GetString() == miSid, "con el SID de quien llamo");
                Check(q.GetProperty("nivel").GetString() == "Impersonation" && q.GetProperty("puede").GetBoolean(),
                      "y sabe que puede actuar en su nombre (nivel Impersonation)");
                Check(q.GetProperty("ejecutado_como").GetString() == yo.Name,
                      "Ejecutar corre la operacion con la identidad del llamador", q.GetProperty("ejecutado_como").GetString());

                // El contexto llega tambien en las peticiones siguientes de la misma conexion.
                Respuesta r2 = await c.LlamarAsync("quien").ConfigureAwait(false);
                Check(r2.Resultado!.Value.GetProperty("sid").GetString() == miSid, "y en las siguientes peticiones de la misma conexion");

                // Una copia que sobrevive a la peticion y a la conexion.
                Check((await c.LlamarAsync("guardar-copia").ConfigureAwait(false)).Resultado!.Value.GetProperty("guardada").GetBoolean(),
                      "se puede duplicar el contexto para un trabajo en segundo plano");
            }

            await Task.Delay(300).ConfigureAwait(false);   // la conexion ya cerro y el contexto original se libero
            Check(CopiaGuardada is not null && CopiaGuardada.PuedeActuarComoElLlamador
                  && CopiaGuardada.Ejecutar(() => WindowsIdentity.GetCurrent().Name) == yo.Name,
                  "la copia sigue sirviendo despues de cerrar la conexion (un escaneo largo no se queda sin identidad)");
            CopiaGuardada?.Dispose();

            // --- Cliente que SOLO deja identificarlo: se sabe quien es, pero no se puede actuar como el ---
            await using (ClienteDePipe c = await ClienteDePipe.ConectarAsync(nombre, Espera, nivel: TokenImpersonationLevel.Identification).ConfigureAwait(false))
            {
                var q = (await c.LlamarAsync("quien").ConfigureAwait(false)).Resultado!.Value;
                Check(q.GetProperty("sid").GetString() == miSid && q.GetProperty("nivel").GetString() == "Identification",
                      "con nivel Identification se sabe QUIEN es");
                Check(!q.GetProperty("puede").GetBoolean() && !q.TryGetProperty("ejecutado_como", out _)
                      && q.GetProperty("error").GetString() == "InvalidOperationException",
                      "pero NO se puede actuar como el: Ejecutar se niega (el servicio no lo sustituye por SYSTEM)");
            }

            Check(ContextoDeLlamada.Actual is null, "fuera de una peticion no hay contexto (no se arrastra entre peticiones)");

            Console.WriteLine();
        }
    }
}
