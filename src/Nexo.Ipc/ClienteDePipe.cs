using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ipc
{
    /// <summary>Cliente del pipe del servicio. Una conexion, peticiones en serie.</summary>
    public sealed class ClienteDePipe : IAsyncDisposable
    {
        private readonly NamedPipeClientStream _pipe;
        private int _siguiente;

        /// <summary>
        /// Si es true (por omision false, para no romper las pruebas que levantan el servicio en su propio proceso), cada
        /// conexion comprueba que el proceso que atiende el pipe corre desde una carpeta de confianza
        /// (<see cref="VerificacionDeServidor"/>) ANTES de mandarle nada. La bandeja y la ventana lo activan cuando usan el pipe
        /// por omision: asi un proceso del usuario que haya creado el pipe antes que el servicio no recibe ni la identidad ni
        /// las peticiones.
        /// </summary>
        public static bool ExigirServidorDeConfianza { get; set; }

        /// <summary>Carpetas donde se acepta el ejecutable del servidor. null = Archivos de programa.</summary>
        public static IReadOnlyList<string>? CarpetasDeConfianza { get; set; }

        private ClienteDePipe(NamedPipeClientStream pipe) => _pipe = pipe;

        /// <param name="nivel">
        /// Que puede hacer el servidor con la identidad de este cliente. Por omision Impersonation: el
        /// servicio actua CON TUS permisos al leer, mover o restaurar archivos (si no, lo haria como SYSTEM
        /// y tu obtendrias permisos que no tienes). Es seguro SOLO si el otro lado es el servicio: la ACL del pipe no impide que
        /// otro proceso lo cree antes (ver <see cref="ExigirServidorDeConfianza"/>); con Identification esas operaciones se rechazan.
        /// </param>
        /// <exception cref="TimeoutException">El servicio no esta escuchando.</exception>
        public static async Task<ClienteDePipe> ConectarAsync(string nombre, TimeSpan espera, CancellationToken ct = default,
            TokenImpersonationLevel nivel = TokenImpersonationLevel.Impersonation)
        {
            var pipe = new NamedPipeClientStream(".", nombre, PipeDirection.InOut, PipeOptions.Asynchronous, nivel);
            try
            {
                await pipe.ConnectAsync((int)espera.TotalMilliseconds, ct).ConfigureAwait(false);
                if (ExigirServidorDeConfianza)
                {
                    string? motivo = VerificacionDeServidor.Comprobar(pipe, CarpetasDeConfianza);
                    if (motivo is not null)
                        throw new IOException("El servidor del pipe no es de confianza: " + motivo + ". No se envia nada.");
                }
                return new ClienteDePipe(pipe);
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async Task<Respuesta> LlamarAsync(string metodo, object? parametros = null, CancellationToken ct = default)
        {
            var s = new Solicitud
            {
                Id = (++_siguiente).ToString(CultureInfo.InvariantCulture),
                Metodo = metodo,
                Parametros = parametros is null ? null : JsonSerializer.SerializeToElement(parametros)
            };
            return await EnviarAsync(JsonSerializer.SerializeToUtf8Bytes(s), ct).ConfigureAwait(false);
        }

        /// <summary>Manda un cuerpo ya serializado (las pruebas lo usan para enviar JSON roto).</summary>
        public async Task<Respuesta> EnviarAsync(byte[] cuerpo, CancellationToken ct = default)
        {
            await Tramas.EscribirAsync(_pipe, cuerpo, ct).ConfigureAwait(false);
            byte[]? r = await Tramas.LeerAsync(_pipe, ct).ConfigureAwait(false);
            if (r is null) throw new IOException("El servicio cerro la conexion.");
            return JsonSerializer.Deserialize<Respuesta>(Tramas.Texto(r))
                   ?? throw new IOException("Respuesta vacia del servicio.");
        }

        /// <summary>Flujo en bruto, para las pruebas de protocolo.</summary>
        public Stream Flujo => _pipe;

        public ValueTask DisposeAsync() => _pipe.DisposeAsync();
    }
}
