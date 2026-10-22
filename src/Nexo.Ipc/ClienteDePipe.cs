using System;
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

        private ClienteDePipe(NamedPipeClientStream pipe) => _pipe = pipe;

        /// <param name="nivel">
        /// Que puede hacer el servidor con la identidad de este cliente. Por omision Impersonation: el
        /// servicio actua CON TUS permisos al leer, mover o restaurar archivos (si no, lo haria como SYSTEM
        /// y tu obtendrias permisos que no tienes). Es seguro porque solo SYSTEM y Administradores pueden
        /// crear el pipe (ver SeguridadDePipe); con Identification esas operaciones se rechazan.
        /// </param>
        /// <exception cref="TimeoutException">El servicio no esta escuchando.</exception>
        public static async Task<ClienteDePipe> ConectarAsync(string nombre, TimeSpan espera, CancellationToken ct = default,
            TokenImpersonationLevel nivel = TokenImpersonationLevel.Impersonation)
        {
            var pipe = new NamedPipeClientStream(".", nombre, PipeDirection.InOut, PipeOptions.Asynchronous, nivel);
            try
            {
                await pipe.ConnectAsync((int)espera.TotalMilliseconds, ct).ConfigureAwait(false);
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
