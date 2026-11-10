using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Identity.Autocompletado
{
    /// <summary>
    /// El camino de un mensaje: extensión → navegador → host nativo (<c>nexo-autocompletar.exe</c>, lo lanza el navegador) → pipe → ventana de
    /// Nexo (donde vive la bóveda abierta y el <see cref="PuenteDeAutocompletado"/>) → y vuelta. El host no sabe nada de contraseñas: reenvía.
    ///
    /// El pipe se abre con <see cref="PipeOptions.CurrentUserOnly"/> en los dos lados: el servidor solo deja entrar a tu usuario, y el cliente
    /// comprueba que el servidor también es tuyo (si otro usuario de la máquina hubiera creado el pipe antes, el host se niega a hablarle).
    /// Un programa que corre con TU usuario sí puede conectarse directamente: para eso está el emparejamiento con clave (ver el puente).
    /// </summary>
    public static class CanalDeAutocompletado
    {
        /// <summary>El nombre del pipe para un usuario. Lleva una huella del usuario para que dos sesiones de la misma máquina no choquen.</summary>
        public static string NombreDePipe(string usuario)
        {
            string h = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(usuario.Trim().ToLowerInvariant()))).ToLowerInvariant();
            return "nexo-autocompletado-" + h[..16];
        }

        /// <summary>El de quien ejecuta este proceso (la ventana y el host corren con el mismo usuario).</summary>
        public static string NombreDePipeActual() => NombreDePipe(Environment.UserDomainName + "\\" + Environment.UserName);

        internal static byte[] Respuesta(string estado, string motivo)
            => JsonSerializer.SerializeToUtf8Bytes(new { estado, motivo },
                new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>
    /// El lado de la ventana: atiende las conexiones del host y pasa cada mensaje a <c>atender</c> (normalmente
    /// <see cref="PuenteDeAutocompletado.AtenderAsync"/>). Pocas conexiones a la vez, cierra a quien no habla, y cada petición tiene un tope
    /// (largo, porque emparejar espera a que la persona conteste en Nexo).
    /// </summary>
    public sealed class ServidorDeAutocompletado : IAsyncDisposable
    {
        public const int MaxConexiones = 4;
        public static readonly TimeSpan InactivoPorOmision = TimeSpan.FromSeconds(30);
        public static readonly TimeSpan PorPeticionPorOmision = TimeSpan.FromMinutes(2);

        private readonly string _nombre;
        private readonly Func<byte[], CancellationToken, Task<byte[]>> _atender;
        private readonly TimeSpan _inactivo, _porPeticion;
        private readonly SemaphoreSlim _huecos = new SemaphoreSlim(MaxConexiones, MaxConexiones);
        private readonly CancellationTokenSource _parar = new CancellationTokenSource();
        private readonly List<Task> _conexiones = new List<Task>();
        private Task? _aceptador;
        private Exception? _fallo;
        private int _atendidas;

        public ServidorDeAutocompletado(string nombrePipe, Func<byte[], CancellationToken, Task<byte[]>> atender,
                                        TimeSpan? porPeticion = null, TimeSpan? inactivo = null)
        {
            if (string.IsNullOrWhiteSpace(nombrePipe) || nombrePipe.IndexOfAny(new[] { '\\', '/' }) >= 0)
                throw new ArgumentException("nombre de pipe no válido", nameof(nombrePipe));
            _nombre = nombrePipe;
            _atender = atender;
            _porPeticion = porPeticion ?? PorPeticionPorOmision;
            _inactivo = inactivo ?? InactivoPorOmision;
        }

        /// <summary>No nulo si dejó de aceptar conexiones por un error: la ventana debe decir que el autocompletado no funciona.</summary>
        public Exception? FalloDelAceptador => Volatile.Read(ref _fallo);
        public int Atendidas => Volatile.Read(ref _atendidas);

        /// <summary>Crea la primera instancia antes de volver: si falla (p. ej. el nombre ya lo tiene otro usuario), lanza aquí y no en segundo plano.</summary>
        public void Iniciar()
        {
            if (_aceptador is not null) throw new InvalidOperationException("ya iniciado");
            NamedPipeServerStream primera = Crear();
            _aceptador = Task.Run(() => AceptarAsync(primera));
        }

        private NamedPipeServerStream Crear()
            => new NamedPipeServerStream(_nombre, PipeDirection.InOut, MaxConexiones + 1, PipeTransmissionMode.Byte,
                                         PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

        private async Task AceptarAsync(NamedPipeServerStream actual)
        {
            CancellationToken ct = _parar.Token;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await actual.WaitForConnectionAsync(ct).ConfigureAwait(false);
                    NamedPipeServerStream conectado = actual;
                    await _huecos.WaitAsync(ct).ConfigureAwait(false);
                    actual = Crear();
                    Task t = Task.Run(() => AtenderAsync(conectado, ct));
                    lock (_conexiones)
                    {
                        _conexiones.RemoveAll(x => x.IsCompleted);
                        _conexiones.Add(t);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Volatile.Write(ref _fallo, ex); }
            finally { actual.Dispose(); }
        }

        private async Task AtenderAsync(NamedPipeServerStream pipe, CancellationToken parar)
        {
            try
            {
                await using (pipe.ConfigureAwait(false))
                {
                    while (!parar.IsCancellationRequested)
                    {
                        byte[]? peticion;
                        using (var inactivo = CancellationTokenSource.CreateLinkedTokenSource(parar))
                        {
                            inactivo.CancelAfter(_inactivo);
                            peticion = await MensajeNativo.LeerAsync(pipe, inactivo.Token).ConfigureAwait(false);
                        }
                        if (peticion is null) return;

                        byte[] respuesta;
                        using (var limite = CancellationTokenSource.CreateLinkedTokenSource(parar))
                        {
                            limite.CancelAfter(_porPeticion);
                            try { respuesta = await _atender(peticion, limite.Token).ConfigureAwait(false); }
                            catch (OperationCanceledException) when (!parar.IsCancellationRequested)
                            {
                                respuesta = CanalDeAutocompletado.Respuesta("error", "Nexo no contestó a tiempo");
                            }
                        }
                        if (respuesta.Length == 0 || respuesta.Length > MensajeNativo.MaxSalida)
                            respuesta = CanalDeAutocompletado.Respuesta("error", "respuesta no válida");
                        Interlocked.Increment(ref _atendidas);
                        await MensajeNativo.EscribirAsync(pipe, respuesta, parar).ConfigureAwait(false);
                    }
                }
            }
            catch (InvalidDataException) { /* trama ilegible: no se puede resincronizar, se cierra */ }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException) { }
            finally { _huecos.Release(); }
        }

        public async ValueTask DisposeAsync()
        {
            _parar.Cancel();
            if (_aceptador is not null) { try { await _aceptador.ConfigureAwait(false); } catch (Exception) { } }
            Task[] pendientes;
            lock (_conexiones) pendientes = _conexiones.ToArray();
            try { await Task.WhenAll(pendientes).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch (Exception) { }
            _parar.Dispose();
        }
    }

    /// <summary>
    /// El lado del host nativo: lee mensajes del navegador (stdin), los reenvía a la ventana y devuelve la respuesta (stdout). Si la ventana no
    /// está abierta, contesta él mismo «sin_nexo». Nunca escribe en stdout nada que no sea un mensaje (el navegador cortaría la conexión).
    /// </summary>
    public sealed class RelevoNativo
    {
        public static readonly TimeSpan ConectarPorOmision = TimeSpan.FromSeconds(2);
        /// <summary>Algo más que el tope del servidor, para que sea el servidor quien diga «no contestó a tiempo».</summary>
        public static readonly TimeSpan RespuestaPorOmision = ServidorDeAutocompletado.PorPeticionPorOmision + TimeSpan.FromSeconds(10);

        private readonly string _nombre;
        private readonly TimeSpan _conectar, _respuesta;

        public RelevoNativo(string nombrePipe, TimeSpan? conectar = null, TimeSpan? respuesta = null)
        {
            _nombre = nombrePipe;
            _conectar = conectar ?? ConectarPorOmision;
            _respuesta = respuesta ?? RespuestaPorOmision;
        }

        /// <returns>0 si el navegador cerró limpiamente; 2 si mandó una trama no válida (se deja de leer: no hay forma de resincronizar).</returns>
        public async Task<int> EjecutarAsync(Stream entrada, Stream salida, CancellationToken ct = default)
        {
            while (true)
            {
                byte[]? m;
                try { m = await MensajeNativo.LeerAsync(entrada, ct).ConfigureAwait(false); }
                catch (InvalidDataException) { return 2; }
                if (m is null) return 0;
                byte[] r = await ReenviarAsync(m, ct).ConfigureAwait(false);
                await MensajeNativo.EscribirAsync(salida, r, ct).ConfigureAwait(false);
            }
        }

        /// <summary>Un mensaje de ida y vuelta. Nunca lanza salvo por cancelación: cualquier fallo es una respuesta JSON con «estado».</summary>
        public async Task<byte[]> ReenviarAsync(byte[] mensaje, CancellationToken ct = default)
        {
            using var cliente = new NamedPipeClientStream(".", _nombre, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            try { await cliente.ConnectAsync((int)_conectar.TotalMilliseconds, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is TimeoutException or IOException)
            {
                return CanalDeAutocompletado.Respuesta("sin_nexo", "Nexo no está abierto: ábrelo y desbloquea la bóveda");
            }
            catch (UnauthorizedAccessException)
            {
                // CurrentUserOnly: el pipe existe pero es de otro usuario. No se le manda nada.
                return CanalDeAutocompletado.Respuesta("error", "el canal de Nexo no pertenece a tu usuario: no se usa");
            }

            try
            {
                using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limite.CancelAfter(_respuesta);
                await MensajeNativo.EscribirAsync(cliente, mensaje, limite.Token).ConfigureAwait(false);
                byte[]? r = await MensajeNativo.LeerAsync(cliente, MensajeNativo.MaxSalida, limite.Token).ConfigureAwait(false);
                if (r is null) return CanalDeAutocompletado.Respuesta("error", "Nexo cerró la conexión sin contestar");
                if (!EsObjetoJson(r)) return CanalDeAutocompletado.Respuesta("error", "Nexo contestó algo que no se entiende");
                return r;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return CanalDeAutocompletado.Respuesta("error", "Nexo no contestó a tiempo");
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentOutOfRangeException)
            {
                return CanalDeAutocompletado.Respuesta("error", "falló la comunicación con Nexo");
            }
        }

        private static bool EsObjetoJson(byte[] b)
        {
            try
            {
                using JsonDocument d = JsonDocument.Parse(b);
                return d.RootElement.ValueKind == JsonValueKind.Object;
            }
            catch (JsonException) { return false; }
        }
    }
}
