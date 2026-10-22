using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ipc
{
    public sealed class OpcionesDeServidor
    {
        /// <summary>Conexiones atendidas a la vez. Una mas y se espera: no se abren instancias sin limite.</summary>
        public int MaxConexiones { get; init; } = 16;

        /// <summary>Un cliente que conecta y no manda nada ocupa un hueco; pasado esto se le cierra.</summary>
        public TimeSpan TiempoInactivo { get; init; } = TimeSpan.FromSeconds(30);

        /// <summary>Limite para que el manejador conteste una peticion.</summary>
        public TimeSpan TiempoPorPeticion { get; init; } = TimeSpan.FromSeconds(30);

        /// <summary>Plazo para cerrar todo al detener; el SCM mata el servicio a los 5 s (Salida 0, §3).</summary>
        public TimeSpan TiempoDeParada { get; init; } = TimeSpan.FromSeconds(3);

        /// <summary>ACL del pipe. Por omision, <see cref="SeguridadDePipe.Crear"/>.</summary>
        public Func<PipeSecurity>? Seguridad { get; init; }
    }

    /// <summary>
    /// Servidor del named pipe del servicio. No abre puertos TCP; el SO aplica la ACL.
    /// Nunca confia en lo que llega: tamano acotado, JSON validado, errores del
    /// manejador contenidos y sin detalles internos hacia el cliente.
    /// </summary>
    public sealed class ServidorDePipe : IAsyncDisposable
    {
        private static readonly JsonSerializerOptions Json = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private readonly string _nombre;
        private readonly IManejadorDeComandos _manejador;
        private readonly OpcionesDeServidor _opciones;
        private readonly SemaphoreSlim _huecos;
        private readonly CancellationTokenSource _parar = new CancellationTokenSource();
        private readonly List<Task> _conexiones = new List<Task>();
        private Task? _aceptador;
        private int _atendidas;
        private Exception? _falloDelAceptador;

        /// <summary>No nulo si el servidor dejo de aceptar conexiones por un error (p. ej. la ACL no se pudo aplicar).</summary>
        public Exception? FalloDelAceptador => Volatile.Read(ref _falloDelAceptador);

        public ServidorDePipe(string nombre, IManejadorDeComandos manejador, OpcionesDeServidor? opciones = null)
        {
            if (string.IsNullOrWhiteSpace(nombre) || nombre.IndexOfAny(new[] { '\\', '/' }) >= 0)
                throw new ArgumentException("Nombre de pipe no valido.", nameof(nombre));
            _nombre = nombre;
            _manejador = manejador;
            _opciones = opciones ?? new OpcionesDeServidor();
            _huecos = new SemaphoreSlim(_opciones.MaxConexiones, _opciones.MaxConexiones);
        }

        public string Nombre => _nombre;

        /// <summary>Peticiones contestadas (con exito o con error), para diagnostico y pruebas.</summary>
        public int Atendidas => Volatile.Read(ref _atendidas);

        /// <summary>Crea la primera instancia ANTES de volver: un cliente que llega justo despues ya la encuentra.</summary>
        public void Iniciar()
        {
            if (_aceptador is not null) throw new InvalidOperationException("Ya iniciado.");
            NamedPipeServerStream primera = Crear();
            _aceptador = Task.Run(() => AceptarAsync(primera));
        }

        private NamedPipeServerStream Crear()
            => NamedPipeServerStreamAcl.Create(_nombre, PipeDirection.InOut, _opciones.MaxConexiones + 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0,
                (_opciones.Seguridad ?? SeguridadDePipe.Crear)());

        private async Task AceptarAsync(NamedPipeServerStream actual)
        {
            CancellationToken ct = _parar.Token;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await actual.WaitForConnectionAsync(ct).ConfigureAwait(false);
                    NamedPipeServerStream conectado = actual;

                    // Si ya hay el maximo atendiendo, no se abre otra instancia: se espera un hueco.
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
            catch (Exception ex)
            {
                // Sin aceptador el servicio queda sordo: se deja constancia para que el anfitrion lo vea.
                Volatile.Write(ref _falloDelAceptador, ex);
            }
            finally { actual.Dispose(); }
        }

        private async Task AtenderAsync(NamedPipeServerStream pipe, CancellationToken parar)
        {
            ContextoDeLlamada? contexto = null;
            try
            {
                await using (pipe.ConfigureAwait(false))
                {
                    while (!parar.IsCancellationRequested)
                    {
                        byte[]? cuerpo;
                        using (var inactivo = CancellationTokenSource.CreateLinkedTokenSource(parar))
                        {
                            inactivo.CancelAfter(_opciones.TiempoInactivo);
                            cuerpo = await Tramas.LeerAsync(pipe, inactivo.Token).ConfigureAwait(false);
                        }
                        if (cuerpo is null) return;                      // el cliente cerro

                        // Solo tras leer el primer mensaje se puede identificar al cliente.
                        contexto ??= Capturar(pipe);

                        Respuesta r = await ResponderAsync(cuerpo, contexto, parar).ConfigureAwait(false);
                        Interlocked.Increment(ref _atendidas);
                        await Tramas.EscribirAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(r, Json), parar).ConfigureAwait(false);
                    }
                }
            }
            catch (Tramas.ViolacionDeProtocoloException)
            {
                // No se puede resincronizar: se cierra. Contestar a un cuerpo ilegible no aporta nada.
            }
            catch (Exception ex) when (ex is OperationCanceledException || ex is IOException || ex is ObjectDisposedException) { }
            finally
            {
                contexto?.Dispose();
                _huecos.Release();
            }
        }

        /// <summary>
        /// Identidad del cliente (SID y nivel de suplantacion que concedio) y, si dejo suplantarlo, un token
        /// duplicado para actuar en su nombre. Si no se puede, el contexto queda SIN token: las operaciones
        /// que lo exijan se rechazan (nunca se sustituye por SYSTEM).
        /// </summary>
        private static ContextoDeLlamada Capturar(NamedPipeServerStream pipe)
        {
            try
            {
                ContextoDeLlamada? c = null;
                pipe.RunAsClient(() =>
                {
                    using WindowsIdentity id = WindowsIdentity.GetCurrent();
                    bool puede = id.ImpersonationLevel is TokenImpersonationLevel.Impersonation or TokenImpersonationLevel.Delegation;
                    c = new ContextoDeLlamada(id.User, id.ImpersonationLevel,
                        puede ? new WindowsIdentity(id.AccessToken.DangerousGetHandle()) : null,
                        esAdministrador: new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator));
                });
                return c ?? new ContextoDeLlamada(null, TokenImpersonationLevel.None, null);
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidOperationException || ex is UnauthorizedAccessException)
            {
                return new ContextoDeLlamada(null, TokenImpersonationLevel.None, null);
            }
        }

        private async Task<Respuesta> ResponderAsync(byte[] cuerpo, ContextoDeLlamada contexto, CancellationToken parar)
        {
            Solicitud? s;
            try { s = JsonSerializer.Deserialize<Solicitud>(Tramas.Texto(cuerpo), Json); }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException)
            {
                return Fallo(null, CodigoDeError.PeticionInvalida, "JSON no valido");
            }

            if (s is null || string.IsNullOrWhiteSpace(s.Metodo) || s.Metodo.Length > 128)
                return Fallo(null, CodigoDeError.PeticionInvalida, "falta el metodo");
            if (s.Id is { Length: > 128 })
                return Fallo(null, CodigoDeError.PeticionInvalida, "id demasiado largo");

            try
            {
                using var limite = CancellationTokenSource.CreateLinkedTokenSource(parar);
                limite.CancelAfter(_opciones.TiempoPorPeticion);
                // Los manejadores leen la identidad del llamador de aqui (fluye por las llamadas asincronas).
                ContextoDeLlamada.Establecer(contexto);
                object? resultado = await _manejador.ManejarAsync(s.Metodo, s.Parametros, limite.Token).ConfigureAwait(false);
                return new Respuesta
                {
                    Id = s.Id,
                    Resultado = resultado is null ? null : JsonSerializer.SerializeToElement(resultado, Json)
                };
            }
            catch (ErrorDeComando e) { return Fallo(s.Id, e.Codigo, e.Message); }
            catch (OperationCanceledException) when (!parar.IsCancellationRequested)
            {
                return Fallo(s.Id, CodigoDeError.Tiempo, "la operacion tardo demasiado");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception)
            {
                // Sin detalles al cliente: la excepcion puede contener rutas o estado interno.
                return Fallo(s.Id, CodigoDeError.ErrorInterno, "error interno del servicio");
            }
        }

        private static Respuesta Fallo(string? id, int codigo, string mensaje)
            => new Respuesta { Id = id, Error = new ErrorIpc { Codigo = codigo, Mensaje = mensaje } };

        public async Task DetenerAsync()
        {
            _parar.Cancel();
            Task[] pendientes;
            lock (_conexiones) pendientes = _conexiones.ToArray();
            Task todo = Task.WhenAll(pendientes.Append(_aceptador ?? Task.CompletedTask));
            await Task.WhenAny(todo, Task.Delay(_opciones.TiempoDeParada)).ConfigureAwait(false);
        }

        public async ValueTask DisposeAsync()
        {
            await DetenerAsync().ConfigureAwait(false);
            _parar.Dispose();
        }
    }
}
