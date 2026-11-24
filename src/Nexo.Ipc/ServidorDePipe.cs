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

        /// <summary>
        /// Plazo para que un cliente recien conectado mande su primer mensaje. Es mas corto que <see cref="TiempoInactivo"/>:
        /// hasta que no manda nada no se sabe quien es, asi que no se le deja ocupar un hueco mucho rato.
        /// </summary>
        public TimeSpan TiempoAntesDelPrimerMensaje { get; init; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Conexiones simultaneas por usuario (SID), una vez identificado. Evita que un solo proceso ocupe los
        /// <see cref="MaxConexiones"/> huecos y deje sin servicio a la bandeja y la ventana. 0 = sin limite.
        /// </summary>
        public int MaxConexionesPorUsuario { get; init; } = 4;

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
        private readonly Dictionary<string, int> _porUsuario = new Dictionary<string, int>(StringComparer.Ordinal);
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
            NamedPipeServerStream primera;
            try { primera = Crear(primeraInstancia: true); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // Con FirstPipeInstance, Windows rechaza crear el pipe si el nombre ya existe: otro proceso (o una copia
                // anterior) lo tiene. No se sirve nada: un cliente podria acabar hablando con quien lo ocupo primero.
                throw new InvalidOperationException(
                    "El nombre de pipe '" + _nombre + "' ya esta en uso por otro proceso; el servicio no arranca.", ex);
            }
            _aceptador = Task.Run(() => AceptarAsync(primera));
        }

        /// <param name="primeraInstancia">
        /// true solo para la primera instancia: exige que el nombre NO exista ya (<see cref="PipeOptions.FirstPipeInstance"/>), asi
        /// otro proceso no puede haberse adelantado y quedarse con el pipe. Las siguientes son instancias del mismo pipe ya creado.
        /// </param>
        private NamedPipeServerStream Crear(bool primeraInstancia = false)
            => NamedPipeServerStreamAcl.Create(_nombre, PipeDirection.InOut, _opciones.MaxConexiones + 1,
                PipeTransmissionMode.Byte,
                primeraInstancia ? PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance : PipeOptions.Asynchronous,
                0, 0, (_opciones.Seguridad ?? SeguridadDePipe.Crear)());

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
                    try { actual = Crear(); }
                    catch { _huecos.Release(); throw; }   // sin esto, el hueco ya tomado no se devolveria nunca

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
            string? usuarioContado = null;
            try
            {
                await using (pipe.ConfigureAwait(false))
                {
                    while (!parar.IsCancellationRequested)
                    {
                        byte[]? cuerpo;
                        using (var inactivo = CancellationTokenSource.CreateLinkedTokenSource(parar))
                        {
                            // Antes del primer mensaje no se sabe quien es: plazo corto.
                            inactivo.CancelAfter(contexto is null ? _opciones.TiempoAntesDelPrimerMensaje : _opciones.TiempoInactivo);
                            cuerpo = await Tramas.LeerAsync(pipe, inactivo.Token).ConfigureAwait(false);
                        }
                        if (cuerpo is null) return;                      // el cliente cerro

                        // Solo tras leer el primer mensaje se puede identificar al cliente.
                        if (contexto is null)
                        {
                            contexto = Capturar(pipe);
                            usuarioContado = ContarUsuario(contexto);
                            if (usuarioContado is null) return;          // ya tiene el maximo de conexiones: se cierra
                        }

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
                if (usuarioContado is not null) DescontarUsuario(usuarioContado);
                contexto?.Dispose();
                _huecos.Release();
            }
        }

        private const string UsuarioDesconocido = "?";

        /// <summary>
        /// Cuenta esta conexion para su usuario. Devuelve la clave con la que se contó (para descontarla despues) o null si
        /// ese usuario ya tiene <see cref="OpcionesDeServidor.MaxConexionesPorUsuario"/> y esta no se admite. Si no se pudo
        /// identificar al cliente, todas esas conexiones comparten una misma cuenta.
        /// </summary>
        private string? ContarUsuario(ContextoDeLlamada contexto)
        {
            int max = _opciones.MaxConexionesPorUsuario;
            string clave = contexto.Usuario?.Value ?? UsuarioDesconocido;
            lock (_porUsuario)
            {
                _porUsuario.TryGetValue(clave, out int actuales);
                if (max > 0 && actuales >= max) return null;
                _porUsuario[clave] = actuales + 1;
            }
            return clave;
        }

        private void DescontarUsuario(string clave)
        {
            lock (_porUsuario)
            {
                if (!_porUsuario.TryGetValue(clave, out int n)) return;
                if (n <= 1) _porUsuario.Remove(clave);
                else _porUsuario[clave] = n - 1;
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
