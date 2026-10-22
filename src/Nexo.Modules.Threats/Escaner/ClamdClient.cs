using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Threats.Escaner
{
    public enum VeredictoDeArchivo
    {
        Limpio,
        Infectado,

        /// <summary>El motor no pudo decidir. NUNCA equivale a Limpio.</summary>
        Error
    }

    public sealed record ResultadoDeMotor(VeredictoDeArchivo Veredicto, string? Firma = null, string? Error = null)
    {
        public static ResultadoDeMotor Limpio() => new(VeredictoDeArchivo.Limpio);
        public static ResultadoDeMotor Infectado(string firma) => new(VeredictoDeArchivo.Infectado, firma);
        public static ResultadoDeMotor Fallo(string error) => new(VeredictoDeArchivo.Error, Error: error);
    }

    /// <summary>
    /// Un motor de firmas. Se abstrae para que el escaner se pruebe sin ClamAV
    /// instalado y para poder sustituir el motor (YARA, otro) sin tocar el escaner.
    /// </summary>
    public interface IMotorDeFirmas
    {
        string Nombre { get; }

        /// <summary>Version del motor y de su base de firmas. Lanza si el motor no responde.</summary>
        Task<string> VersionAsync(CancellationToken ct = default);

        Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default);
    }

    public sealed class MotorNoDisponibleException : Exception
    {
        public MotorNoDisponibleException(string mensaje, Exception? interna = null) : base(mensaje, interna) { }
    }

    /// <summary>
    /// Cliente del demonio <c>clamd</c> de ClamAV por TCP (protocolo INSTREAM).
    ///
    /// Se usa clamd por TCP y no libclamav enlazada: libclamav es GPLv2 y
    /// enlazarla obligaria a publicar Nexo bajo GPL (Salida 0, §5). Hablar el
    /// protocolo no enlaza nada.
    ///
    /// Privacidad: el contenido de los archivos solo se envia a una direccion de
    /// LOOPBACK. Apuntar a otro host exige permitirRemoto: true, explicito; Nexo
    /// no manda archivos del usuario a ninguna otra maquina por omision.
    ///
    /// Se usan los comandos con prefijo z (terminados en NUL) porque, a diferencia
    /// de los terminados en salto de linea, no se confunden con datos.
    /// </summary>
    public sealed class ClamdClient : IMotorDeFirmas
    {
        public const int PuertoPorDefecto = 3310;

        private readonly string _host;
        private readonly int _puerto;
        private readonly TimeSpan _timeout;
        private readonly int _tamanoChunk;

        public ClamdClient(
            string host = "127.0.0.1",
            int puerto = PuertoPorDefecto,
            bool permitirRemoto = false,
            TimeSpan? timeout = null,
            int tamanoChunk = 64 * 1024)
        {
            if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Host vacio.", nameof(host));
            if (puerto is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(puerto));
            if (tamanoChunk < 1) throw new ArgumentOutOfRangeException(nameof(tamanoChunk));

            if (!permitirRemoto && !EsLoopback(host))
                throw new ArgumentException(
                    "'" + host + "' no es una direccion local. Nexo no envia archivos a otra maquina " +
                    "salvo que se pida explicitamente (permitirRemoto).", nameof(host));

            _host = host;
            _puerto = puerto;
            _timeout = timeout ?? TimeSpan.FromSeconds(30);
            _tamanoChunk = tamanoChunk;
        }

        public string Nombre => "ClamAV (clamd)";

        public async Task<string> VersionAsync(CancellationToken ct = default)
        {
            string r = await ComandoSimpleAsync("zVERSION\0", ct).ConfigureAwait(false);
            if (r.Length == 0) throw new MotorNoDisponibleException("clamd no respondio a VERSION.");
            return r;
        }

        /// <summary>True si clamd responde PONG.</summary>
        public async Task<bool> PingAsync(CancellationToken ct = default)
        {
            try { return (await ComandoSimpleAsync("zPING\0", ct).ConfigureAwait(false)) == "PONG"; }
            catch (MotorNoDisponibleException) { return false; }
        }

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            if (contenido is null) throw new ArgumentNullException(nameof(contenido));

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_timeout);

                using var tcp = new TcpClient();
                await tcp.ConnectAsync(_host, _puerto, cts.Token).ConfigureAwait(false);
                using NetworkStream red = tcp.GetStream();

                await red.WriteAsync(Encoding.ASCII.GetBytes("zINSTREAM\0"), cts.Token).ConfigureAwait(false);

                // Si clamd contesta antes de tiempo (p. ej. limite de tamano) y cierra,
                // la escritura falla: igual hay que leer SU respuesta, que explica por que.
                try
                {
                    byte[] datos = new byte[_tamanoChunk];
                    byte[] largo = new byte[4];
                    int n;
                    while ((n = await contenido.ReadAsync(datos.AsMemory(0, datos.Length), cts.Token).ConfigureAwait(false)) > 0)
                    {
                        // Longitud del fragmento en 4 bytes, orden de red (big-endian).
                        largo[0] = (byte)(n >> 24); largo[1] = (byte)(n >> 16); largo[2] = (byte)(n >> 8); largo[3] = (byte)n;
                        await red.WriteAsync(largo, cts.Token).ConfigureAwait(false);
                        await red.WriteAsync(datos.AsMemory(0, n), cts.Token).ConfigureAwait(false);
                    }
                    // Un fragmento de longitud cero cierra el flujo.
                    await red.WriteAsync(new byte[4], cts.Token).ConfigureAwait(false);
                    await red.FlushAsync(cts.Token).ConfigureAwait(false);
                }
                catch (IOException) { /* se lee la respuesta igualmente */ }
                catch (SocketException) { }

                string respuesta = await LeerRespuestaAsync(red, cts.Token).ConfigureAwait(false);
                return Interpretar(respuesta);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return ResultadoDeMotor.Fallo("tiempo de espera agotado esperando a clamd");
            }
            catch (SocketException ex)
            {
                return ResultadoDeMotor.Fallo("no se pudo hablar con clamd (" + ex.SocketErrorCode + ")");
            }
            catch (IOException ex)
            {
                return ResultadoDeMotor.Fallo("conexion con clamd interrumpida: " + ex.Message);
            }
        }

        /// <summary>
        /// Traduce la respuesta de clamd. Todo lo que no se reconoce con certeza es
        /// Error: ante la duda, jamas "Limpio".
        /// </summary>
        public static ResultadoDeMotor Interpretar(string respuesta)
        {
            string r = respuesta.Trim('\0', '\n', '\r', ' ');
            if (r.Length == 0) return ResultadoDeMotor.Fallo("clamd cerro la conexion sin responder");

            if (r.EndsWith(" FOUND", StringComparison.Ordinal))
            {
                string cuerpo = r[..^" FOUND".Length];
                int i = cuerpo.IndexOf(": ", StringComparison.Ordinal);
                string firma = i >= 0 ? cuerpo[(i + 2)..] : cuerpo;
                return string.IsNullOrWhiteSpace(firma)
                    ? ResultadoDeMotor.Fallo("deteccion sin nombre de firma: " + r)
                    : ResultadoDeMotor.Infectado(firma);
            }

            if (r.EndsWith(" ERROR", StringComparison.Ordinal))
                return ResultadoDeMotor.Fallo(r[..^" ERROR".Length].Trim());

            if (r.EndsWith(": OK", StringComparison.Ordinal))
                return ResultadoDeMotor.Limpio();

            return ResultadoDeMotor.Fallo("respuesta no reconocida de clamd: " + Recortar(r));
        }

        private async Task<string> ComandoSimpleAsync(string comando, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_timeout);

                using var tcp = new TcpClient();
                await tcp.ConnectAsync(_host, _puerto, cts.Token).ConfigureAwait(false);
                using NetworkStream red = tcp.GetStream();
                await red.WriteAsync(Encoding.ASCII.GetBytes(comando), cts.Token).ConfigureAwait(false);
                return (await LeerRespuestaAsync(red, cts.Token).ConfigureAwait(false)).Trim('\0', '\n', '\r', ' ');
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new MotorNoDisponibleException("clamd no respondio a tiempo en " + _host + ":" + _puerto);
            }
            catch (Exception ex) when (ex is SocketException || ex is IOException)
            {
                throw new MotorNoDisponibleException(
                    "no se pudo conectar con clamd en " + _host + ":" + _puerto + ". ¿Esta instalado y en marcha?", ex);
            }
        }

        private static async Task<string> LeerRespuestaAsync(Stream red, CancellationToken ct)
        {
            // Las respuestas con prefijo z terminan en NUL. Tope de 4 KB: una
            // respuesta legitima mide decenas de bytes.
            var sb = new StringBuilder();
            byte[] b = new byte[512];
            int n;
            while ((n = await red.ReadAsync(b.AsMemory(), ct).ConfigureAwait(false)) > 0)
            {
                sb.Append(Encoding.UTF8.GetString(b, 0, n));
                if (sb.Length > 4096 || sb[^1] == '\0') break;
            }
            return sb.ToString();
        }

        private static bool EsLoopback(string host)
            => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
               || (IPAddress.TryParse(host, out IPAddress? ip) && IPAddress.IsLoopback(ip));

        private static string Recortar(string s) => s.Length > 120 ? s[..120] + "..." : s;
    }
}
