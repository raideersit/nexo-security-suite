using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Scan.Demo
{
    public enum ModoClamd
    {
        Normal,
        /// <summary>Acepta la conexion y no contesta nunca (prueba del tiempo de espera).</summary>
        Silencioso,
        /// <summary>Contesta algo que no es protocolo clamd.</summary>
        Basura,
        /// <summary>Cierra la conexion nada mas aceptarla.</summary>
        Caido
    }

    /// <summary>
    /// Un clamd de mentira: implementa el protocolo real (zPING, zVERSION,
    /// zINSTREAM con fragmentos de longitud big-endian) sobre loopback. Detecta una
    /// cadena marcadora propia en vez del EICAR, para no dejar en el disco archivos
    /// que Windows Defender quisiera poner en cuarentena.
    /// </summary>
    public sealed class ClamdFalso : IDisposable
    {
        public const string Marcador = "NEXO-FIRMA-DE-PRUEBA-NO-ES-UN-VIRUS";
        public const string Firma = "Nexo.Test.Signature";

        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private int _conexiones;

        public ClamdFalso()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Puerto = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(AceptarAsync);
        }

        public int Puerto { get; }
        public ModoClamd Modo { get; set; } = ModoClamd.Normal;

        /// <summary>Tras esta cantidad de conexiones, el servidor pasa a modo Caido.</summary>
        public int CaerseTras { get; set; } = int.MaxValue;

        /// <summary>Si es mayor que 0, un flujo mayor responde «size limit exceeded» y cierra.</summary>
        public long LimiteBytes { get; set; }

        public int Conexiones => _conexiones;
        public long UltimosBytes { get; private set; }
        public int UltimosFragmentos { get; private set; }

        private async Task AceptarAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false); }
                catch (Exception) { return; }
                _ = Task.Run(() => AtenderAsync(c));
            }
        }

        private async Task AtenderAsync(TcpClient cliente)
        {
            using (cliente)
            {
                try
                {
                    int n = Interlocked.Increment(ref _conexiones);
                    ModoClamd modo = n > CaerseTras ? ModoClamd.Caido : Modo;
                    if (modo == ModoClamd.Caido) return;

                    using NetworkStream red = cliente.GetStream();
                    string comando = await LeerComandoAsync(red).ConfigureAwait(false);

                    if (modo == ModoClamd.Silencioso) { await Task.Delay(Timeout.Infinite, _cts.Token).ConfigureAwait(false); return; }
                    if (modo == ModoClamd.Basura) { await Responder(red, "banana").ConfigureAwait(false); return; }

                    switch (comando)
                    {
                        case "zPING": await Responder(red, "PONG").ConfigureAwait(false); break;
                        case "zVERSION": await Responder(red, "ClamAV 1.4.0-falso/27000/Mon Oct 20 2026").ConfigureAwait(false); break;
                        case "zINSTREAM": await InstreamAsync(red).ConfigureAwait(false); break;
                        default: await Responder(red, "UNKNOWN COMMAND").ConfigureAwait(false); break;
                    }
                }
                catch (Exception) { /* un cliente que se va no debe tumbar el servidor */ }
            }
        }

        private static async Task<string> LeerComandoAsync(NetworkStream red)
        {
            var sb = new StringBuilder();
            byte[] b = new byte[1];
            while (await red.ReadAsync(b).ConfigureAwait(false) == 1)
            {
                if (b[0] == 0) break;
                sb.Append((char)b[0]);
            }
            return sb.ToString();
        }

        private async Task InstreamAsync(NetworkStream red)
        {
            var datos = new MemoryStream();
            byte[] largo = new byte[4];
            int fragmentos = 0;

            while (true)
            {
                await red.ReadExactlyAsync(largo).ConfigureAwait(false);
                int len = (largo[0] << 24) | (largo[1] << 16) | (largo[2] << 8) | largo[3];
                if (len == 0) break;

                byte[] trozo = new byte[len];
                await red.ReadExactlyAsync(trozo).ConfigureAwait(false);
                datos.Write(trozo);
                fragmentos++;

                if (LimiteBytes > 0 && datos.Length > LimiteBytes)
                {
                    await Responder(red, "INSTREAM size limit exceeded. ERROR").ConfigureAwait(false);
                    return;
                }
            }

            UltimosBytes = datos.Length;
            UltimosFragmentos = fragmentos;

            string texto = Encoding.Latin1.GetString(datos.ToArray());
            await Responder(red, texto.Contains(Marcador, StringComparison.Ordinal)
                ? "stream: " + Firma + " FOUND"
                : "stream: OK").ConfigureAwait(false);
        }

        private static async Task Responder(NetworkStream red, string texto)
        {
            await red.WriteAsync(Encoding.UTF8.GetBytes(texto + "\0")).ConfigureAwait(false);
            await red.FlushAsync().ConfigureAwait(false);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
        }
    }
}
