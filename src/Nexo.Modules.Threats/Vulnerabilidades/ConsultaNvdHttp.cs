using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    /// <summary>
    /// Pregunta a <c>https://services.nvd.nist.gov/rest/json/cves/2.0</c> (gratuito, sin cuenta ni clave) que fallos conocidos
    /// tiene un producto y version. Lo unico que sale del equipo es la cadena CPE («a:proveedor:producto:version»). Defensas: el
    /// servidor es fijo y solo HTTPS; no sigue redirecciones ni guarda cookies; el CPE se valida antes de armar la direccion (nada
    /// de texto libre en la URL); tope de tamano y de tiempo; no registra nada. Lo que no sea un 200 se devuelve con su codigo.
    /// </summary>
    public sealed class ConsultaNvdHttp : IConsultaNvd, IDisposable
    {
        public static readonly Uri Servidor = new Uri("https://services.nvd.nist.gov/");

        private static readonly Regex FormaDeCpe = new Regex(@"^cpe:2\.3:a:[a-z0-9_.\-]{1,64}:[a-z0-9_.\-]{1,64}:[0-9]{1,6}(\.[0-9]{1,6}){1,3}(:update[1-9][0-9]{0,3}(:\*){6}|(:\*){7})\z",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly HttpClient _http;
        private readonly TimeSpan _espera;

        /// <param name="manejador">Solo para pruebas: sustituye al transporte real. En produccion, null.</param>
        public ConsultaNvdHttp(HttpMessageHandler? manejador = null, TimeSpan? espera = null)
        {
            _espera = espera ?? TimeSpan.FromSeconds(60);
            HttpMessageHandler h = manejador ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(10),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
            };
            _http = new HttpClient(h, disposeHandler: manejador is null) { BaseAddress = Servidor, Timeout = Timeout.InfiniteTimeSpan };
        }

        public async Task<RespuestaHttp> ConsultarCvesAsync(string cpe, CancellationToken ct)
        {
            if (cpe is null || !FormaDeCpe.IsMatch(cpe))
                throw new ArgumentException("El CPE no tiene la forma esperada.", nameof(cpe));

            using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limite.CancelAfter(_espera);
            try
            {
                string ruta = "rest/json/cves/2.0?resultsPerPage=2000&virtualMatchString=" + Uri.EscapeDataString(cpe);
                using var peticion = new HttpRequestMessage(HttpMethod.Get, ruta);
                peticion.Headers.UserAgent.ParseAdd("Nexo-Security-Suite");

                using HttpResponseMessage resp = await _http.SendAsync(peticion, HttpCompletionOption.ResponseHeadersRead, limite.Token).ConfigureAwait(false);
                int codigo = (int)resp.StatusCode;
                if (resp.StatusCode != HttpStatusCode.OK) return new RespuestaHttp(codigo, "");
                if (resp.Content.Headers.ContentLength is long largo && largo > ParserDeNvd.MaximoDeCaracteres)
                    return new RespuestaHttp(null, "", "la respuesta es demasiado grande");

                using Stream s = await resp.Content.ReadAsStreamAsync(limite.Token).ConfigureAwait(false);
                using var ms = new MemoryStream();
                byte[] buf = new byte[16 * 1024];
                int n;
                while ((n = await s.ReadAsync(buf.AsMemory(), limite.Token).ConfigureAwait(false)) > 0)
                {
                    if (ms.Length + n > ParserDeNvd.MaximoDeCaracteres) return new RespuestaHttp(null, "", "la respuesta es demasiado grande");
                    ms.Write(buf, 0, n);
                }
                return new RespuestaHttp(200, Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new RespuestaHttp(null, "", "se agotó el tiempo de espera");
            }
            catch (HttpRequestException e)
            {
                return new RespuestaHttp(null, "", e.InnerException?.GetType().Name ?? e.GetType().Name);
            }
        }

        public void Dispose() => _http.Dispose();
    }
}
