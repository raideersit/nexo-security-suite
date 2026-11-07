using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Identity.Filtraciones
{
    /// <summary>
    /// Pregunta a <c>https://api.pwnedpasswords.com/range/XXXXX</c> (gratuita, sin clave). Solo envia el prefijo de 5
    /// caracteres. Defensas: el servidor es fijo y solo HTTPS; no sigue redirecciones ni guarda cookies; pide relleno
    /// (<c>Add-Padding</c>) para ocultar cuantos resultados reales hay; limita el tamano de la respuesta y el tiempo; y no
    /// registra nada. Cualquier cosa que no sea un 200 con un cuerpo acotado es un fallo, no un «no encontrada».
    /// </summary>
    public sealed class ConsultaDeRangosHttp : IConsultaDeRangos, IDisposable
    {
        public static readonly Uri Servidor = new Uri("https://api.pwnedpasswords.com/");

        /// <summary>Una respuesta real ronda los 30-60 KB (con relleno, hasta ~100 KB); mas de 1 MiB no es una respuesta legitima.</summary>
        public const int MaximoDeBytes = 1024 * 1024;

        private static readonly Regex Prefijo = new Regex("^[0-9A-F]{5}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly HttpClient _http;
        private readonly TimeSpan _espera;

        /// <param name="manejador">Solo para pruebas: sustituye al transporte real. En produccion, null.</param>
        public ConsultaDeRangosHttp(HttpMessageHandler? manejador = null, TimeSpan? espera = null)
        {
            _espera = espera ?? TimeSpan.FromSeconds(20);
            HttpMessageHandler h = manejador ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(10),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
            };
            _http = new HttpClient(h, disposeHandler: manejador is null) { BaseAddress = Servidor, Timeout = Timeout.InfiniteTimeSpan };
        }

        public async Task<RespuestaDeRango> ObtenerAsync(string prefijo, CancellationToken ct)
        {
            if (prefijo is null || !Prefijo.IsMatch(prefijo))
                throw new ArgumentException("El prefijo debe ser de exactamente 5 caracteres hexadecimales en mayúscula.", nameof(prefijo));

            using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limite.CancelAfter(_espera);
            try
            {
                using var peticion = new HttpRequestMessage(HttpMethod.Get, "range/" + prefijo);
                peticion.Headers.TryAddWithoutValidation("Add-Padding", "true");
                peticion.Headers.UserAgent.ParseAdd("Nexo-Security-Suite");

                using HttpResponseMessage resp = await _http.SendAsync(peticion, HttpCompletionOption.ResponseHeadersRead, limite.Token).ConfigureAwait(false);
                if (resp.StatusCode != HttpStatusCode.OK)
                    return RespuestaDeRango.Fallo("el servicio respondió HTTP " + (int)resp.StatusCode);
                if (resp.Content.Headers.ContentLength is long largo && largo > MaximoDeBytes)
                    return RespuestaDeRango.Fallo("la respuesta es demasiado grande");

                using Stream s = await resp.Content.ReadAsStreamAsync(limite.Token).ConfigureAwait(false);
                using var ms = new MemoryStream();
                byte[] buf = new byte[16 * 1024];
                int n;
                while ((n = await s.ReadAsync(buf.AsMemory(), limite.Token).ConfigureAwait(false)) > 0)
                {
                    if (ms.Length + n > MaximoDeBytes) return RespuestaDeRango.Fallo("la respuesta es demasiado grande");
                    ms.Write(buf, 0, n);
                }
                return RespuestaDeRango.Ok(Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return RespuestaDeRango.Fallo("se agotó el tiempo de espera");
            }
            catch (HttpRequestException e)
            {
                return RespuestaDeRango.Fallo("no hay conexión con el servicio (" + (e.InnerException?.GetType().Name ?? e.GetType().Name) + ")");
            }
        }

        public void Dispose() => _http.Dispose();
    }
}
