using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;

namespace Nexo.Modules.Threats.Enlaces
{
    /// <summary>De donde salen las listas. La real es <see cref="DescargaDeListasHttp"/>; las pruebas usan una falsa.</summary>
    public interface IDescargaDeListas
    {
        Task<RespuestaHttp> DescargarAsync(FuenteDeLista fuente, CancellationToken ct);
    }

    /// <summary>
    /// Descarga las listas desde direcciones FIJAS, solo HTTPS, sin seguir redirecciones ni guardar cookies, con un User-Agent generico
    /// y topes de tamaño y tiempo. Lo unico que sale del equipo es la peticion de la lista entera: ningun enlace del usuario.
    /// </summary>
    public sealed class DescargaDeListasHttp : IDescargaDeListas, IDisposable
    {
        public static readonly Uri PhishingArmy = new("https://phishing.army/download/phishing_army_blocklist.txt");

        /// <summary>«openphish.com/feed.txt» redirige aqui (comprobado el 2026-11-09); se pide directo para no seguir redirecciones.</summary>
        public static readonly Uri OpenPhish = new("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt");

        private readonly HttpClient _http;
        private readonly TimeSpan _espera;

        /// <param name="manejador">Solo para pruebas: sustituye al transporte real. En produccion, null.</param>
        public DescargaDeListasHttp(HttpMessageHandler? manejador = null, TimeSpan? espera = null)
        {
            _espera = espera ?? TimeSpan.FromSeconds(90);
            HttpMessageHandler h = manejador ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(10),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli
            };
            _http = new HttpClient(h, disposeHandler: manejador is null) { Timeout = Timeout.InfiniteTimeSpan };
        }

        public static Uri DireccionDe(FuenteDeLista f) => f == FuenteDeLista.PhishingArmy ? PhishingArmy : OpenPhish;

        public async Task<RespuestaHttp> DescargarAsync(FuenteDeLista fuente, CancellationToken ct)
        {
            using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limite.CancelAfter(_espera);
            try
            {
                using var peticion = new HttpRequestMessage(HttpMethod.Get, DireccionDe(fuente));
                peticion.Headers.UserAgent.ParseAdd("Nexo-Security-Suite");
                using HttpResponseMessage resp = await _http.SendAsync(peticion, HttpCompletionOption.ResponseHeadersRead, limite.Token).ConfigureAwait(false);
                if (resp.StatusCode != HttpStatusCode.OK) return new RespuestaHttp((int)resp.StatusCode, "");
                if (resp.Content.Headers.ContentLength is long largo && largo > ParserDeListas.MaximoDeCaracteres)
                    return new RespuestaHttp(null, "", "la lista es demasiado grande");

                using Stream s = await resp.Content.ReadAsStreamAsync(limite.Token).ConfigureAwait(false);
                using var ms = new MemoryStream();
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = await s.ReadAsync(buf.AsMemory(), limite.Token).ConfigureAwait(false)) > 0)
                {
                    if (ms.Length + n > ParserDeListas.MaximoDeCaracteres) return new RespuestaHttp(null, "", "la lista es demasiado grande");
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
                return new RespuestaHttp(null, "", "sin conexión (" + (e.InnerException?.GetType().Name ?? e.GetType().Name) + ")");
            }
        }

        public void Dispose() => _http.Dispose();
    }

    public sealed record ActualizacionDeFuente(FuenteDeLista Fuente, bool Actualizada, string Mensaje);

    public sealed record ResultadoDeActualizacion(ListasDePhishing Listas, IReadOnlyList<ActualizacionDeFuente> Fuentes);

    public sealed record CargaDeListas(ListasDePhishing Listas, IReadOnlyList<string> Avisos);

    /// <summary>
    /// Guarda las listas tal como llegaron (texto) en una carpeta del usuario, y la fecha de descarga al lado. Es estado, no un log.
    /// Reglas:
    ///  - Una descarga solo reemplaza a la guardada si pasa la validacion: una descarga mala nunca deja al equipo sin la lista anterior.
    ///  - Escritura atomica (archivo temporal + reemplazo).
    ///  - Al cargar se vuelve a validar: un archivo dañado no se usa, y se avisa.
    ///  - Cortesia con los servidores: una lista bajada hace menos de <see cref="MinimoEntreDescargas"/> no se vuelve a pedir.
    /// </summary>
    public sealed class AlmacenDeListas
    {
        public static readonly TimeSpan MinimoEntreDescargas = TimeSpan.FromHours(1);

        private readonly string _carpeta;

        public AlmacenDeListas(string carpeta) => _carpeta = carpeta ?? throw new ArgumentNullException(nameof(carpeta));

        public static string CarpetaPorOmision()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "listas");

        public string Carpeta => _carpeta;

        private string Archivo(FuenteDeLista f) => Path.Combine(_carpeta, f == FuenteDeLista.PhishingArmy ? "phishing-army.txt" : "openphish.txt");

        private string Fecha(FuenteDeLista f) => Archivo(f) + ".fecha";

        public CargaDeListas Cargar()
        {
            var avisos = new List<string>();
            ListaCargada? army = CargarUna(FuenteDeLista.PhishingArmy, avisos);
            ListaCargada? op = CargarUna(FuenteDeLista.OpenPhish, avisos);
            return new CargaDeListas(new ListasDePhishing(army, op), avisos);
        }

        private ListaCargada? CargarUna(FuenteDeLista f, List<string> avisos)
        {
            string ruta = Archivo(f);
            if (!File.Exists(ruta)) return null;
            try
            {
                string texto = File.ReadAllText(ruta, Encoding.UTF8);
                DateTimeOffset descargada = LeerFecha(f) ?? new DateTimeOffset(File.GetLastWriteTimeUtc(ruta), TimeSpan.Zero);
                LecturaDeLista l = Leer(f, texto, descargada);
                if (l.Lista is null) avisos.Add("La lista guardada de " + AnalizadorDeMensajes.NombreDe(f) + " no se pudo usar: " + l.Motivo + ". Vuelve a descargarla.");
                return l.Lista;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                avisos.Add("No se pudo leer la lista guardada de " + AnalizadorDeMensajes.NombreDe(f) + " (" + e.GetType().Name + ").");
                return null;
            }
        }

        private DateTimeOffset? LeerFecha(FuenteDeLista f)
        {
            try
            {
                string ruta = Fecha(f);
                if (!File.Exists(ruta)) return null;
                return DateTimeOffset.TryParse(File.ReadAllText(ruta).Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset d) ? d.ToUniversalTime() : null;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        }

        private static LecturaDeLista Leer(FuenteDeLista f, string texto, DateTimeOffset descargada)
            => f == FuenteDeLista.PhishingArmy ? ParserDeListas.LeerPhishingArmy(texto, descargada) : ParserDeListas.LeerOpenPhish(texto, descargada);

        /// <summary>Baja las dos listas. Cada una por separado: si una falla, la otra se actualiza igual, y la que fallo conserva la anterior.</summary>
        public async Task<ResultadoDeActualizacion> ActualizarAsync(IDescargaDeListas descarga, ListasDePhishing actuales, DateTimeOffset ahora, CancellationToken ct = default)
        {
            var fuentes = new List<ActualizacionDeFuente>();
            ListasDePhishing listas = actuales;
            foreach (FuenteDeLista f in new[] { FuenteDeLista.PhishingArmy, FuenteDeLista.OpenPhish })
            {
                ct.ThrowIfCancellationRequested();
                string nombre = AnalizadorDeMensajes.NombreDe(f);
                ListaCargada? anterior = listas.De(f);
                string conserva = anterior is null ? "No hay ninguna lista anterior." : "Se sigue usando la anterior (" + anterior.Entradas.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + " entradas).";

                if (anterior is not null && ahora - anterior.Descargada < MinimoEntreDescargas && ahora >= anterior.Descargada)
                {
                    fuentes.Add(new ActualizacionDeFuente(f, false, nombre + ": ya está al día (se descargó hace " + (int)(ahora - anterior.Descargada).TotalMinutes + " min)."));
                    continue;
                }

                RespuestaHttp r = await descarga.DescargarAsync(f, ct).ConfigureAwait(false);
                if (r.Estado != 200)
                {
                    string por = r.Estado is int c ? "el servidor respondió " + c : r.Error ?? "no hubo respuesta";
                    fuentes.Add(new ActualizacionDeFuente(f, false, nombre + ": no se pudo descargar (" + por + "). " + conserva));
                    continue;
                }

                LecturaDeLista l = Leer(f, r.Texto, ahora);
                if (l.Lista is null)
                {
                    fuentes.Add(new ActualizacionDeFuente(f, false, nombre + ": la descarga no se aceptó (" + l.Motivo + "). " + conserva));
                    continue;
                }

                try
                {
                    Guardar(f, r.Texto, ahora);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    // Se usa en memoria igualmente (es valida), pero no queda guardada: se dice.
                    listas = listas.Con(l.Lista);
                    fuentes.Add(new ActualizacionDeFuente(f, true, nombre + ": descargada (" + l.Lista.Entradas.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + " entradas), pero no se pudo guardar en el disco (" + e.GetType().Name + "): habrá que descargarla otra vez al abrir Nexo."));
                    continue;
                }
                listas = listas.Con(l.Lista);
                fuentes.Add(new ActualizacionDeFuente(f, true, nombre + ": actualizada (" + l.Lista.Entradas.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + " entradas)."));
            }
            return new ResultadoDeActualizacion(listas, fuentes);
        }

        private void Guardar(FuenteDeLista f, string texto, DateTimeOffset descargada)
        {
            Directory.CreateDirectory(_carpeta);
            EscribirAtomico(Archivo(f), texto);
            EscribirAtomico(Fecha(f), descargada.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        }

        private static void EscribirAtomico(string ruta, string texto)
        {
            string tmp = ruta + ".tmp";
            File.WriteAllText(tmp, texto, new UTF8Encoding(false));
            File.Move(tmp, ruta, overwrite: true);
        }
    }
}
