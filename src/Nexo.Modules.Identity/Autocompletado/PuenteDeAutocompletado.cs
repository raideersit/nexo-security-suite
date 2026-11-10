using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;

namespace Nexo.Modules.Identity.Autocompletado
{
    /// <summary>Navegadores autorizados a pedir contraseñas. Se guarda la HUELLA de su clave, nunca la clave.</summary>
    public interface INavegadoresEmparejados
    {
        bool Autorizado(string navegador, byte[] clave);
        /// <returns>null si se guardó; si no, el motivo.</returns>
        string? Guardar(string navegador, byte[] clave);
        IReadOnlyList<string> Lista();
        bool Olvidar(string navegador);
    }

    /// <summary>
    /// El protocolo entre la extensión del navegador y la ventana de Nexo (la bóveda vive en la ventana). Cada petición es un JSON con
    /// «tipo», «navegador» y «clave»; cada respuesta, un JSON con «estado». Reglas de seguridad:
    ///  - Nada se contesta a un navegador no emparejado salvo «estado» y «emparejar», y emparejar exige que la persona confirme en Nexo
    ///    que el código que ve coincide con el de la extensión (se pregunta de uno en uno, y tras un rechazo hay una espera).
    ///  - Con la bóveda bloqueada no sale nada: «bloqueada».
    ///  - «buscar» devuelve usuarios y sitios, NUNCA contraseñas. La contraseña solo sale con «rellenar», para UNA entrada, y se vuelve a
    ///    comprobar que el sitio de la entrada coincide con la página (<see cref="SitioDeEntrada"/>).
    ///  - Hay un tope de rellenados por minuto: un programa que intente vaciar la bóveda de golpe se frena (y se ve en Nexo).
    ///  - Una petición mal formada se contesta «error», sin detalles internos.
    /// Lo que NO puede evitar, y se dice: un programa que corre con tu usuario puede leer la clave guardada en el perfil del navegador y
    /// hacerse pasar por él (igual que con KeePassXC o Bitwarden). Por eso la bóveda se bloquea sola y Nexo avisa de cada rellenado.
    /// </summary>
    public sealed class PuenteDeAutocompletado
    {
        public const int BytesDeClave = 32;
        public const int MaxRellenadosPorMinuto = 20;
        public const int MaxEntradasPorRespuesta = 50;
        public static readonly TimeSpan EsperaTrasRechazo = TimeSpan.FromSeconds(30);

        private static readonly Regex NombreValido = new Regex("^[a-z0-9-]{1,32}$", RegexOptions.CultureInvariant);
        private static readonly JsonSerializerOptions Opciones = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        private readonly Func<IReadOnlyList<EntradaDeBoveda>?> _entradas;
        private readonly INavegadoresEmparejados _emparejados;
        private readonly Func<string, string, CancellationToken, Task<bool>> _confirmarEmparejamiento;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Queue<DateTimeOffset> _rellenados = new Queue<DateTimeOffset>();
        private readonly SemaphoreSlim _unEmparejamiento = new SemaphoreSlim(1, 1);
        private readonly Func<string, string?>? _motivoParaNoEmparejar;
        private DateTimeOffset _noPreguntarHasta = DateTimeOffset.MinValue;

        /// <param name="entradas">Las entradas de la bóveda ABIERTA, o null si está bloqueada (o no hay bóveda).</param>
        /// <param name="confirmarEmparejamiento">Pregunta a la persona (navegador, código) y devuelve si aceptó. Por omisión, «No».</param>
        /// <param name="motivoParaNoEmparejar">Antes de preguntar: null = se puede; si no, el motivo para NO preguntar (p. ej. la persona no pidió
        /// emparejar en Nexo). Así un programa no puede hacer saltar la pregunta cuando quiera.</param>
        public PuenteDeAutocompletado(Func<IReadOnlyList<EntradaDeBoveda>?> entradas, INavegadoresEmparejados emparejados,
                                      Func<string, string, CancellationToken, Task<bool>> confirmarEmparejamiento, Func<DateTimeOffset>? reloj = null,
                                      Func<string, string?>? motivoParaNoEmparejar = null)
        {
            _motivoParaNoEmparejar = motivoParaNoEmparejar;
            _entradas = entradas;
            _emparejados = emparejados;
            _confirmarEmparejamiento = confirmarEmparejamiento;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        /// <summary>Se dispara tras dar una contraseña (navegador, sitio de la página). Para avisar en la ventana. No debe lanzar.</summary>
        public event Action<string, string>? Rellenado;

        /// <summary>Un navegador quedó emparejado (nombre). No debe lanzar.</summary>
        public event Action<string>? Emparejado;
        /// <summary>Se preguntó y la persona dijo que no (o la pregunta falló). No debe lanzar.</summary>
        public event Action<string>? EmparejamientoRechazado;
        /// <summary>Alguien pidió emparejar cuando no se admitía (no se preguntó nada). No debe lanzar.</summary>
        public event Action<string>? EmparejamientoNoAdmitido;

        private static void Disparar(Action<string>? e, string navegador)
        {
            try { e?.Invoke(navegador); } catch (Exception) { /* un aviso roto no cambia la respuesta */ }
        }

        /// <summary>El código de 6 cifras que ven las dos partes para confirmar el emparejamiento. La extensión lo calcula igual.</summary>
        public static string CodigoDe(byte[] clave)
        {
            byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes("nexo-emparejar:" + Convert.ToBase64String(clave)));
            uint n = (uint)(h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3]) % 1_000_000;
            string s = n.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
            return s[..3] + " " + s[3..];
        }

        /// <summary>Atiende una petición (el JSON que mandó la extensión) y devuelve la respuesta JSON. Nunca lanza salvo por cancelación.</summary>
        public async Task<byte[]> AtenderAsync(byte[] peticion, CancellationToken ct = default)
        {
            object respuesta;
            try { respuesta = await AtenderInternoAsync(peticion, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or KeyNotFoundException)
            {
                respuesta = Error("petición no válida");
            }
            return JsonSerializer.SerializeToUtf8Bytes(respuesta, Opciones);
        }

        private async Task<object> AtenderInternoAsync(byte[] peticion, CancellationToken ct)
        {
            using JsonDocument doc = JsonDocument.Parse(peticion);
            JsonElement p = doc.RootElement;
            if (p.ValueKind != JsonValueKind.Object) return Error("petición no válida");
            string tipo = Texto(p, "tipo") ?? "";
            string? navegador = Texto(p, "navegador");
            if (navegador is null || !NombreValido.IsMatch(navegador)) return Error("falta el nombre del navegador o no es válido");
            byte[]? clave = Clave(p);
            bool emparejado = clave is not null && _emparejados.Autorizado(navegador, clave);

            switch (tipo)
            {
                case "estado":
                    return new { estado = "ok", bloqueada = _entradas() is null, emparejado };

                case "emparejar":
                    if (clave is null) return Error("falta la clave (32 bytes en base64)");
                    if (emparejado) return new { estado = "ok", emparejado = true };
                    return await EmparejarAsync(navegador, clave, ct).ConfigureAwait(false);

                case "buscar":
                case "rellenar":
                {
                    if (!emparejado) return new { estado = "no_emparejado", motivo = "este navegador no está autorizado en Nexo" };
                    IReadOnlyList<EntradaDeBoveda>? entradas = _entradas();
                    if (entradas is null) return new { estado = "bloqueada", motivo = "desbloquea la bóveda en Nexo" };
                    PaginaParaRellenar pagina = SitioDeEntrada.AnalizarPagina(Texto(p, "url"));
                    if (!pagina.Valida) return new { estado = "rechazada", motivo = pagina.Motivo };
                    string host = pagina.Host!;

                    if (tipo == "buscar")
                    {
                        var coinciden = entradas.Where(e => SitioDeEntrada.HostDeEntrada(e.Sitio) is { } h && SitioDeEntrada.Coincide(host, h))
                                                .OrderBy(e => e.Usuario, StringComparer.OrdinalIgnoreCase).ToList();
                        return new
                        {
                            estado = "ok",
                            sitio = host,
                            entradas = coinciden.Take(MaxEntradasPorRespuesta).Select(e => new { id = e.Id, usuario = e.Usuario, sitio = e.Sitio }).ToList(),
                            mas = Math.Max(0, coinciden.Count - MaxEntradasPorRespuesta)
                        };
                    }

                    if (!Guid.TryParse(Texto(p, "id"), out Guid id)) return Error("falta el id de la entrada");
                    EntradaDeBoveda? e = entradas.FirstOrDefault(x => x.Id == id);
                    if (e is null) return new { estado = "no_encontrada" };
                    if (SitioDeEntrada.HostDeEntrada(e.Sitio) is not { } hostEntrada || !SitioDeEntrada.Coincide(host, hostEntrada))
                        return new { estado = "rechazada", motivo = "esa entrada no es de " + host };
                    if (!DentroDelLimite()) return new { estado = "limite", motivo = "demasiados rellenados seguidos; espera un minuto" };
                    try { Rellenado?.Invoke(navegador, host); } catch (Exception) { /* un aviso roto no cambia la respuesta */ }
                    return new { estado = "ok", usuario = e.Usuario, contrasena = e.Contrasena };
                }

                default:
                    return Error("tipo de petición desconocido");
            }
        }

        private async Task<object> EmparejarAsync(string navegador, byte[] clave, CancellationToken ct)
        {
            string? noAdmitido = _motivoParaNoEmparejar?.Invoke(navegador);
            if (noAdmitido is not null)
            {
                Disparar(EmparejamientoNoAdmitido, navegador);
                return new { estado = "rechazado", motivo = noAdmitido };
            }
            if (_reloj() < _noPreguntarHasta) return new { estado = "rechazado", motivo = "se rechazó hace poco; espera antes de volver a pedirlo" };
            // De una en una: varias peticiones a la vez no pueden apilar ventanas de confirmación.
            if (!await _unEmparejamiento.WaitAsync(0, ct).ConfigureAwait(false)) return new { estado = "ocupado", motivo = "ya hay un emparejamiento esperando respuesta en Nexo" };
            try
            {
                bool si;
                try { si = await _confirmarEmparejamiento(navegador, CodigoDe(clave), ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException) { si = false; }
                if (!si)
                {
                    _noPreguntarHasta = _reloj() + EsperaTrasRechazo;
                    Disparar(EmparejamientoRechazado, navegador);
                    return new { estado = "rechazado", motivo = "no se aceptó en Nexo" };
                }
                string? problema = _emparejados.Guardar(navegador, clave);
                if (problema is not null) return Error("no se pudo guardar el emparejamiento (" + problema + ")");
                Disparar(Emparejado, navegador);
                return new { estado = "ok", emparejado = true };
            }
            finally { _unEmparejamiento.Release(); }
        }

        private bool DentroDelLimite()
        {
            DateTimeOffset ahora = _reloj();
            lock (_rellenados)
            {
                while (_rellenados.Count > 0 && ahora - _rellenados.Peek() >= TimeSpan.FromMinutes(1)) _rellenados.Dequeue();
                if (_rellenados.Count >= MaxRellenadosPorMinuto) return false;
                _rellenados.Enqueue(ahora);
                return true;
            }
        }

        private static object Error(string motivo) => new { estado = "error", motivo };

        private static string? Texto(JsonElement o, string nombre)
            => o.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static byte[]? Clave(JsonElement o)
        {
            string? b64 = Texto(o, "clave");
            if (b64 is null || b64.Length > 64) return null;
            try
            {
                byte[] c = Convert.FromBase64String(b64);
                return c.Length == BytesDeClave ? c : null;
            }
            catch (FormatException) { return null; }
        }
    }

    /// <summary>
    /// Los navegadores emparejados en un JSON (escritura atómica). Solo la huella SHA-256 de cada clave. Dañado = se aparta como «.corrupto» y
    /// hay que volver a emparejar (nunca se autoriza nada por no poder leer la lista).
    /// </summary>
    public sealed class NavegadoresEmparejadosJson : INavegadoresEmparejados
    {
        private sealed class Registro
        {
            public string Navegador { get; set; } = "";
            public string Huella { get; set; } = "";
            public DateTimeOffset Desde { get; set; }
        }

        private readonly string _ruta;
        private readonly object _candado = new object();
        private readonly Func<DateTimeOffset> _reloj;

        public NavegadoresEmparejadosJson(string ruta, Func<DateTimeOffset>? reloj = null) { _ruta = ruta; _reloj = reloj ?? (() => DateTimeOffset.Now); }

        public string? Problema { get; private set; }

        public bool Autorizado(string navegador, byte[] clave)
        {
            string huella = Huella(clave);
            lock (_candado)
                return Leer().Any(r => r.Navegador == navegador
                                       && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(r.Huella), Encoding.ASCII.GetBytes(huella)));
        }

        public string? Guardar(string navegador, byte[] clave)
        {
            lock (_candado)
            {
                List<Registro> l = Leer();
                l.RemoveAll(r => r.Navegador == navegador);
                l.Add(new Registro { Navegador = navegador, Huella = Huella(clave), Desde = _reloj() });
                return Escribir(l);
            }
        }

        public IReadOnlyList<string> Lista() { lock (_candado) return Leer().Select(r => r.Navegador).ToList(); }

        public bool Olvidar(string navegador)
        {
            lock (_candado)
            {
                List<Registro> l = Leer();
                if (l.RemoveAll(r => r.Navegador == navegador) == 0) return false;
                return Escribir(l) is null;
            }
        }

        private static string Huella(byte[] clave) => Convert.ToHexString(SHA256.HashData(clave)).ToLowerInvariant();

        private List<Registro> Leer()
        {
            if (!File.Exists(_ruta)) return new List<Registro>();
            try
            {
                List<Registro>? l = JsonSerializer.Deserialize<List<Registro>>(File.ReadAllText(_ruta, Encoding.UTF8));
                if (l is null || l.Any(r => r is null || r.Navegador.Length == 0 || r.Huella.Length != 64)) throw new InvalidDataException();
                return l;
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                try { File.Copy(_ruta, _ruta + ".corrupto", overwrite: true); File.Delete(_ruta); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                Problema = "la lista de navegadores emparejados estaba dañada y se apartó: hay que volver a emparejarlos";
                return new List<Registro>();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Problema = "no se pudo leer la lista de navegadores emparejados (" + ex.GetType().Name + ")";
                return new List<Registro>();
            }
        }

        private string? Escribir(List<Registro> l)
        {
            try
            {
                string carpeta = Path.GetDirectoryName(Path.GetFullPath(_ruta))!;
                Directory.CreateDirectory(carpeta);
                string tmp = Path.Combine(carpeta, "~" + Path.GetFileName(_ruta) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
                File.WriteAllText(tmp, JsonSerializer.Serialize(l, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
                if (File.Exists(_ruta)) File.Replace(tmp, _ruta, null); else File.Move(tmp, _ruta);
                return null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return ex.GetType().Name;
            }
        }
    }
}
