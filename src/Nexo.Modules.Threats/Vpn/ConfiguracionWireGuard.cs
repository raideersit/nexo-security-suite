using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Vpn
{
    public sealed record ScriptWg(string Clave, string Comando);

    /// <summary>
    /// La seccion [Interface]. La clave privada NO se guarda: se valida y se descarta (solo queda <see cref="TieneClavePrivada"/>).
    /// </summary>
    public sealed record InterfazWg(bool TieneClavePrivada, IReadOnlyList<string> Direcciones, IReadOnlyList<string> Dns, int? Mtu, int? PuertoLocal,
                                    IReadOnlyList<ScriptWg> Scripts, string? Tabla);

    /// <summary>Un [Peer]. La clave compartida (PresharedKey) tampoco se guarda. La publica si: es publica.</summary>
    public sealed record PeerWg(string ClavePublica, bool TieneClaveCompartida, IReadOnlyList<string> IpsPermitidas, string? Endpoint, string? HostDelEndpoint,
                                int? PuertoDelEndpoint, int KeepAlive);

    public sealed record ConfiguracionWg(InterfazWg Interfaz, IReadOnlyList<PeerWg> Peers);

    /// <summary>
    /// El resultado de leer un archivo. <see cref="Errores"/> son los motivos por los que WireGuard para Windows RECHAZARIA el archivo (con su linea);
    /// con alguno, <see cref="Configuracion"/> es null. <see cref="ErrorDeNombre"/> es aparte: el contenido puede estar bien y el nombre no.
    /// </summary>
    public sealed record LecturaDeConfiguracionWg(ConfiguracionWg? Configuracion, IReadOnlyList<string> Errores, string? NombreDeTunel, string? ErrorDeNombre)
    {
        public bool Valida => Configuracion is not null && ErrorDeNombre is null;
    }

    /// <summary>
    /// Lee un archivo de WireGuard (formato wg-quick) con las MISMAS reglas que WireGuard para Windows (<c>conf/parser.go</c> y
    /// <c>conf/name.go</c> de wireguard-windows, leidos el 2026-11-09): claves sin distinguir mayusculas; una clave desconocida, una linea fuera
    /// de seccion o un valor vacio son error; las claves deben ser base64 de exactamente 32 bytes; MTU 576-65535; keepalive «off» o 0-65535;
    /// puerto 0-65535; Table «off», «auto», «main» o un entero de 32 bits; el nombre del tunel ^[a-zA-Z0-9_=+.-]{1,32}$ y sin nombres reservados
    /// de Windows. Asi «WireGuard lo rechazara» sale por los mismos motivos que en el programa. Nada sale del equipo.
    /// </summary>
    public static class ParserDeWireGuard
    {
        public const int MaximoDeCaracteres = 64 * 1024;

        private static readonly Regex NombrePermitido = new(@"^[a-zA-Z0-9_=+.-]{1,32}\z", RegexOptions.CultureInvariant);
        private static readonly string[] Reservados = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                                        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
        private static readonly Regex NombreDeHost = new(@"^(?=.{1,253}\z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z", RegexOptions.CultureInvariant);

        /// <summary>El nombre del tunel sale del nombre del archivo sin «.conf». Null si es valido; si no, el motivo.</summary>
        public static string? ValidarNombre(string nombre)
        {
            if (string.IsNullOrEmpty(nombre)) return "el nombre está vacío";
            string sinPunto = nombre.Split('.')[0];
            if (Reservados.Any(r => string.Equals(r, sinPunto, StringComparison.OrdinalIgnoreCase)))
                return "«" + nombre + "» es un nombre reservado de Windows";
            if (nombre.StartsWith('.') || nombre.EndsWith('.')) return "no puede empezar ni terminar en punto";
            if (!NombrePermitido.IsMatch(nombre))
                return nombre.Length > 32 ? "tiene más de 32 caracteres" : "solo se admiten letras sin tilde, números y _ = + . - (sin espacios)";
            return null;
        }

        public static string NombreDesdeArchivo(string archivo)
        {
            string n = archivo.Replace('\\', '/');
            n = n.Substring(n.LastIndexOf('/') + 1);
            if (n.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)) n = n.Substring(0, n.Length - 5);
            return n;
        }

        public static LecturaDeConfiguracionWg Leer(string? texto, string nombreDeArchivo)
        {
            string nombre = NombreDesdeArchivo(nombreDeArchivo ?? "");
            string? errorDeNombre = ValidarNombre(nombre);
            var errores = new List<string>();
            if (string.IsNullOrEmpty(texto)) return new(null, new[] { "el archivo está vacío" }, nombre, errorDeNombre);
            if (texto.Length > MaximoDeCaracteres) return new(null, new[] { "el archivo es demasiado grande para ser una configuración de WireGuard" }, nombre, errorDeNombre);
            if (texto[0] == '﻿') texto = texto.Substring(1);

            bool enInterfaz = false, enPeer = false, vioInterfaz = false;
            bool clavePrivada = false, vioPrivada = false;
            var direcciones = new List<string>(); var dns = new List<string>(); var scripts = new List<ScriptWg>();
            int? mtu = null, puerto = null; string? tabla = null;
            var peers = new List<PeerWg>();
            PeerEnCurso? peer = null;

            void CerrarPeer()
            {
                if (peer is null) return;
                if (peer.ClavePublica is null) errores.Add("todos los [Peer] deben tener PublicKey (falta en el que empieza en la línea " + peer.Linea + ")");
                else peers.Add(new PeerWg(peer.ClavePublica, peer.Compartida, peer.Ips, peer.Endpoint, peer.Host, peer.Puerto, peer.KeepAlive));
                peer = null;
            }

            string[] lineas = texto.Split('\n');
            for (int i = 0; i < lineas.Length; i++)
            {
                int n = i + 1;
                string linea = lineas[i];
                int almohadilla = linea.IndexOf('#');
                if (almohadilla >= 0) linea = linea.Substring(0, almohadilla);
                linea = linea.Trim();
                if (linea.Length == 0) continue;

                string minus = linea.ToLowerInvariant();
                if (minus == "[interface]") { CerrarPeer(); enInterfaz = true; enPeer = false; vioInterfaz = true; continue; }
                if (minus == "[peer]") { CerrarPeer(); enInterfaz = false; enPeer = true; peer = new PeerEnCurso(n); continue; }
                if (!enInterfaz && !enPeer) { errores.Add("línea " + n + ": está fuera de una sección [Interface] o [Peer]"); continue; }

                int igual = linea.IndexOf('=');
                if (igual < 0) { errores.Add("línea " + n + ": falta el «=» entre la clave y el valor"); continue; }
                string clave = linea.Substring(0, igual).Trim().ToLowerInvariant();
                string valor = linea.Substring(igual + 1).Trim();
                if (valor.Length == 0) { errores.Add("línea " + n + ": «" + clave + "» no tiene valor"); continue; }

                string? e = null;
                if (enInterfaz)
                {
                    switch (clave)
                    {
                        case "privatekey": vioPrivada = true; e = ValidarClave(valor); if (e is null) clavePrivada = true; break; // la clave se descarta aqui mismo
                        case "listenport": e = Entero(valor, 0, 65535, out int p) ? null : "puerto inválido"; puerto = p; break;
                        case "mtu": e = Entero(valor, 576, 65535, out int m) ? null : "MTU inválido (debe estar entre 576 y 65535)"; mtu = m; break;
                        case "address":
                            foreach (string a in Lista(valor)) { string? ea = ValidarCidr(a); if (ea is not null) { e = ea; break; } direcciones.Add(a); }
                            break;
                        case "dns": dns.AddRange(Lista(valor)); break;
                        case "preup": case "postup": case "predown": case "postdown":
                            scripts.Add(new ScriptWg(clave switch { "preup" => "PreUp", "postup" => "PostUp", "predown" => "PreDown", _ => "PostDown" }, valor)); break;
                        case "table":
                            string t = valor.ToLowerInvariant();
                            if (t is "off" or "auto" or "main" || uint.TryParse(valor, NumberStyles.None, CultureInfo.InvariantCulture, out _)) tabla = valor;
                            else e = "valor de Table inválido";
                            break;
                        default: e = "«" + clave + "» no es una clave válida en [Interface]"; break;
                    }
                }
                else
                {
                    switch (clave)
                    {
                        case "publickey": e = ValidarClave(valor); if (e is null) peer!.ClavePublica = valor; break;
                        case "presharedkey": e = ValidarClave(valor); if (e is null) peer!.Compartida = true; break;
                        case "allowedips":
                            foreach (string a in Lista(valor)) { string? ea = ValidarCidr(a); if (ea is not null) { e = ea; break; } peer!.Ips.Add(a); }
                            break;
                        case "endpoint":
                            e = ValidarEndpoint(valor, out string? host, out int? pe);
                            if (e is null) { peer!.Endpoint = valor; peer.Host = host; peer.Puerto = pe; }
                            break;
                        case "persistentkeepalive":
                            if (valor.Equals("off", StringComparison.OrdinalIgnoreCase)) peer!.KeepAlive = 0;
                            else if (Entero(valor, 0, 65535, out int k)) peer!.KeepAlive = k;
                            else e = "PersistentKeepalive inválido (debe ser «off» o un número de 0 a 65535)";
                            break;
                        default: e = "«" + clave + "» no es una clave válida en [Peer]"; break;
                    }
                }
                if (e is not null) errores.Add("línea " + n + ": " + e);
            }
            CerrarPeer();

            if (!vioInterfaz) errores.Add("falta la sección [Interface]");
            else if (!vioPrivada) errores.Add("la sección [Interface] debe tener PrivateKey");

            if (errores.Count > 0) return new(null, errores, nombre, errorDeNombre);
            return new(new ConfiguracionWg(new InterfazWg(clavePrivada, direcciones, dns, mtu, puerto, scripts, tabla), peers), errores, nombre, errorDeNombre);
        }

        private sealed class PeerEnCurso
        {
            public PeerEnCurso(int linea) => Linea = linea;
            public int Linea { get; }
            public string? ClavePublica;
            public bool Compartida;
            public readonly List<string> Ips = new();
            public string? Endpoint, Host;
            public int? Puerto;
            public int KeepAlive;
        }

        private static IEnumerable<string> Lista(string v) => v.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0);

        private static bool Entero(string v, int min, int max, out int n)
            => int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out n) && n >= min && n <= max;

        /// <summary>Base64 de exactamente 32 bytes, como WireGuard. Nunca se devuelve ni se copia el valor.</summary>
        public static string? ValidarClave(string v)
        {
            Span<byte> buf = stackalloc byte[64];
            if (v.Length != 44 || !Convert.TryFromBase64String(v, buf, out int escritos) || escritos != 32) return "la clave debe ser base64 de exactamente 32 bytes";
            buf.Clear();
            return null;
        }

        public static string? ValidarCidr(string v)
        {
            string ip = v; int? prefijo = null;
            int barra = v.IndexOf('/');
            if (barra >= 0)
            {
                ip = v.Substring(0, barra);
                if (!int.TryParse(v.Substring(barra + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int p)) return "«" + v + "» no es una red válida";
                prefijo = p;
            }
            if (!IPAddress.TryParse(ip, out IPAddress? dir) || ip.Contains('%')) return "«" + v + "» no es una dirección IP válida";
            int maximo = dir.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
            if (dir.AddressFamily == AddressFamily.InterNetwork && ip.Count(c => c == '.') != 3) return "«" + v + "» no es una dirección IP válida";
            if (prefijo is int pp && (pp < 0 || pp > maximo)) return "«" + v + "» tiene un prefijo fuera de rango";
            return null;
        }

        public static string? ValidarEndpoint(string v, out string? host, out int? puerto)
        {
            host = null; puerto = null;
            string h; string p;
            if (v.StartsWith('['))
            {
                int cierre = v.IndexOf(']');
                if (cierre < 0 || cierre + 1 >= v.Length || v[cierre + 1] != ':') return "Endpoint inválido";
                h = v.Substring(1, cierre - 1); p = v.Substring(cierre + 2);
                if (!IPAddress.TryParse(h, out IPAddress? a6) || a6.AddressFamily != AddressFamily.InterNetworkV6) return "Endpoint inválido";
            }
            else
            {
                int dos = v.LastIndexOf(':');
                if (dos <= 0 || v.IndexOf(':') != dos) return "Endpoint inválido (debe ser «servidor:puerto»)";
                h = v.Substring(0, dos); p = v.Substring(dos + 1);
                if (!IPAddress.TryParse(h, out _) && !NombreDeHost.IsMatch(h)) return "Endpoint inválido (el servidor no es un nombre ni una IP)";
            }
            if (!Entero(p, 0, 65535, out int pn)) return "Endpoint inválido (puerto)";
            host = h.ToLowerInvariant(); puerto = pn;
            return null;
        }
    }
}
