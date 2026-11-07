using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private const string ClaveSentinela = "SECRETO-DE-PRUEBA-NO-DEBE-SALIR-123";

        /// <summary>Un perfil con la forma que escribe Windows (esquema v1, con la clave CIFRADA en keyMaterial).</summary>
        private static string Xml(string nombre, string auth, string cif, string modo = "auto", bool oculta = false, string clave = "01000000D08C9DDF0115D1118C7A00C04FC297EB01000000", bool protegida = true)
            => "<?xml version=\"1.0\"?>\n<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
             + "  <name>" + nombre + "</name>\n  <SSIDConfig><SSID><name>" + nombre + "</name></SSID><nonBroadcast>" + (oculta ? "true" : "false") + "</nonBroadcast></SSIDConfig>\n"
             + "  <connectionType>ESS</connectionType>\n  <connectionMode>" + modo + "</connectionMode>\n"
             + "  <MSM><security><authEncryption><authentication>" + auth + "</authentication><encryption>" + cif + "</encryption><useOneX>false</useOneX></authEncryption>\n"
             + (cif == "none" ? "" : "    <sharedKey><keyType>passPhrase</keyType><protected>" + (protegida ? "true" : "false") + "</protected><keyMaterial>" + clave + "</keyMaterial></sharedKey>\n")
             + "  </security></MSM>\n</WLANProfile>";

        private static InstantaneaDeWifi Wifi(IEnumerable<PerfilCrudo> perfiles, ConexionActual? conexion = null)
            => new(EstadoDeLecturaWifi.Correcta, new[] { new AdaptadorWifi("Wi-Fi de prueba", perfiles.ToList(), conexion) });

        private static ResultadoDeAnalisis Perfil(string auth, string cif, string modo = "auto", bool oculta = false)
            => AnalizadorDeWifi.Analizar(Wifi(new[] { new PerfilCrudo("MiRed", Xml("MiRed", auth, cif, modo, oculta)) }));

        private static void ProbarParserWifi()
        {
            Console.WriteLine("7. Parser de perfiles de Wi-Fi");
            PerfilWifi? p = ParserDePerfilWifi.Parsear("MiRed", Xml("MiRed", "WPA2PSK", "AES"));
            Check(p is not null && p.Autenticacion == "WPA2PSK" && p.Cifrado == "AES" && p.Automatico == true && p.Oculta == false, "lee autenticacion, cifrado, modo automatico y red no oculta", p?.ToString());

            PerfilWifi? manual = ParserDePerfilWifi.Parsear("X", Xml("X", "WPA2PSK", "AES", modo: "manual", oculta: true));
            Check(manual is { Automatico: false, Oculta: true }, "lee modo manual y red oculta");

            // La clave NUNCA se lee, ni cifrada ni (si estuviera) en texto plano.
            PerfilWifi? conClave = ParserDePerfilWifi.Parsear("MiRed", Xml("MiRed", "WPA2PSK", "AES", clave: ClaveSentinela, protegida: false));
            Check(conClave is not null && !conClave.ToString().Contains(ClaveSentinela) && !conClave.GetType().GetProperties().Any(pr => Convert.ToString(pr.GetValue(conClave))?.Contains(ClaveSentinela) == true),
                  "una clave en TEXTO PLANO dentro del XML no aparece en ningun campo del resultado");
            Check(!typeof(PerfilWifi).GetProperties().Any(pr => pr.Name.Contains("Clave", StringComparison.OrdinalIgnoreCase) || pr.Name.Contains("Key", StringComparison.OrdinalIgnoreCase)),
                  "y PerfilWifi no tiene ningun campo donde ponerla");

            // Un keyMaterial malicioso con elementos dentro no puede falsear los datos de seguridad.
            // El keyMaterial falso va ANTES de la seguridad real: si el parser lo leyera, ganaria el primer valor («open»/«none»).
            string falso = "<WLANProfile><MSM><security><sharedKey><keyMaterial><authentication>open</authentication><encryption>none</encryption></keyMaterial></sharedKey>"
                         + "<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption></security></MSM></WLANProfile>";
            PerfilWifi? f = ParserDePerfilWifi.Parsear("MiRed", falso);
            Check(f is { Autenticacion: "WPA2PSK", Cifrado: "AES" }, "elementos escondidos dentro de keyMaterial (y antes de la seguridad real) se saltan y no la sustituyen", f?.ToString());

            // Otras versiones del esquema (v3) y espacios en blanco.
            string v3 = Xml("MiRed", "WPA3SAE", "AES").Replace("profile/v1", "profile/v3").Replace("<authentication>", "<authentication>\n   ").Replace("</authentication>", "  \n</authentication>");
            Check(ParserDePerfilWifi.Parsear("MiRed", v3) is { Autenticacion: "WPA3SAE" }, "el espacio de nombres v3 y los espacios en blanco no importan");

            // Entradas hostiles.
            string xxe = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///c:/windows/win.ini\">]>" + Xml("MiRed", "WPA2PSK", "AES").Replace("<name>MiRed</name>\n  <SSIDConfig>", "<name>&e;</name>\n  <SSIDConfig>");
            Check(ParserDePerfilWifi.Parsear("MiRed", xxe) is null, "un XML con DTD y entidad externa se rechaza (no se resuelve)");
            // Un DTD, aunque sea inofensivo, se rechaza: el perfil es valido salvo por el DOCTYPE, asi que solo falla si se prohibe de verdad.
            string inofensivo = "<?xml version=\"1.0\"?><!DOCTYPE p [<!ENTITY e \"x\">]>" + Xml("MiRed", "WPA2PSK", "AES").Replace("<?xml version=\"1.0\"?>\n", "");
            Check(ParserDePerfilWifi.Parsear("X", Xml("MiRed", "WPA2PSK", "AES")) is not null && ParserDePerfilWifi.Parsear("X", inofensivo) is null, "control: el mismo perfil sin DTD se lee; con un DTD inofensivo se rechaza");
            string laughs = "<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]>"
                          + Xml("MiRed", "WPA2PSK", "AES").Replace("<?xml version=\"1.0\"?>\n", "").Replace("<name>MiRed</name>\n  <SSIDConfig>", "<name>&c;</name>\n  <SSIDConfig>");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Check(ParserDePerfilWifi.Parsear("X", laughs) is null && sw.ElapsedMilliseconds < 2000, "una bomba de entidades dentro de un perfil valido se rechaza rapido", sw.ElapsedMilliseconds + " ms");
            Check(ParserDePerfilWifi.Parsear("X", new string('a', ParserDePerfilWifi.MaximoDeCaracteres + 1)) is null, "un XML mas grande que el tope se rechaza");
            Check(ParserDePerfilWifi.Parsear("X", Xml("X", "WPA2PSK", "AES") + new string(' ', ParserDePerfilWifi.MaximoDeCaracteres)) is null, "relleno hasta pasar el tope tambien");
            Check(ParserDePerfilWifi.Parsear("X", "") is null && ParserDePerfilWifi.Parsear("X", null) is null && ParserDePerfilWifi.Parsear("X", "esto no es xml") is null, "vacio, nulo y texto que no es XML dan null");
            Check(ParserDePerfilWifi.Parsear("X", "<WLANProfile><name>x</name></WLANProfile>") is null, "un perfil sin autenticacion ni cifrado da null (no se adivina)");
            Check(ParserDePerfilWifi.Parsear("X", Xml("X", "WPA2PSK", "AES").Replace("</WLANProfile>", "")) is null, "un XML truncado da null");
            Check(ParserDePerfilWifi.Parsear("X", "<a><authentication><x/></authentication><encryption>AES</encryption></a>") is null, "un elemento authentication con hijos (no es texto) da null, sin lanzar");

            // Fuzz sencillo: cortar el XML en cada posicion nunca lanza.
            string base1 = Xml("MiRed", "WPA2PSK", "AES");
            int lanzo = 0;
            for (int i = 0; i < base1.Length; i++) { try { ParserDePerfilWifi.Parsear("X", base1.Substring(0, i)); } catch (Exception) { lanzo++; } }
            Check(lanzo == 0, "cortar el XML en cada una de sus " + base1.Length + " posiciones nunca lanza una excepcion", lanzo + " lanzaron");
        }

        private static void ProbarReglasWifi()
        {
            Console.WriteLine("8. Reglas sobre las redes guardadas");
            Check(Perfil("WPA2PSK", "AES").Hallazgos.Count == 0 && Perfil("WPA2PSK", "AES").Completo, "WPA2-AES: sin hallazgos y completo");
            Check(Perfil("WPA3SAE", "AES").Hallazgos.Count == 0 && Perfil("OWE", "AES").Hallazgos.Count == 0 && Perfil("WPA3ENT192", "GCMP256").Hallazgos.Count == 0, "WPA3 y OWE (Open Enhanced) no dan hallazgos");

            HallazgoDeSistema abiertaAuto = Perfil("open", "none").Hallazgos.Single();
            Check(abiertaAuto.Id == "WIFI-RED-ABIERTA-AUTOMATICA" && abiertaAuto.Severidad == Severidad.Alta && abiertaAuto.Sujeto == "MiRed", "red abierta que se conecta sola -> Alta");
            HallazgoDeSistema abiertaMan = Perfil("open", "none", modo: "manual").Hallazgos.Single();
            Check(abiertaMan.Id == "WIFI-RED-ABIERTA" && abiertaMan.Severidad == Severidad.Media, "red abierta manual -> Media");

            Check(Perfil("shared", "WEP").Hallazgos.Single().Id == "WIFI-WEP" && Perfil("shared", "WEP").Hallazgos.Single().Severidad == Severidad.Alta, "WEP (shared) -> Alta");
            Check(Perfil("open", "WEP").Hallazgos.Single().Id == "WIFI-WEP", "WEP con autenticacion abierta tambien es WEP, no «red abierta»");
            Check(Perfil("WPA2PSK", "TKIP").Hallazgos.Single().Id == "WIFI-TKIP" && Perfil("WPAPSK", "TKIP").Hallazgos.Single().Severidad == Severidad.Media, "TKIP (WPA2 o WPA) -> Media");

            ResultadoDeAnalisis oculta = Perfil("WPA2PSK", "AES", oculta: true);
            Check(oculta.Hallazgos.Single().Id == "WIFI-RED-OCULTA" && oculta.Hallazgos.Single().Severidad == Severidad.Baja, "red oculta -> Baja");
            Check(Perfil("open", "none", oculta: true).Hallazgos.Count == 2, "una red abierta y oculta da dos hallazgos");

            ResultadoDeAnalisis rara = Perfil("raro", "extra");
            Check(rara.Hallazgos.Count == 0 && !rara.Completo && rara.NoEvaluado.Single().Contains("raro / extra"), "una combinacion desconocida NO se da por buena: queda «no evaluado» con sus valores");
            Check(!Perfil("open", "AES").Completo, "«open» con cifrado AES (incoherente) tampoco se da por buena");

            ResultadoDeAnalisis ilegible = AnalizadorDeWifi.Analizar(Wifi(new[] { new PerfilCrudo("Cafe", null) }));
            Check(!ilegible.Completo && ilegible.NoEvaluado.Single().Contains("Cafe") && ilegible.Hallazgos.Count == 0, "un perfil que no se pudo leer es «no evaluado» y nombra la red");
            ResultadoDeAnalisis malformado = AnalizadorDeWifi.Analizar(Wifi(new[] { new PerfilCrudo("Bar", "<basura/>") }));
            Check(!malformado.Completo && malformado.NoEvaluado.Single().Contains("Bar"), "un perfil con formato raro es «no evaluado»");

            // Se sigue analizando el resto aunque un perfil falle.
            ResultadoDeAnalisis mezcla = AnalizadorDeWifi.Analizar(Wifi(new[]
            {
                new PerfilCrudo("Mala", Xml("Mala", "shared", "WEP")), new PerfilCrudo("Rota", null), new PerfilCrudo("Buena", Xml("Buena", "WPA2PSK", "AES")), new PerfilCrudo("Abierta", Xml("Abierta", "open", "none"))
            }));
            Check(mezcla.Hallazgos.Count == 2 && mezcla.NoEvaluado.Count == 1 && mezcla.Hallazgos[0].Severidad >= mezcla.Hallazgos[1].Severidad, "con 4 perfiles (WEP, ilegible, buena, abierta): 2 hallazgos ordenados + 1 no evaluado");
            Check(mezcla.Maxima == Severidad.Alta, "la maxima es Alta");
        }

        private static void ProbarConexionWifi()
        {
            Console.WriteLine("9. Conexion actual");
            ResultadoDeAnalisis Con(ConexionActual c) => AnalizadorDeWifi.Analizar(Wifi(Array.Empty<PerfilCrudo>(), c));

            ResultadoDeAnalisis sin = Con(new ConexionActual("Cafe", false, 1, 0));
            Check(sin.Hallazgos.Single().Id == "WIFI-CONEXION-SIN-CIFRADO" && sin.Hallazgos.Single().Severidad == Severidad.Alta, "conectado sin cifrado -> Alta");
            Check(Con(new ConexionActual("X", true, 2, 1)).Hallazgos.Single().Id == "WIFI-CONEXION-WEP", "autenticacion shared (2) -> WEP, Alta");
            Check(Con(new ConexionActual("X", true, 4, 5)).Hallazgos.Single().Id == "WIFI-CONEXION-WEP", "cifrado WEP-104 (5) -> WEP");
            Check(Con(new ConexionActual("X", true, 4, 0x101)).Hallazgos.Single().Id == "WIFI-CONEXION-WEP", "cifrado WEP (0x101) -> WEP");
            ResultadoDeAnalisis tkip = Con(new ConexionActual("X", true, 7, 2));
            Check(tkip.Hallazgos.Single().Id == "WIFI-CONEXION-TKIP" && tkip.Hallazgos.Single().Severidad == Severidad.Media, "cifrado TKIP (2) -> Media");
            Check(Con(new ConexionActual("X", true, 7, 4)).Hallazgos.Count == 0, "WPA2-PSK con CCMP (auth 7, cifrado 4) -> nada");
            Check(Con(new ConexionActual("X", true, 9, 9)).Hallazgos.Count == 0, "WPA3-SAE con GCMP-256 -> nada");
            Check(AnalizadorDeWifi.Analizar(Wifi(Array.Empty<PerfilCrudo>(), null)).Hallazgos.Count == 0, "sin conexion activa no se inventa ninguna");
        }

        private static void ProbarEstadosWifi()
        {
            Console.WriteLine("10. Estados de lectura: «sin Wi-Fi» no es «no pude leer»");
            ResultadoDeAnalisis sinAd = AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.SinAdaptador, Array.Empty<AdaptadorWifi>()));
            Check(sinAd.Completo && sinAd.Hallazgos.Count == 0, "sin adaptador Wi-Fi: completo y sin hallazgos (es un hecho)");
            ResultadoDeAnalisis serv = AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.ServicioNoActivo, Array.Empty<AdaptadorWifi>()));
            Check(!serv.Completo && serv.NoEvaluado.Single().Contains("servicio"), "servicio WLAN parado con adaptador presente: NO evaluado");
            ResultadoDeAnalisis err = AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.Error, Array.Empty<AdaptadorWifi>()));
            Check(!err.Completo && err.Hallazgos.Count == 0, "error de la API: NO evaluado y sin hallazgos inventados");
            Check(AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.Correcta, Array.Empty<AdaptadorWifi>())).Completo, "lectura correcta con cero perfiles: completa");
            bool lanzo = false;
            try { AnalizadorDeWifi.Analizar(null!); } catch (ArgumentNullException) { lanzo = true; }
            Check(lanzo, "una instantanea null se rechaza");
        }

        private static void ProbarEventosWifi()
        {
            Console.WriteLine("11. Evento de la revision de Wi-Fi");
            NexoEvent sinAd = EventosDeVulnerabilidades.RevisionDeWifi(AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.SinAdaptador, Array.Empty<AdaptadorWifi>())), EstadoDeLecturaWifi.SinAdaptador);
            Check(sinAd.Severidad == Severidad.Info && sinAd.Titulo.Contains("no tiene adaptador"), "sin adaptador: Info y lo dice");

            ResultadoDeAnalisis serv = AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(EstadoDeLecturaWifi.ServicioNoActivo, Array.Empty<AdaptadorWifi>()));
            NexoEvent inc = EventosDeVulnerabilidades.RevisionDeWifi(serv, EstadoDeLecturaWifi.ServicioNoActivo);
            Check(inc.Severidad == Severidad.Media && inc.Titulo.Contains("incompleta") && inc.Cuerpo!.Contains("NO significa que este bien"), "servicio parado: Media, «incompleta» y aclara que no significa que este bien");

            ResultadoDeAnalisis limpia = Perfil("WPA2PSK", "AES");
            NexoEvent ok = EventosDeVulnerabilidades.RevisionDeWifi(limpia, EstadoDeLecturaWifi.Correcta);
            Check(ok.Severidad == Severidad.Info && ok.Titulo == "Revision de Wi-Fi: sin hallazgos", "leida entera y sin problemas: Info, «sin hallazgos»");

            // Con una clave en texto plano en el XML, nada del evento la contiene.
            InstantaneaDeWifi conClave = Wifi(new[] { new PerfilCrudo("Red|rara", Xml("Red|rara", "shared", "WEP", clave: ClaveSentinela, protegida: false)) });
            NexoEvent grave = EventosDeVulnerabilidades.RevisionDeWifi(AnalizadorDeWifi.Analizar(conClave), EstadoDeLecturaWifi.Correcta);
            string todo = grave.Titulo + "|" + grave.Cuerpo + "|" + string.Join(",", grave.Campos.Select(k => k.Key + "=" + k.Value));
            Check(grave.Severidad == Severidad.Alta && !todo.Contains(ClaveSentinela), "con la clave en texto plano dentro del XML, el evento (Alta) NO la contiene", todo);
            string fila = grave.Cuerpo!.Split('\n').First(l => l.StartsWith("| Alta"));
            Check(fila.Count(c => c == '|') == 4, "una red llamada «Red|rara» no rompe la tabla (4 barras por fila)", fila);
        }
    }
}
