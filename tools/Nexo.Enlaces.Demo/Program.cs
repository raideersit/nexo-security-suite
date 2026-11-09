using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Enlaces.Demo
{
    internal static class Program
    {
        private static int _fallos;
        private static readonly DateTimeOffset Ahora = new(2026, 11, 9, 15, 0, 0, TimeSpan.Zero);

        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            if (args.Contains("--real")) return await ProbarRealAsync();

            ProbarExtractor();
            ProbarNormalizador();
            ProbarPhishingArmy();
            ProbarOpenPhishReal();
            ProbarMarcas();
            ProbarReglasDeEnlace();
            ProbarFrases();
            ProbarMensajesCompletos();
            ProbarHonestidad();
            await ProbarAlmacenAsync();
            await ProbarHttpAsync();
            ProbarTextos();

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        // ---------- utilidades ----------

        private static List<string> Relleno(int n) => Enumerable.Range(0, n).Select(i => $"sitio-falso-{i:D5}.example").ToList();

        /// <summary>Una lista con la cabecera REAL de Phishing Army (copiada de la descarga del 2026-11-09), con los dominios que se le pasen.</summary>
        private static string Army(IEnumerable<string> dominios, int? declarar = null, bool formato = true, string generada = "2026-11-09T14:00:33Z")
        {
            List<string> l = dominios.ToList();
            var sb = new StringBuilder();
            sb.Append("#\n# Title: Phishing Army | Community phishing domain blocklist\n# Aggregated from independent phishing intelligence sources.\n#\n# Expires: 4 hours\n");
            sb.Append("# Generated: " + generada + "\n# Entries: " + (declarar ?? l.Count) + "\n");
            if (formato) sb.Append("# Format: domains; version=1\n");
            sb.Append("# Harmless filtering test: amiprotected.it, www.amiprotected.it\n#\n");
            foreach (string d in l) sb.Append(d).Append('\n');
            return sb.ToString();
        }

        private static string OpenPhishReal()
        {
            using Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("openphish-2026-11-09.txt")!;
            using var r = new StreamReader(s);
            return r.ReadToEnd();
        }

        private static ListaCargada ArmyCargada(params string[] extra)
            => ParserDeListas.LeerPhishingArmy(Army(Relleno(1200).Concat(extra)), Ahora.AddHours(-1)).Lista!;

        private static ListasDePhishing Listas(params string[] extraArmy)
            => new(ArmyCargada(extraArmy), ParserDeListas.LeerOpenPhish(OpenPhishReal(), Ahora.AddHours(-1)).Lista!);

        private static EnlaceNormalizado N(string texto, OrigenDelEnlace o = OrigenDelEnlace.ConEsquema)
            => NormalizadorDeEnlaces.Normalizar(new EnlaceEncontrado(texto, 0, o), out _)!;

        private static IReadOnlyList<string> Ids(EnlaceRevisado e) => e.Hallazgos.Select(h => h.Id).ToList();

        private static string Ver(EnlaceRevisado e) => e.Veredicto + ": " + string.Join(",", Ids(e));

        // ---------- 1 ----------

        private static void ProbarExtractor()
        {
            Console.WriteLine("1. Sacar los enlaces de un mensaje");
            ExtraccionDeEnlaces x = ExtractorDeEnlaces.Extraer("BancoEstado: su cuenta sera bloqueada. Ingrese a bancoestado-cl.top/verificar.");
            Check(x.Enlaces.Count == 1 && x.Enlaces[0].Texto == "bancoestado-cl.top/verificar" && x.Enlaces[0].Origen == OrigenDelEnlace.SoloDominio,
                "un SMS con el sitio suelto: se encuentra, sin el punto final de la frase", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("(ver https://x.cl/a). Y https://es.wikipedia.org/wiki/Chile_(desambiguación)");
            Check(x.Enlaces.Select(e => e.Texto).SequenceEqual(new[] { "https://x.cl/a", "https://es.wikipedia.org/wiki/Chile_(desambiguación)" }),
                "el paréntesis de cierre de la frase se quita; el que abrió el enlace se queda", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("p.ej. lo dijo EE.UU. y la S.A. el 1.5 de hola.como");
            Check(x.Enlaces.Count == 0, "«p.ej.», «EE.UU.», «S.A.», «1.5», «hola.como» no son enlaces (terminaciones que no existen)", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("escríbeme a juan.perez@gmail.com o maria.es@empresa.cl");
            Check(x.Enlaces.Count == 0, "un correo electrónico no es un enlace", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("entra a www.bancoestado.cl o a WWW.BancoEstado.cl");
            Check(x.Enlaces.Count == 1 && x.Enlaces[0].Origen == OrigenDelEnlace.ConWww, "«www.» se reconoce y el repetido (con otras mayúsculas) cuenta una vez", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("https://bancoestado.cl@evil.com/login");
            Check(x.Enlaces.Count == 1 && x.Enlaces[0].Texto == "https://bancoestado.cl@evil.com/login", "un enlace con «@» se toma entero (no se parte en dos)", string.Join("|", x.Enlaces.Select(e => e.Texto)));

            x = ExtractorDeEnlaces.Extraer("bаncoestado.cl/clave");
            Check(x.Enlaces.Count == 1 && x.Enlaces[0].Texto.StartsWith("bаnco"), "un nombre con una letra cirílica suelto en el texto se encuentra");

            string muchos = string.Join(" ", Enumerable.Range(0, 60).Select(i => $"https://s{i}.cl/"));
            x = ExtractorDeEnlaces.Extraer(muchos);
            Check(x.Enlaces.Count == ExtractorDeEnlaces.MaximoDeEnlaces && x.DemasiadosEnlaces, "con 60 enlaces se revisan 50 y se avisa", x.Enlaces.Count.ToString());

            x = ExtractorDeEnlaces.Extraer(new string('a', 25_000) + " https://tarde.cl");
            Check(x.TextoRecortado && x.Enlaces.Count == 0, "un texto de 25 000 caracteres se recorta y se avisa");

            Check(ExtractorDeEnlaces.EsTerminacionConocida("cl") && ExtractorDeEnlaces.EsTerminacionConocida("COM") && ExtractorDeEnlaces.EsTerminacionConocida("top")
                  && !ExtractorDeEnlaces.EsTerminacionConocida("ej") && !ExtractorDeEnlaces.EsTerminacionConocida("uu") && ExtractorDeEnlaces.TerminacionesConocidas.Count > 1400,
                "la lista embebida de IANA está cargada (más de 1400 terminaciones)", ExtractorDeEnlaces.TerminacionesConocidas.Count.ToString());
        }

        // ---------- 2 ----------

        private static void ProbarNormalizador()
        {
            Console.WriteLine("2. Interpretar un enlace");
            EnlaceNormalizado ip = N("http://3232235777/x");
            Check(ip.EsIp && ip.Sitio == "192.168.1.1", "una IP escrita como número entero se reconoce como IP", ip.Sitio);
            Check(N("http://0xC0A80101/").EsIp && N("http://017700000001/").Sitio == "127.0.0.1", "también en hexadecimal y octal");

            EnlaceNormalizado arroba = N("https://bancoestado.cl@evil.com/login");
            Check(arroba.Sitio == "evil.com" && arroba.Usuario == "bancoestado.cl", "lo que va antes de «@» se separa del sitio real", arroba.Sitio + " / " + arroba.Usuario);

            EnlaceNormalizado may = N("http://BancoEstado.CL./Pago?a=1#f");
            Check(may.Sitio == "bancoestado.cl" && may.Clave == "bancoestado.cl/Pago?a=1", "mayúsculas y punto final fuera; el fragmento no cuenta", may.Clave);
            Check(N("https://a.com/b/").Clave == N("http://a.com/b").Clave && N("https://a.com/").Clave == "a.com", "la «/» final y el esquema no cambian la clave");

            EnlaceNormalizado cir = N("https://bаncoestado.cl/");
            Check(cir.Sitio == "xn--bncoestado-zqi.cl" && cir.SitioLegible == "bаncoestado.cl", "un nombre con letra cirílica: ASCII real y forma legible", cir.Sitio);
            Check(N("https://xn--bncoestado-2dj.cl/").NombreMalCodificado, "un «xn--» que no corresponde a ningún nombre se marca como mal codificado");
            Check(N("https://ejemplo.com:8443/").PuertoRaro && !N("https://ejemplo.com:443/").PuertoRaro, "puerto raro solo si no es el habitual del esquema");
            Check(NormalizadorDeEnlaces.Normalizar(new EnlaceEncontrado("https://a..b.com/", 0, OrigenDelEnlace.ConEsquema), out string? m) is null && m is not null, "un nombre inválido no se interpreta y dice por qué", m);
            Check(NormalizadorDeEnlaces.Normalizar(new EnlaceEncontrado("https://-a.com/", 0, OrigenDelEnlace.ConEsquema), out _) is null, "un nombre que empieza por «-» no es válido");
            Check(!N("bancoestado.cl", OrigenDelEnlace.SoloDominio).Cifrado && N("bancoestado.cl", OrigenDelEnlace.SoloDominio).Origen == OrigenDelEnlace.SoloDominio, "sin esquema se interpreta como http, pero se recuerda que no lo traía");
        }

        // ---------- 3 ----------

        private static void ProbarPhishingArmy()
        {
            Console.WriteLine("3. La lista de Phishing Army");
            LecturaDeLista ok = ParserDeListas.LeerPhishingArmy(Army(Relleno(1200).Append("santander-serfin.com").Append("amiprotected.it")), Ahora);
            Check(ok.Lista is { Entradas: 1202 } && ok.Motivo is null, "una lista con la cabecera real se acepta", ok.Motivo);
            Check(ok.Lista!.Generada == new DateTimeOffset(2026, 11, 9, 14, 0, 33, TimeSpan.Zero), "la fecha «Generated» se lee", ok.Lista.Generada?.ToString("O"));

            // Una descarga cortada: la cabecera dice 1202 y llegan 1201.
            LecturaDeLista cortada = ParserDeListas.LeerPhishingArmy(Army(Relleno(1201), declarar: 1202), Ahora);
            Check(cortada.Lista is null && cortada.Motivo!.Contains("incompleta"), "una lista cortada (dice 1202, llegan 1201) se rechaza entera", cortada.Motivo);
            LecturaDeLista sinFormato = ParserDeListas.LeerPhishingArmy(Army(Relleno(1200), formato: false), Ahora);
            Check(sinFormato.Lista is null && sinFormato.Motivo!.Contains("formato"), "sin «Format: domains» se rechaza (el formato cambió)", sinFormato.Motivo);
            Check(ParserDeListas.LeerPhishingArmy(Army(Relleno(50)), Ahora).Lista is null, "una lista de 50 dominios es sospechosamente pequeña");
            Check(ParserDeListas.LeerPhishingArmy("<html><body>Error</body></html>", Ahora).Lista is null, "una página de error servida con 200 se rechaza");
            Check(ParserDeListas.LeerPhishingArmy(Army(Relleno(1200).Append("ESTO NO ES UN DOMINIO")), Ahora).Lista is null, "una línea basura descuadra el recuento y se rechaza");
            Check(ParserDeListas.LeerPhishingArmy(Army(Relleno(1200), generada: "2030-01-01T00:00:00Z"), Ahora).Lista!.Generada is null, "una fecha de generación en el futuro no se cree");
            string crlf = Army(Relleno(1200)).Replace("\n", "\r\n");
            Check(ParserDeListas.LeerPhishingArmy(crlf, Ahora).Lista is { Entradas: 1200 }, "con fines de línea de Windows también se lee");

            var listas = new ListasDePhishing(ArmyCargada("santander-serfin.com", "co.uk", "amiprotected.it"), null);
            Check(listas.CoincidenciaEnPhishingArmy("feb9neejaquagiepokah.mail.santander-serfin.com") == "santander-serfin.com",
                "un subdominio REAL de la lista coincide con su dominio («…mail.santander-serfin.com»)");
            Check(listas.CoincidenciaEnPhishingArmy("www.amiprotected.it") == "amiprotected.it", "el dominio de prueba inofensivo que publica la lista coincide");
            Check(listas.CoincidenciaEnPhishingArmy("banco.co.uk") is null, "una entrada «co.uk» no marca a todo «.co.uk» (nunca se sube a una terminación)");
            Check(listas.CoincidenciaEnPhishingArmy("serfin.com") is null && listas.CoincidenciaEnPhishingArmy("santander-serfin.com.ar") is null, "no coincide por parecido ni por prefijo");
        }

        // ---------- 4 ----------

        private static void ProbarOpenPhishReal()
        {
            Console.WriteLine("4. El feed REAL de OpenPhish (2026-11-09)");
            string real = OpenPhishReal();
            LecturaDeLista l = ParserDeListas.LeerOpenPhish(real, Ahora);
            Check(l.Lista is { Entradas: 300 }, "las 300 direcciones reales se leen todas", l.Motivo ?? l.Lista?.Entradas.ToString());
            var listas = new ListasDePhishing(null, l.Lista);
            Check(listas.DireccionEnOpenPhish(N("https://www.roblox.com.ml/users/364354365772/profile").Clave), "una dirección real de la lista coincide exacta");
            Check(listas.DireccionEnOpenPhish(N("http://WWW.ROBLOX.COM.ML/users/364354365772/profile/").Clave), "con otro esquema, mayúsculas en el sitio y «/» final, también");
            Check(!listas.DireccionEnOpenPhish(N("https://www.roblox.com.ml/otra").Clave) && listas.SitioEnOpenPhish("www.roblox.com.ml"), "otra página del mismo sitio no es «exacta», pero el sitio sí figura");
            Check(!listas.DireccionEnOpenPhish(N("https://www.roblox.com.ml/USERS/364354365772/profile").Clave), "la ruta distingue mayúsculas (como el servidor)");

            Check(ParserDeListas.LeerOpenPhish("<!DOCTYPE html><html><head><title>404</title></head></html>", Ahora).Lista is null, "una página HTML servida con 200 se rechaza");
            string sucio = string.Join("\n", real.Split('\n').Take(100).Concat(Enumerable.Repeat("basura", 5)));
            Check(ParserDeListas.LeerOpenPhish(sucio, Ahora).Lista is null, "con más de un 2 % de líneas que no son direcciones se rechaza");
            Check(ParserDeListas.LeerOpenPhish(string.Join("\n", real.Split('\n').Take(10)), Ahora).Lista is null, "10 direcciones es sospechosamente poco");
        }

        // ---------- 5 ----------

        private static Imitacion? Im(string sitio, string? legible = null) => CatalogoDeMarcas.Imitada(sitio, legible ?? sitio);

        private static void ProbarMarcas()
        {
            Console.WriteLine("5. Sitios que se hacen pasar por una marca");
            Check(Im("bancoestado.cl.verificar.top") is { Tipo: TipoDeImitacion.Nombre, Marca.Nombre: "BancoEstado" }, "«bancoestado.cl.verificar.top» imita a BancoEstado");
            Check(Im("bancoestado.cl") is null && Im("www.bancoestado.cl") is null, "el dominio oficial (y su «www») no se marca");
            Check(Im("bancoestadoseguro.com") is { Tipo: TipoDeImitacion.Nombre }, "la marca larga dentro de una palabra se encuentra");
            Check(Im("santander.co.uk") is null, "santander.co.uk es oficial");
            Check(Im("santander.de") is { Tipo: TipoDeImitacion.OtroPais }, "«santander.de»: la marca con otra terminación de país (solo aviso)");
            Check(Im("santander.top") is { Tipo: TipoDeImitacion.Nombre } && Im("santander.tk") is { Tipo: TipoDeImitacion.Nombre },
                "«santander.top» y «santander.tk» NO son «otro país»: son terminaciones de estafa");
            Check(Im("paypa1-login.com") is { Tipo: TipoDeImitacion.Numeros, Marca.Nombre: "PayPal" }, "«paypa1» (un 1 por la l) imita a PayPal");
            Check(Im("bancoestad0.cl") is { Tipo: TipoDeImitacion.Numeros }, "«bancoestad0» (un 0 por la o)");
            Check(Im("rnercadolibre.com") is { Tipo: TipoDeImitacion.Numeros }, "«rn» por «m» («rnercadolibre»)");
            Check(Im("xn--bncoestado-zqi.cl", "bаncoestado.cl") is { Tipo: TipoDeImitacion.OtroAlfabeto, Marca.Nombre: "BancoEstado" }, "con una «а» cirílica imita a BancoEstado");
            Check(Im("steamcomunity.com") is { Tipo: TipoDeImitacion.UnaLetra, Marca.Nombre: "Steam" }, "«steamcomunity» (falta una m) se parece a Steam");
            Check(Im("santnader.cl") is { Tipo: TipoDeImitacion.UnaLetra }, "dos letras vecinas intercambiadas («santnader»)");
            Check(Im("bci-cl.com") is { Tipo: TipoDeImitacion.Nombre, Marca.Nombre: "BCI" } && Im("abcinema.cl") is null, "una marca corta solo cuenta como palabra entera («bci-cl» sí, «abcinema» no)");
            Check(Im("economicoutlook.org") is null && Im("outlook-verify.com") is { Marca.Nombre: "Microsoft" }, "«outlook» solo como palabra entera");
            Check(Im("correos.es") is { Tipo: TipoDeImitacion.OtroPais } && Im("correos-chile.top") is { Tipo: TipoDeImitacion.Nombre }, "«correos.es» es otro país; «correos-chile.top» imita");
            Check(Im("googleusercontent.com") is null && Im("sharepoint.com") is null, "los dominios oficiales auxiliares no se marcan");
            Check(Im("www.roblox.com.ml") is { Tipo: TipoDeImitacion.Nombre, Marca.Nombre: "Roblox" }, "un caso REAL de OpenPhish («www.roblox.com.ml») imita a Roblox");
            Check(Im("hkdiscord.antsoon.com") is { Marca.Nombre: "Discord" }, "otro REAL («hkdiscord.antsoon.com») imita a Discord");
            Check(Im("ejemplo.cl") is null && Im("municipalidad.cl") is null && Im("apply.com") is null, "sitios sin relación no se marcan («apply» no es «apple»: las cortas no van por una letra)");
            Check(CatalogoDeMarcas.MezclaAlfabetos("bаncoestado") && !CatalogoDeMarcas.MezclaAlfabetos("mañana") && !CatalogoDeMarcas.MezclaAlfabetos("пример"),
                "mezcla de alfabetos: latino+cirílico sí; «mañana» no; todo cirílico no");
            Check(CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "abd") && CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "abcd") && CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "bac")
                  && !CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "abc") && !CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "xyz") && !CatalogoDeMarcas.DistanciaDeUnaLetra("abc", "abcde"),
                "distancia de una letra: cambio, sobrante, intercambio sí; igual o lejos no");
            Check(Dominios.Terminacion("a.b.banco.com.ar") == "com.ar" && Dominios.EtiquetaPrincipal("a.b.banco.com.ar") == "banco" && Dominios.Terminacion("x.cl") == "cl", "terminaciones de dos niveles");
        }

        // ---------- 6 ----------

        private static void ProbarReglasDeEnlace()
        {
            Console.WriteLine("6. Reglas sobre cada enlace");
            ListasDePhishing listas = Listas("santander-serfin.com", "amiprotected.it");
            EnlaceRevisado R(string t, OrigenDelEnlace o = OrigenDelEnlace.ConEsquema) => AnalizadorDeMensajes.RevisarEnlace(N(t, o), listas);

            EnlaceRevisado lista = R("https://www.amiprotected.it/");
            Check(lista.Veredicto == Veredicto.Peligroso && Ids(lista).Contains("ENL-LISTA-PHISHING"), "un sitio de la lista: Peligroso", Ver(lista));
            EnlaceRevisado op = R("https://hkdiscord.antsoon.com/category/engineering");
            Check(op.Veredicto == Veredicto.Peligroso && Ids(op).Contains("ENL-LISTA-OPENPHISH") && !Ids(op).Contains("ENL-SITIO-OPENPHISH"), "una dirección exacta de OpenPhish: Peligroso (y no se repite como «mismo sitio»)", Ver(op));
            EnlaceRevisado mismo = R("https://hkdiscord.antsoon.com/otra-cosa");
            Check(Ids(mismo).Contains("ENL-SITIO-OPENPHISH"), "otra página del mismo sitio: aviso de «mismo sitio»", Ver(mismo));
            EnlaceRevisado arroba = R("https://bancoestado.cl@evil.com/login");
            Check(arroba.Veredicto == Veredicto.Peligroso && Ids(arroba).Contains("ENL-USUARIO-EN-ENLACE") && arroba.MarcaOficial is null, "el truco de la «@»: Peligroso, y NO cuenta como oficial", Ver(arroba));
            EnlaceRevisado oficial = R("https://www.bancoestado.cl/");
            Check(oficial.Veredicto == Veredicto.SinSenales && Ids(oficial).SequenceEqual(new[] { "ENL-DOMINIO-OFICIAL" }) && oficial.MarcaOficial == "BancoEstado", "el dominio oficial: sin señales, con la nota de que es oficial", Ver(oficial));
            EnlaceRevisado imita = R("bancoestado.cl.verificar.top/clave", OrigenDelEnlace.SoloDominio);
            Check(imita.Veredicto == Veredicto.Peligroso && Ids(imita).Contains("ENL-IMITA-MARCA") && Ids(imita).Contains("ENL-TERMINACION") && !Ids(imita).Contains("ENL-SIN-CIFRADO"),
                "imita a una marca: Peligroso; la terminación se suma; sin esquema NO se acusa de «http»", Ver(imita));
            EnlaceRevisado cir = R("https://bаncoestado.cl/");
            Check(cir.Veredicto == Veredicto.Peligroso && Ids(cir).Contains("ENL-MEZCLA-ALFABETOS") && Ids(cir).Contains("ENL-IMITA-MARCA"), "letra cirílica: mezcla de alfabetos e imitación", Ver(cir));
            EnlaceRevisado tilde = R("https://mañana.cl/");
            Check(tilde.Veredicto == Veredicto.SinSenales && Ids(tilde).SequenceEqual(new[] { "ENL-LETRAS-ESPECIALES" }), "«mañana.cl» solo lleva una nota baja (la ñ es normal)", Ver(tilde));
            EnlaceRevisado ip = R("http://192.168.1.1:8080/banco");
            Check(ip.Veredicto == Veredicto.Sospechoso && Ids(ip).Contains("ENL-IP") && Ids(ip).Contains("ENL-PUERTO") && Ids(ip).Contains("ENL-SIN-CIFRADO"), "una IP con puerto y http: Sospechoso", Ver(ip));
            EnlaceRevisado corto = R("https://bit.ly/3abcde");
            Check(corto.Veredicto == Veredicto.Sospechoso && Ids(corto).Contains("ENL-ACORTADOR"), "un acortador: Sospechoso", Ver(corto));
            EnlaceRevisado parecido = R("https://steamcomunity.com/gift");
            Check(parecido.Veredicto == Veredicto.Sospechoso && Ids(parecido).Contains("ENL-PARECIDO-A-MARCA"), "a una letra de Steam: Sospechoso", Ver(parecido));
            EnlaceRevisado otroPais = R("https://santander.de/");
            Check(otroPais.Veredicto == Veredicto.SinSenales && Ids(otroPais).Contains("ENL-MARCA-OTRO-PAIS"), "la marca en otro país: solo nota", Ver(otroPais));
            EnlaceRevisado normal = R("https://municipalidad.cl/tramites");
            Check(normal.Veredicto == Veredicto.SinSenales && normal.Hallazgos.Count == 0, "un sitio normal sin nada: sin señales y sin notas", Ver(normal));
            EnlaceRevisado mal = R("https://xn--bncoestado-2dj.cl/");
            Check(Ids(mal).Contains("ENL-NOMBRE-MAL-CODIFICADO") && mal.Veredicto == Veredicto.Sospechoso, "un «xn--» inválido: Sospechoso", Ver(mal));
        }

        // ---------- 7 ----------

        private static RevisionDeMensaje A(string texto, ListasDePhishing? l = null) => AnalizadorDeMensajes.Analizar(texto, l ?? Listas(), Ahora);

        private static HallazgoDeSistema? H(RevisionDeMensaje r, string id) => r.Analisis.Hallazgos.FirstOrDefault(h => h.Id == id);

        private static void ProbarFrases()
        {
            Console.WriteLine("7. Frases típicas de estafa (solo español)");
            RevisionDeMensaje pide = A("Estimado cliente, actualice sus datos y su clave en https://seguridad-clientes.com");
            Check(H(pide, "MSJ-PIDE-CLAVES")?.Severidad == Severidad.Alta && pide.Veredicto == Veredicto.Peligroso, "pide claves y trae un enlace: Alta", string.Join(",", pide.Analisis.Hallazgos.Select(h => h.Id + ":" + h.Severidad)));
            RevisionDeMensaje sinEnlace = A("Hola, soy del banco, me dicta el código de verificación que le llegó?");
            Check(H(sinEnlace, "MSJ-PIDE-CLAVES")?.Severidad == Severidad.Media, "pide un código sin enlace (estafa por teléfono): Media");
            RevisionDeMensaje real = A("BancoEstado: Nunca te pediremos tu clave por SMS ni por teléfono. Más información en https://www.bancoestado.cl");
            Check(H(real, "MSJ-PIDE-CLAVES")?.Severidad == Severidad.Baja && real.Veredicto == Veredicto.SinSenales,
                "un aviso real del banco (advierte y el enlace es oficial): solo Baja, sin señales", string.Join(",", real.Analisis.Hallazgos.Select(h => h.Id + ":" + h.Severidad)));
            RevisionDeMensaje copiaAviso = A("Nunca te pediremos tu clave. Valida tu cuenta aquí: bancoestado-validacion.top");
            Check(copiaAviso.Veredicto == Veredicto.Peligroso && H(copiaAviso, "MSJ-PIDE-CLAVES")?.Severidad == Severidad.Media,
                "un estafador que copia «nunca te pediremos» sigue saliendo Peligroso por el enlace", string.Join(",", copiaAviso.Analisis.Hallazgos.Select(h => h.Id + ":" + h.Severidad)));
            RevisionDeMensaje presion = A("ÚLTIMO AVISO: su paquete está retenido en aduana. Pague hoy mismo.");
            Check(H(presion, "MSJ-PRESION")?.Severidad == Severidad.Media && H(presion, "MSJ-PRESION")!.Detalle.Contains("«ultimo aviso»"), "urgencia + pago: Media, con las frases encontradas (sin tildes, como se buscaron)", H(presion, "MSJ-PRESION")?.Detalle);
            RevisionDeMensaje entera = A("Su cuenta será bloqueada y su envío está retenido.");
            Check(H(entera, "MSJ-PRESION") is { } he && he.Detalle.Contains("«sera bloqueada»") && he.Detalle.Contains("retenido»") && !he.Detalle.Contains("bloquead»"),
                "las frases citadas llevan la palabra entera («sera bloqueada», no «sera bloquead»)", H(entera, "MSJ-PRESION")?.Detalle);
            RevisionDeMensaje uno = A("Le recordamos su pago pendiente del mes.");
            Check(H(uno, "MSJ-PRESION")?.Severidad == Severidad.Baja && uno.Veredicto == Veredicto.SinSenales, "una sola táctica: Baja (los reales también la usan)");
            RevisionDeMensaje nada = A("Hola, nos vemos mañana a las 5 en la plaza.");
            Check(nada.Analisis.Hallazgos.Count == 0 && nada.Veredicto == Veredicto.SinSenales && nada.Analisis.Completo, "un mensaje normal sin enlaces: nada");
            RevisionDeMensaje claveSol = A("La clave de sol es la primera figura del pentagrama");
            Check(H(claveSol, "MSJ-PIDE-CLAVES")?.Severidad == Severidad.Media, "«clave» suelta cuenta (límite conocido: no se entiende el sentido)");
            RevisionDeMensaje ingles = A("URGENT: verify your password at https://example.com");
            Check(H(ingles, "MSJ-PIDE-CLAVES") is null && H(ingles, "MSJ-PRESION") is null, "en inglés no se reconoce ninguna frase (solo español, decisión del proyecto)");
            Check(AnalizadorDeMensajes.SinTildes("ÚLTIMO Código Contraseña") == "ultimo codigo contrasena", "la búsqueda ignora tildes, eñes y mayúsculas");
        }

        // ---------- 8 ----------

        private static void ProbarMensajesCompletos()
        {
            Console.WriteLine("8. Mensajes completos");
            RevisionDeMensaje correos = A("Correos de Chile: su paquete esta retenido. Pague el costo de envio en correoschile-pagos.top hoy mismo o sera devuelto.");
            Check(correos.Veredicto == Veredicto.Peligroso && correos.Enlaces.Count == 1 && H(correos, "ENL-IMITA-MARCA") is not null && H(correos, "MSJ-PRESION")?.Severidad == Severidad.Media,
                "SMS falso de Correos: Peligroso (imita a Correos + presión)", string.Join(",", correos.Analisis.Hallazgos.Select(h => h.Id)));
            Check(correos.Analisis.Hallazgos.First().Severidad == Severidad.Alta, "los hallazgos van del más grave al menos grave");
            RevisionDeMensaje dos = A("Mira https://www.bancoestado.cl y también https://www.amiprotected.it", Listas("amiprotected.it"));
            Check(dos.Veredicto == Veredicto.Peligroso && dos.Enlaces[0].Veredicto == Veredicto.SinSenales && dos.Enlaces[1].Veredicto == Veredicto.Peligroso,
                "con un enlace bueno y uno malo: el mensaje es Peligroso y cada enlace tiene el suyo");
            Check(dos.Enlaces.All(e => e.Hallazgos.All(h => h.Sujeto == e.Sitio || h.Sujeto!.Contains(e.Sitio))), "cada hallazgo de enlace lleva su sitio como sujeto");
        }

        // ---------- 9 ----------

        private static void ProbarHonestidad()
        {
            Console.WriteLine("9. Honestidad: sin listas, listas viejas, lo que no se pudo leer");
            RevisionDeMensaje sin = AnalizadorDeMensajes.Analizar("Revisa https://ejemplo.cl/x", ListasDePhishing.Vacias, Ahora);
            Check(!sin.Analisis.Completo && sin.Analisis.NoEvaluado.Count == 2 && sin.Analisis.NoEvaluado.All(n => n.Contains("Actualizar listas")),
                "sin listas: incompleta, y dice cuáles faltan y cómo bajarlas", string.Join(" | ", sin.Analisis.NoEvaluado));
            RevisionDeMensaje sinEnlaces = AnalizadorDeMensajes.Analizar("Hola, ¿cómo estás?", ListasDePhishing.Vacias, Ahora);
            Check(sinEnlaces.Analisis.Completo, "sin enlaces, que falten las listas no importa (no había nada que cruzar)");

            var vieja = ParserDeListas.LeerPhishingArmy(Army(Relleno(1200), generada: "2026-10-20T00:00:00Z"), Ahora.AddDays(-1)).Lista!;
            RevisionDeMensaje rv = AnalizadorDeMensajes.Analizar("https://ejemplo.cl", new ListasDePhishing(vieja, ParserDeListas.LeerOpenPhish(OpenPhishReal(), Ahora).Lista), Ahora);
            Check(!rv.Analisis.Completo && rv.Analisis.NoEvaluado.Single().Contains("20 días"), "una lista generada hace 20 días: incompleta, con su antigüedad (manda la fecha de la lista, no la de descarga)", string.Join(" | ", rv.Analisis.NoEvaluado));

            RevisionDeMensaje ilegible = A("entra a https://a..b.com/x ya");
            Check(ilegible.EnlacesIlegibles == 1 && !ilegible.Analisis.Completo && ilegible.Analisis.NoEvaluado[0].Contains("a..b.com"), "un enlace que no se pudo interpretar se nombra y deja la revisión incompleta");
            Check(A(new string('x', 25_000)).Analisis.NoEvaluado.Any(n => n.Contains("primeros 20.000")), "un texto recortado lo dice (con el número en formato chileno)",
                string.Join(" | ", A(new string('x', 25_000)).Analisis.NoEvaluado));
        }

        // ---------- 10 ----------

        private sealed class DescargaFalsa : IDescargaDeListas
        {
            public readonly Dictionary<FuenteDeLista, RespuestaHttp> Respuestas = new();
            public int Llamadas;

            public Task<RespuestaHttp> DescargarAsync(FuenteDeLista fuente, CancellationToken ct)
            {
                Llamadas++;
                return Task.FromResult(Respuestas[fuente]);
            }
        }

        private static async Task ProbarAlmacenAsync()
        {
            Console.WriteLine("10. Guardar y cargar las listas");
            string carpeta = Path.Combine(Path.GetTempPath(), "nexo-enlaces-" + Guid.NewGuid().ToString("N"));
            try
            {
                var almacen = new AlmacenDeListas(carpeta);
                CargaDeListas vacia = almacen.Cargar();
                Check(vacia.Listas.PhishingArmy is null && vacia.Listas.OpenPhish is null && vacia.Avisos.Count == 0, "sin nada guardado: sin listas y sin avisos");

                string armyBuena = Army(Relleno(1200).Append("amiprotected.it"));
                var d = new DescargaFalsa();
                d.Respuestas[FuenteDeLista.PhishingArmy] = new RespuestaHttp(200, armyBuena);
                d.Respuestas[FuenteDeLista.OpenPhish] = new RespuestaHttp(200, OpenPhishReal());
                ResultadoDeActualizacion r1 = await almacen.ActualizarAsync(d, ListasDePhishing.Vacias, Ahora);
                Check(r1.Fuentes.All(f => f.Actualizada) && r1.Listas.PhishingArmy!.Entradas == 1201 && r1.Listas.OpenPhish!.Entradas == 300, "las dos se descargan y se aceptan",
                    string.Join(" | ", r1.Fuentes.Select(f => f.Mensaje)));
                CargaDeListas recarga = new AlmacenDeListas(carpeta).Cargar();
                Check(recarga.Listas.PhishingArmy?.Entradas == 1201 && recarga.Listas.OpenPhish?.Entradas == 300 && recarga.Listas.OpenPhish.Descargada == Ahora,
                    "al volver a abrir se cargan de disco, con su fecha de descarga", recarga.Listas.OpenPhish?.Descargada.ToString("O"));
                Check(!Directory.GetFiles(carpeta, "*.tmp").Any(), "no quedan archivos temporales");

                int antes = d.Llamadas;
                ResultadoDeActualizacion r2 = await almacen.ActualizarAsync(d, r1.Listas, Ahora.AddMinutes(20));
                Check(d.Llamadas == antes && r2.Fuentes.All(f => !f.Actualizada && f.Mensaje.Contains("al día")), "a los 20 minutos no se vuelve a pedir (cortesía con los servidores)",
                    string.Join(" | ", r2.Fuentes.Select(f => f.Mensaje)));

                byte[] enDisco = File.ReadAllBytes(Path.Combine(carpeta, "phishing-army.txt"));
                d.Respuestas[FuenteDeLista.PhishingArmy] = new RespuestaHttp(200, Army(Relleno(1100), declarar: 1201));
                d.Respuestas[FuenteDeLista.OpenPhish] = new RespuestaHttp(503, "");
                ResultadoDeActualizacion r3 = await almacen.ActualizarAsync(d, r1.Listas, Ahora.AddHours(2));
                Check(r3.Fuentes.All(f => !f.Actualizada) && r3.Listas.PhishingArmy!.Entradas == 1201 && r3.Listas.OpenPhish!.Entradas == 300,
                    "una descarga cortada y un 503: se sigue usando la lista anterior", string.Join(" | ", r3.Fuentes.Select(f => f.Mensaje)));
                Check(r3.Fuentes[0].Mensaje.Contains("no se aceptó") && r3.Fuentes[1].Mensaje.Contains("503") && r3.Fuentes.All(f => f.Mensaje.Contains("anterior")), "y dice por qué");
                Check(File.ReadAllBytes(Path.Combine(carpeta, "phishing-army.txt")).SequenceEqual(enDisco), "la lista mala NO pisó a la buena en el disco");

                d.Respuestas[FuenteDeLista.PhishingArmy] = new RespuestaHttp(null, "", "sin conexión (SocketException)");
                ResultadoDeActualizacion r4 = await almacen.ActualizarAsync(d, ListasDePhishing.Vacias, Ahora.AddHours(3));
                Check(r4.Fuentes[0].Mensaje.Contains("sin conexión") && r4.Fuentes[0].Mensaje.Contains("No hay ninguna lista anterior"), "sin red y sin lista anterior: lo dice");

                File.WriteAllText(Path.Combine(carpeta, "phishing-army.txt"), armyBuena.Substring(0, armyBuena.Length / 2));
                CargaDeListas dañada = new AlmacenDeListas(carpeta).Cargar();
                Check(dañada.Listas.PhishingArmy is null && dañada.Listas.OpenPhish is not null && dañada.Avisos.Single().Contains("Phishing Army"),
                    "una lista guardada que se dañó no se usa, y se avisa (la otra sigue)", string.Join(" | ", dañada.Avisos));
            }
            finally
            {
                try { Directory.Delete(carpeta, true); } catch (IOException) { }
            }
        }

        // ---------- 11 ----------

        private sealed class ManejadorFalso : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _f;
            public HttpRequestMessage? Ultima;
            public ManejadorFalso(Func<HttpRequestMessage, HttpResponseMessage> f) => _f = f;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Ultima = request;
                return Task.FromResult(_f(request));
            }
        }

        private static async Task ProbarHttpAsync()
        {
            Console.WriteLine("11. La descarga por HTTP");
            var m = new ManejadorFalso(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("hola") });
            using (var h = new DescargaDeListasHttp(m))
            {
                RespuestaHttp r = await h.DescargarAsync(FuenteDeLista.OpenPhish, CancellationToken.None);
                Check(r.Estado == 200 && r.Texto == "hola", "un 200 devuelve el texto");
                Check(m.Ultima!.RequestUri == DescargaDeListasHttp.OpenPhish && m.Ultima.RequestUri!.Scheme == "https" && m.Ultima.Headers.UserAgent.ToString() == "Nexo-Security-Suite",
                    "pide la dirección fija, por HTTPS, con un User-Agent genérico", m.Ultima.RequestUri + " / " + m.Ultima.Headers.UserAgent);
                await h.DescargarAsync(FuenteDeLista.PhishingArmy, CancellationToken.None);
                Check(m.Ultima!.RequestUri == DescargaDeListasHttp.PhishingArmy, "cada fuente a su dirección");
            }
            using (var h = new DescargaDeListasHttp(new ManejadorFalso(_ =>
                   {
                       var resp = new HttpResponseMessage(HttpStatusCode.Found);
                       resp.Headers.Location = new Uri("https://otro-sitio.example/");
                       return resp;
                   })))
                Check((await h.DescargarAsync(FuenteDeLista.OpenPhish, CancellationToken.None)).Estado == 302, "una redirección se devuelve como 302 (no se sigue)");
            using (var h = new DescargaDeListasHttp(new ManejadorFalso(_ =>
                   {
                       var c = new ByteArrayContent(new byte[10]);
                       c.Headers.ContentLength = (long)ParserDeListas.MaximoDeCaracteres + 1;
                       return new HttpResponseMessage(HttpStatusCode.OK) { Content = c };
                   })))
            {
                RespuestaHttp g = await h.DescargarAsync(FuenteDeLista.PhishingArmy, CancellationToken.None);
                Check(g.Estado is null && g.Error!.Contains("demasiado grande"), "una respuesta que anuncia más del tope se corta sin leerla");
            }
            using (var h = new DescargaDeListasHttp(new ManejadorFalso(_ => throw new HttpRequestException("x", new System.Net.Sockets.SocketException()))))
            {
                RespuestaHttp s = await h.DescargarAsync(FuenteDeLista.PhishingArmy, CancellationToken.None);
                Check(s.Estado is null && s.Error!.StartsWith("sin conexión"), "sin red: «sin conexión», no una excepción", s.Error);
            }
        }

        // ---------- 12 ----------

        private static void ProbarTextos()
        {
            Console.WriteLine("12. Textos con tildes");
            var textos = new List<string>();
            ListasDePhishing listas = Listas("amiprotected.it");
            foreach (string t in new[]
            {
                "https://www.amiprotected.it/ https://hkdiscord.antsoon.com/category/engineering https://hkdiscord.antsoon.com/x https://bancoestado.cl@evil.com/a",
                "https://www.bancoestado.cl/ bancoestado.cl.verificar.top https://bаncoestado.cl/ https://mañana.cl/ http://192.168.1.1:8080/ https://bit.ly/x",
                "https://steamcomunity.com/ https://santander.de/ https://xn--bncoestado-2dj.cl/ paypa1-login.com",
                "Actualice su clave. ÚLTIMO AVISO: paquete retenido, ganaste un premio. https://a..b.com"
            })
            {
                RevisionDeMensaje r = AnalizadorDeMensajes.Analizar(t, listas, Ahora);
                textos.AddRange(r.Analisis.Hallazgos.SelectMany(h => new[] { h.Titulo, h.Detalle, h.Recomendacion }));
                textos.AddRange(r.Analisis.NoEvaluado);
            }
            textos.AddRange(AnalizadorDeMensajes.Analizar("https://x.cl", ListasDePhishing.Vacias, Ahora).Analisis.NoEvaluado);
            var sinTilde = new Regex(@"\b(numero|numeros|pagina|paginas|direccion|codigo|codigos|telefono|aplicacion|dias|segun|tambien|mas alla|mas grave|todavia|estafa ya|cirilica|cirilicas|griega|leelo|interpretacion|habitual|ingles|espanol|valido|pais|terminacion|clasico|comun|enganar|asi que)\b");
            string[] malas = textos.Where(t => sinTilde.Matches(t).Cast<Match>().Any(m => m.Value is not ("habitual" or "estafa ya" or "mas alla"))).ToArray();
            Check(textos.Count > 60 && malas.Length == 0, "ninguna palabra que lleva tilde aparece sin ella (" + textos.Count + " textos)", string.Join(" || ", malas.Take(3)));
            // Lo citado entre «» es lo que escribio el usuario (puede traer «..»): no cuenta.
            static string SinCitas(string t) => Regex.Replace(t, "«[^»]*»", "«»");
            Check(textos.All(t => !SinCitas(t).Contains("  ") && !SinCitas(t).Contains(" .") && !SinCitas(t).Contains("..")), "sin dobles espacios ni puntos sueltos (fuera de lo citado)",
                string.Join(" || ", textos.Where(t => SinCitas(t).Contains("  ") || SinCitas(t).Contains(" .") || SinCitas(t).Contains("..")).Take(3)));
            Check(textos.All(t => !Regex.IsMatch(t, @"\bseguro\b", RegexOptions.IgnoreCase) || t.Contains("Lo más seguro")), "ningún texto dice que algo es «seguro»", string.Join(" || ", textos.Where(t => Regex.IsMatch(t, @"\bseguro\b", RegexOptions.IgnoreCase)).Take(3)));
        }

        // ---------- real ----------

        private static async Task<int> ProbarRealAsync()
        {
            Console.WriteLine("PRUEBA REAL: descarga las dos listas (sale a Internet) y las valida.");
            string carpeta = Path.Combine(Path.GetTempPath(), "nexo-enlaces-real-" + Guid.NewGuid().ToString("N"));
            try
            {
                using var http = new DescargaDeListasHttp();
                var almacen = new AlmacenDeListas(carpeta);
                DateTimeOffset ahora = DateTimeOffset.UtcNow;
                ResultadoDeActualizacion r = await almacen.ActualizarAsync(http, ListasDePhishing.Vacias, ahora);
                foreach (ActualizacionDeFuente f in r.Fuentes) Console.WriteLine("  " + f.Mensaje);
                Check(r.Fuentes.All(f => f.Actualizada), "las dos listas reales se descargan y pasan la validación");
                ListaCargada? army = r.Listas.PhishingArmy;
                Check(army is { Entradas: > 10_000 } && army.Generada is not null && army.Antiguedad(ahora) < TimeSpan.FromDays(2),
                    "Phishing Army: más de 10 000 dominios y generada hace menos de 2 días", army is null ? "sin lista" : army.Entradas + " / " + army.Generada?.ToString("O"));
                // La lista real trae «amiprotected.it» Y «www.amiprotected.it» como entradas propias: gana la mas especifica.
                Check(r.Listas.CoincidenciaEnPhishingArmy("www.amiprotected.it") == "www.amiprotected.it" && r.Listas.CoincidenciaEnPhishingArmy("otra.amiprotected.it") == "amiprotected.it",
                    "el dominio de prueba inofensivo que publica Phishing Army coincide (exacto, y un subdominio por su padre)");
                Check(r.Listas.OpenPhish is { Entradas: >= ParserDeListas.MinimoOpenPhish }, "OpenPhish: al menos " + ParserDeListas.MinimoOpenPhish + " direcciones", r.Listas.OpenPhish?.Entradas.ToString());
                CargaDeListas c = new AlmacenDeListas(carpeta).Cargar();
                Check(c.Avisos.Count == 0 && c.Listas.PhishingArmy?.Entradas == army?.Entradas, "guardadas en disco y vueltas a cargar iguales");

                // Una direccion cualquiera de la lista de HOY debe salir Peligrosa: las reglas y la lista trabajan juntas.
                string hoy = File.ReadAllLines(Path.Combine(carpeta, "openphish.txt")).First(l => l.StartsWith("http", StringComparison.Ordinal));
                RevisionDeMensaje rev = AnalizadorDeMensajes.Analizar("Mira esto: " + hoy, r.Listas, ahora);
                Check(rev.Veredicto == Veredicto.Peligroso && rev.Analisis.Completo, "una dirección de la lista de hoy, pegada en un mensaje, sale Peligrosa y la revisión está completa", hoy);
                var tiempo = System.Diagnostics.Stopwatch.StartNew();
                CargaDeListas c2 = new AlmacenDeListas(carpeta).Cargar();
                tiempo.Stop();
                Console.WriteLine("  (cargar las listas reales de disco: " + tiempo.ElapsedMilliseconds + " ms)");
                Check(c2.Listas.PhishingArmy is not null && tiempo.Elapsed < TimeSpan.FromSeconds(5), "cargar de disco tarda menos de 5 s");
            }
            finally
            {
                try { Directory.Delete(carpeta, true); } catch (IOException) { }
            }
            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }
    }
}
