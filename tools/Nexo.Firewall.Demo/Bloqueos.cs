using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Firewall;
using Nexo.Reports.Model;

namespace Nexo.Firewall.Demo
{
    public static partial class Program
    {
        private static readonly DateTimeOffset T0 = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);

        /// <summary>Un evento 5157 con la forma que entrega Windows. Los parametros permiten romperlo a proposito.</summary>
        private static string Evento5157(
            string app = @"\device\harddiskvolume3\apps\navegador.exe", string direccion = "%%14593",
            string origen = "192.168.1.5", string puertoOrigen = "50000", string destino = "203.0.113.9",
            string puertoDestino = "443", string protocolo = "6", string filtro = "12345",
            string idEvento = "5157", string proveedor = "Microsoft-Windows-Security-Auditing",
            DateTimeOffset? cuando = null, string? extra = null)
            => "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
               $"<Provider Name='{proveedor}' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>{idEvento}</EventID>" +
               $"<TimeCreated SystemTime='{(cuando ?? T0).UtcDateTime:yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'}'/>" +
               "<Channel>Security</Channel></System><EventData>" +
               "<Data Name='ProcessId'>4242</Data>" +
               $"<Data Name='Application'>{app}</Data><Data Name='Direction'>{direccion}</Data>" +
               $"<Data Name='SourceAddress'>{origen}</Data><Data Name='SourcePort'>{puertoOrigen}</Data>" +
               $"<Data Name='DestAddress'>{destino}</Data><Data Name='DestPort'>{puertoDestino}</Data>" +
               $"<Data Name='Protocol'>{protocolo}</Data><Data Name='FilterRTID'>{filtro}</Data>" +
               (extra ?? "") + "</EventData></Event>";

        private static async Task ProbarBloqueos()
        {
            Console.WriteLine("6. Bloqueos del firewall (evento 5157): analisis, agrupacion y honestidad");

            // --- Analizador: lo bueno ---
            bool ok = ParserDeEvento5157.TryParse(Evento5157(), out ConexionBloqueada? c, out string? motivo);
            Check(ok && c is not null && c.Direccion == DireccionDeRegla.Saliente && c.IpRemota == "203.0.113.9"
                  && c.PuertoRemoto == 443 && c.Protocolo == "TCP" && c.Filtro == 12345 && c.Cuando == T0
                  && c.Aplicacion == @"\device\harddiskvolume3\apps\navegador.exe",
                  "un 5157 saliente se interpreta entero (el destino es la parte remota)", motivo);

            ok = ParserDeEvento5157.TryParse(Evento5157(direccion: "%%14592", origen: "198.51.100.7", puertoOrigen: "4444",
                                                        destino: "192.168.1.5", puertoDestino: "3389"), out c, out motivo);
            Check(ok && c!.Direccion == DireccionDeRegla.Entrante && c.IpRemota == "198.51.100.7" && c.PuertoRemoto == 4444,
                  "en uno entrante la parte remota es el ORIGEN, no el destino", motivo);

            ok = ParserDeEvento5157.TryParse(Evento5157(destino: "2001:0db8:0000:0000:0000:0000:0000:0001", protocolo: "58"), out c, out _);
            Check(ok && c!.IpRemota == "2001:db8::1" && c.Protocolo == "ICMPv6", "una IPv6 se normaliza y se reconoce el protocolo");

            ok = ParserDeEvento5157.TryParse(Evento5157(app: "-"), out c, out _);
            Check(ok && c!.Aplicacion == "(sistema)", "una aplicacion '-' (trafico del sistema) se muestra como '(sistema)'");

            ok = ParserDeEvento5157.TryParse(Evento5157(protocolo: "99"), out c, out _);
            Check(ok && c!.Protocolo == "99", "un protocolo desconocido se conserva como numero");

            // El bucle del analizador no debe saltarse el campo que sigue a otro ni quedarse en un elemento vacio.
            var termino = Task.Run(() => ParserDeEvento5157.TryParse(
                Evento5157(extra: "<Data Name='Vacio'/><Data Name='Otro'></Data>"), out _, out _));
            Check(termino.Wait(TimeSpan.FromSeconds(5)) && termino.Result, "elementos <Data/> vacios no cuelgan el analizador ni se saltan los campos siguientes");

            // --- Analizador: lo hostil. Nada de esto debe dar un bloqueo con valores a medias ---
            void Rechaza(string xml, string descripcion)
            {
                bool r = true; string? m = null;
                try { r = ParserDeEvento5157.TryParse(xml, out ConexionBloqueada? x, out m); r = r && x is not null; }
                catch (Exception e) { m = "LANZO " + e.GetType().Name; }
                Check(!r && m is not null && !m.StartsWith("LANZO", StringComparison.Ordinal), descripcion, m);
            }

            Rechaza(Evento5157(idEvento: "5156"), "otro numero de evento (5156) se rechaza");
            Rechaza(Evento5157(proveedor: "Otro-Proveedor"), "un evento que no viene de la auditoria de seguridad se rechaza");
            Rechaza(Evento5157(puertoDestino: "70000"), "un puerto fuera de 0-65535 se rechaza");
            Rechaza(Evento5157(puertoDestino: "-1"), "un puerto negativo se rechaza");
            Rechaza(Evento5157(puertoDestino: "44x"), "un puerto no numerico se rechaza");
            Rechaza(Evento5157(destino: "no-es-una-ip"), "una direccion que no es IP se rechaza");
            Rechaza(Evento5157(destino: "1.2.3.4\n## inyectado"), "una IP con texto pegado (inyeccion en la nota) se rechaza");
            Rechaza(Evento5157(direccion: "%%99999"), "una direccion de trafico desconocida se rechaza");
            Rechaza(Evento5157(app: "C:\\a.exe\n# Titulo falso"), "una ruta de aplicacion con salto de linea se rechaza entera");
            Rechaza(Evento5157(app: ""), "sin aplicacion se rechaza");
            Rechaza("", "XML vacio");
            Rechaza("<Event><System>", "XML cortado a la mitad");
            Rechaza("no es xml", "texto que no es XML");
            Rechaza("<!DOCTYPE e [<!ENTITY x SYSTEM 'file:///c:/windows/win.ini'>]>" + Evento5157(app: "&x;"),
                    "un DOCTYPE con entidad externa se rechaza (no se resuelve nada)");
            Rechaza("<!DOCTYPE e [<!ENTITY a '" + new string('A', 100) + "'><!ENTITY b '&a;&a;&a;&a;'>]>" + Evento5157(app: "&b;"),
                    "un DOCTYPE con entidades que se multiplican (bomba) se rechaza");
            Rechaza(Evento5157(app: new string('x', 70_000)), "un documento enorme se rechaza sin procesarlo");

            // Fuzz: mutaciones aleatorias del XML valido. Ninguna puede lanzar ni colgar.
            var rnd = new Random(5157);
            string baseXml = Evento5157();
            int lanzo = 0;
            var fuzz = Task.Run(() =>
            {
                for (int i = 0; i < 3000; i++)
                {
                    char[] cs = baseXml.ToCharArray();
                    for (int k = 0, n = rnd.Next(1, 6); k < n; k++) cs[rnd.Next(cs.Length)] = (char)rnd.Next(1, 300);
                    string s = new string(cs);
                    if (rnd.Next(4) == 0) s = s[..rnd.Next(s.Length)];
                    try { ParserDeEvento5157.TryParse(s, out _, out _); } catch { lanzo++; }
                }
            });
            Check(fuzz.Wait(TimeSpan.FromSeconds(30)) && lanzo == 0, "3000 XML mutados al azar: ninguno lanza ni cuelga", "lanzaron: " + lanzo);

            // --- Lector: agrupacion ---
            var fuente = new FuenteFalsa { Auditoria = true };
            fuente.Xml.AddRange(new[]
            {
                Evento5157(cuando: T0), Evento5157(cuando: T0.AddMinutes(1)), Evento5157(cuando: T0.AddMinutes(2)),
                Evento5157(destino: "198.51.100.1", cuando: T0.AddMinutes(3)),
                Evento5157(app: @"\DEVICE\HARDDISKVOLUME3\APPS\NAVEGADOR.EXE", cuando: T0.AddMinutes(4))
            });
            ResultadoDeBloqueos res = new LectorDeBloqueos(fuente).Leer(T0.AddHours(-1));
            Check(res.Grupos.Count == 2 && res.Grupos[0].Repeticiones == 4 && res.Grupos[1].Repeticiones == 1 && res.EventosLeidos == 5,
                  "5 eventos se agrupan en 2 (misma app sin distinguir mayusculas, destino y puerto), el mas repetido primero",
                  string.Join(" | ", res.Grupos.Select(g => g.IpRemota + "x" + g.Repeticiones)));
            Check(res.Grupos[0].Primero == T0 && res.Grupos[0].Ultimo == T0.AddMinutes(4), "el grupo recuerda el primero y el ultimo");
            Check(!res.PuedeAfirmarQueNoHuboBloqueos && !res.ResultadoNoConcluyente, "con bloqueos encontrados no se afirma 'sin bloqueos' y el resultado es concluyente");

            fuente = new FuenteFalsa { Auditoria = true };
            fuente.Xml.AddRange(new[] { Evento5157(cuando: T0.AddDays(-3)), Evento5157(cuando: T0) });
            res = new LectorDeBloqueos(fuente).Leer(T0.AddHours(-1));
            Check(res.Grupos.Count == 1 && res.Grupos[0].Repeticiones == 1, "un evento anterior a la ventana pedida no cuenta");

            // --- Lector: honestidad. Cada via de "no se" debe decir no se ---
            res = new LectorDeBloqueos(new FuenteFalsa { Estado = EstadoDeFuente.SinPermisos, Auditoria = null }).Leer(T0);
            Check(res.Estado == EstadoDeFuente.SinPermisos && res.Grupos.Count == 0 && !res.PuedeAfirmarQueNoHuboBloqueos && res.ResultadoNoConcluyente,
                  "sin permisos para leer el registro: NO es 'sin bloqueos'");

            res = new LectorDeBloqueos(new FuenteFalsa { Estado = EstadoDeFuente.NoDisponible, Auditoria = true }).Leer(T0);
            Check(!res.PuedeAfirmarQueNoHuboBloqueos && res.ResultadoNoConcluyente, "registro no disponible: NO es 'sin bloqueos' aunque la auditoria este activa");

            res = new LectorDeBloqueos(new FuenteFalsa { Auditoria = true }).Leer(T0);
            Check(res.PuedeAfirmarQueNoHuboBloqueos && !res.ResultadoNoConcluyente,
                  "leido, auditoria activa y cero eventos: ESTE si es 'sin bloqueos'");

            res = new LectorDeBloqueos(new FuenteFalsa { Auditoria = false }).Leer(T0);
            Check(!res.PuedeAfirmarQueNoHuboBloqueos && res.ResultadoNoConcluyente,
                  "con la auditoria apagada, cero eventos no prueba nada (Windows no los escribe)");

            res = new LectorDeBloqueos(new FuenteFalsa { Auditoria = null }).Leer(T0);
            Check(!res.PuedeAfirmarQueNoHuboBloqueos && res.ResultadoNoConcluyente, "si no se sabe si la auditoria esta activa, cero eventos no prueba nada");

            res = new LectorDeBloqueos(new FuenteFalsa { Auditoria = true, Truncada = true }).Leer(T0);
            Check(res.Truncada && !res.PuedeAfirmarQueNoHuboBloqueos, "una lectura truncada no puede afirmar 'sin bloqueos'");

            var rotos = new FuenteFalsa { Auditoria = true };
            rotos.Xml.AddRange(new[] { "<roto", "no es xml" });
            res = new LectorDeBloqueos(rotos).Leer(T0);
            Check(res.Descartados == 2 && res.Grupos.Count == 0 && !res.PuedeAfirmarQueNoHuboBloqueos,
                  "eventos que no se pudieron interpretar se cuentan como descartados y NO como 'sin bloqueos'");

            var muchos = new FuenteFalsa { Auditoria = true };
            for (int i = 0; i < 50; i++) muchos.Xml.Add(Evento5157(destino: "203.0.113." + (i + 1), cuando: T0));
            res = new LectorDeBloqueos(muchos).Leer(T0.AddHours(-1), maximo: 10);
            Check(res.EventosLeidos == 10 && res.Truncada && res.Grupos.Sum(g => g.Repeticiones) == 10,
                  "una fuente que devuelve mas del maximo pedido se recorta y se marca truncada");

            // --- Rutas de dispositivo -> C:\ ---
            var rutas = new TraductorDeRutasNt(new Dictionary<string, string>
            {
                ["C:"] = @"\Device\HarddiskVolume3",
                ["d:"] = @"\Device\HarddiskVolume30",
                ["E:"] = @"\Device\HarddiskVolume3",                                  // mismo dispositivo que C:
                ["Z:"] = @"\Device\LanmanRedirector\;Z:0000000000012345\srv\datos",   // unidad de red: se ignora
                ["S:"] = @"\??\C:\carpeta",                                           // subst: se ignora
                ["CC"] = @"\Device\HarddiskVolume9",                                  // letra mal formada
                ["F:"] = "\\Device\\Harddisk\nVolume4"                                // control: se ignora
            });
            Check(rutas.Unidades == 2, "solo se aceptan letras validas que apuntan a un \\Device\\ de un componente", "unidades: " + rutas.Unidades);
            Check(rutas.Traducir(@"\device\harddiskvolume3\apps\navegador.exe") == @"C:\apps\navegador.exe",
                  "\\device\\harddiskvolume3\\... se traduce a C:\\... sin distinguir mayusculas");
            Check(rutas.Traducir(@"\Device\HarddiskVolume30\x.exe") == @"D:\x.exe",
                  "harddiskvolume30 va a su propia letra: no lo captura el prefijo de harddiskvolume3");
            Check(rutas.Traducir(@"\Device\HarddiskVolume3x\x.exe") == @"\Device\HarddiskVolume3x\x.exe",
                  "un dispositivo que solo comparte el comienzo del nombre no se traduce");
            Check(rutas.Traducir(@"\Device\HarddiskVolume3") == @"C:\", "el dispositivo solo es la raiz de la unidad");
            Check(rutas.Traducir(@"\device\harddiskvolume7\otro.exe") == @"\device\harddiskvolume7\otro.exe",
                  "un volumen desconocido (USB desconectado) queda TAL CUAL: no se adivina la letra");
            Check(rutas.Traducir(@"\device\mup\servidor\recurso\app.exe") == @"\\servidor\recurso\app.exe",
                  "una ruta de red (\\device\\mup\\...) se traduce a UNC");
            Check(rutas.Traducir(@"\device\mup\servidor") == @"\device\mup\servidor" && rutas.Traducir(@"\device\mup\servidor\") == @"\device\mup\servidor\",
                  "una ruta de red sin recurso no se convierte en un UNC invalido");
            Check(rutas.Traducir("(sistema)") == "(sistema)" && rutas.Traducir(@"C:\ya\es.exe") == @"C:\ya\es.exe" && rutas.Traducir("") == "",
                  "lo que no es una ruta de dispositivo no se toca");
            Check(TraductorDeRutasNt.Vacio.Traducir(@"\device\harddiskvolume3\a.exe") == @"\device\harddiskvolume3\a.exe"
                  && TraductorDeRutasNt.Vacio.Traducir(@"\device\mup\s\r\a.exe") == @"\\s\r\a.exe",
                  "sin tabla de unidades solo se traducen las rutas de red");

            var mezcla = new FuenteFalsa { Auditoria = true };
            mezcla.Xml.AddRange(new[]
            {
                Evento5157(cuando: T0),
                Evento5157(app: @"C:\apps\navegador.exe", cuando: T0.AddMinutes(1)),
                Evento5157(app: @"\device\harddiskvolume7\usb.exe", cuando: T0.AddMinutes(2))
            });
            res = new LectorDeBloqueos(mezcla, rutas).Leer(T0.AddHours(-1));
            Check(res.Grupos.Count == 2 && res.Grupos[0].Aplicacion == @"C:\apps\navegador.exe" && res.Grupos[0].Repeticiones == 2
                  && res.Grupos[1].Aplicacion == @"\device\harddiskvolume7\usb.exe",
                  "el lector traduce antes de agrupar: la misma app en las dos formas es un solo grupo, y la desconocida se conserva",
                  string.Join(" | ", res.Grupos.Select(g => g.Aplicacion + "x" + g.Repeticiones)));

            // --- Registro en el vault: acotado ---
            var grandes = new FuenteFalsa { Auditoria = true };
            for (int i = 0; i < 60; i++) grandes.Xml.Add(Evento5157(destino: "203.0.113." + (i + 1), cuando: T0));
            res = new LectorDeBloqueos(grandes).Leer(T0.AddHours(-1));
            var reportes = new ReportesEnMemoria();
            int sinAnotar = await LectorDeBloqueos.RegistrarAsync(res, reportes, maximoNotas: 50).ConfigureAwait(false);
            Check(reportes.Eventos.Count == 50 && sinAnotar == 10, "60 bloqueos distintos: se anotan 50 y se informa de los 10 que no", "notas: " + reportes.Eventos.Count);
            Check(reportes.Eventos.All(e => e.Tipo == TipoEvento.BloqueoFirewall && e.Campos.ContainsKey("repeticiones")),
                  "las notas son del tipo bloqueo-firewall e incluyen cuantas veces se repitio");

            reportes = new ReportesEnMemoria();
            res = new LectorDeBloqueos(new FuenteFalsa { Auditoria = true }).Leer(T0);
            await LectorDeBloqueos.RegistrarAsync(res, reportes).ConfigureAwait(false);
            Check(reportes.Eventos.Count == 0, "si no hay bloqueos no se escribe ninguna nota");
        }
    }

    internal sealed class FuenteFalsa : IFuenteDeBloqueos
    {
        public List<string> Xml { get; } = new();
        public EstadoDeFuente Estado { get; set; } = EstadoDeFuente.Ok;
        public bool? Auditoria { get; set; }
        public bool Truncada { get; set; }

        public bool? AuditoriaActiva() => Auditoria;

        // Ignora el maximo a proposito: el lector no debe fiarse de la fuente.
        public LecturaCruda Leer(DateTimeOffset desde, int maximo)
            => new(Xml.ToList(), Estado, Estado == EstadoDeFuente.Ok ? null : "motivo de prueba", Truncada);
    }
}
