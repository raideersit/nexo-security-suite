using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Inicio;

namespace Nexo.Cleanup.Demo
{
    public static partial class Program
    {
        private static readonly DateTimeOffset A0 = new(2026, 11, 2, 9, 0, 0, TimeSpan.Zero);

        /// <summary>Un evento de Diagnostics-Performance con la forma documentada. <paramref name="datos"/> va tal cual en EventData.</summary>
        private static string EventoDiag(string id, string datos, DateTimeOffset? cuando = null,
                                         string proveedor = "Microsoft-Windows-Diagnostics-Performance")
            => "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
               $"<Provider Name='{proveedor}' Guid='{{cfc18ec0-96b1-4eba-961b-622caee05b0a}}'/><EventID>{id}</EventID>" +
               $"<TimeCreated SystemTime='{(cuando ?? A0).UtcDateTime:yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'}'/>" +
               "<Channel>Microsoft-Windows-Diagnostics-Performance/Operational</Channel></System><EventData>" +
               datos + "</EventData></Event>";

        private static string Arranque100(string total = "45000", DateTimeOffset? cuando = null)
            => EventoDiag("100",
                "<Data Name='BootTsVersion'>2</Data>" +
                $"<Data Name='BootTime'>{total}</Data><Data Name='MainPathBootTime'>20000</Data>" +
                "<Data Name='BootPostBootTime'>25000</Data><Data Name='BootNumStartupApps'>12</Data>" +
                "<Data Name='BootIsDegradation'>true</Data>", cuando);

        private static string Lenta(string nombre = "OneDrive.exe", string amigable = "Microsoft OneDrive", string total = "9000",
                                    string degradacion = "4000", string id = "101", DateTimeOffset? cuando = null)
            => EventoDiag(id,
                $"<Data Name='Name'>{nombre}</Data><Data Name='FriendlyName'>{amigable}</Data>" +
                "<Data Name='Version'>24.1</Data>" +
                $"<Data Name='TotalTime'>{total}</Data><Data Name='DegradationTime'>{degradacion}</Data>", cuando);

        private static void ProbarArranque()
        {
            Console.WriteLine();
            Console.WriteLine("5b. Impacto de arranque (Diagnostics-Performance 100-103): analisis y honestidad");

            // --- Analizador: lo bueno ---
            bool ok = ParserDeEventoDeArranque.TryParse(Arranque100(), out ArranqueMedido? a, out DegradacionDeArranque? d, out string? m);
            Check(ok && d is null && a is { TotalMs: 45000, RutaPrincipalMs: 20000, PostArranqueMs: 25000, AppsDeInicio: 12, EsDegradacion: true }
                  && a.Cuando == A0, "un evento 100 se interpreta entero (tiempos en ms, apps de inicio, degradacion)", m);

            ok = ParserDeEventoDeArranque.TryParse(Lenta(), out a, out d, out m);
            Check(ok && a is null && d is { Tipo: TipoDeDegradacion.Aplicacion, Nombre: "OneDrive.exe", NombreAmigable: "Microsoft OneDrive",
                                             TotalMs: 9000, DegradacionMs: 4000 },
                  "un evento 101 es una aplicacion que retraso el arranque", m);

            ok = ParserDeEventoDeArranque.TryParse(Lenta(id: "102"), out _, out d, out _)
                 && d!.Tipo == TipoDeDegradacion.Controlador
                 && ParserDeEventoDeArranque.TryParse(Lenta(id: "103"), out _, out d, out _)
                 && d!.Tipo == TipoDeDegradacion.Servicio;
            Check(ok, "102 es un controlador y 103 un servicio");

            ok = ParserDeEventoDeArranque.TryParse(EventoDiag("100", "<Data Name='BootTime'>30000</Data>"), out a, out _, out _);
            Check(ok && a!.TotalMs == 30000 && a.RutaPrincipalMs is null && a.AppsDeInicio is null && a.EsDegradacion is null,
                  "un 100 con solo BootTime vale; lo que falta queda como 'no se sabe', no como cero");

            ok = ParserDeEventoDeArranque.TryParse(Lenta(amigable: "Falso\n# titulo"), out _, out d, out _);
            Check(ok && d!.NombreAmigable is null, "un nombre amigable con salto de linea se omite sin invalidar el evento");

            var termino = Task.Run(() => ParserDeEventoDeArranque.TryParse(
                EventoDiag("100", "<Data Name='Vacio'/><Data Name='BootTime'>1</Data>"), out ArranqueMedido? x, out _, out _) && x!.TotalMs == 1);
            Check(termino.Wait(TimeSpan.FromSeconds(5)) && termino.Result, "un <Data/> vacio no cuelga el analizador ni se salta el campo siguiente");

            // --- Analizador: lo hostil ---
            void Rechaza(string xml, string descripcion)
            {
                bool r = true; string? mo = null;
                try { r = ParserDeEventoDeArranque.TryParse(xml, out _, out _, out mo); }
                catch (Exception e) { mo = "LANZO " + e.GetType().Name; }
                Check(!r && mo is not null && !mo.StartsWith("LANZO", StringComparison.Ordinal), descripcion, mo);
            }

            Rechaza(EventoDiag("200", "<Data Name='ShutdownTime'>1</Data>"), "otro evento del mismo registro (200, apagado) se rechaza");
            Rechaza(Lenta().Replace("Microsoft-Windows-Diagnostics-Performance'", "Otro'"), "un evento de otro proveedor se rechaza");
            Rechaza(Arranque100(total: "-5"), "un tiempo negativo se rechaza");
            Rechaza(Arranque100(total: "99999999999"), "un tiempo de mas de un dia es un dato roto y se rechaza");
            Rechaza(Arranque100(total: "45 s"), "un tiempo no numerico se rechaza");
            Rechaza(EventoDiag("100", "<Data Name='MainPathBootTime'>1</Data>"), "un 100 sin BootTime se rechaza");
            Rechaza(Lenta(nombre: "malo.exe\n## inyectado"), "un nombre con salto de linea se rechaza entero");
            Rechaza(Lenta(nombre: " "), "sin nombre se rechaza");
            Rechaza(Lenta(degradacion: ""), "sin tiempo de degradacion se rechaza");
            Rechaza("<!DOCTYPE e [<!ENTITY x SYSTEM 'file:///c:/windows/win.ini'>]>" + Lenta(nombre: "&x;"),
                    "un DOCTYPE con entidad externa se rechaza");
            Rechaza(Lenta(nombre: new string('x', 70_000)), "un documento enorme se rechaza sin procesarlo");
            Rechaza("<Event><System>", "XML cortado a la mitad");

            var rnd = new Random(101);
            string baseXml = Lenta();
            int lanzo = 0;
            var fuzz = Task.Run(() =>
            {
                for (int i = 0; i < 3000; i++)
                {
                    char[] cs = baseXml.ToCharArray();
                    for (int k = 0, n = rnd.Next(1, 6); k < n; k++) cs[rnd.Next(cs.Length)] = (char)rnd.Next(1, 300);
                    string s = new string(cs);
                    if (rnd.Next(4) == 0) s = s[..rnd.Next(s.Length)];
                    try { ParserDeEventoDeArranque.TryParse(s, out _, out _, out _); } catch { lanzo++; }
                }
            });
            Check(fuzz.Wait(TimeSpan.FromSeconds(30)) && lanzo == 0, "3000 XML mutados al azar: ninguno lanza ni cuelga", "lanzaron: " + lanzo);

            // --- Analizador de arranque: agrupacion y mediana ---
            var fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.AddRange(new[]
            {
                Arranque100("40000", A0), Arranque100("60000", A0.AddDays(-1)), Arranque100("50000", A0.AddDays(-2)),
                Lenta(degradacion: "2000", cuando: A0), Lenta(nombre: "ONEDRIVE.EXE", degradacion: "6000", cuando: A0.AddDays(-1)),
                Lenta(nombre: "Teams.exe", amigable: "Teams", degradacion: "9000", cuando: A0),
                Lenta(nombre: "Spooler", amigable: "Cola de impresion", id: "103", cuando: A0)
            });
            ResultadoDeArranque res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-7));
            Check(res.Arranques.Count == 3 && res.Arranques[0].Cuando == A0 && res.MedianaMs == 50000,
                  "tres arranques, el mas reciente primero, mediana 50 s", "mediana: " + res.MedianaMs);
            DegradacionAgrupada one = res.Degradaciones[0];
            Check(res.Degradaciones.Count == 3 && one.Nombre == "OneDrive.exe" && one.Veces == 2 && one.DegradacionMediaMs == 4000
                  && one.DegradacionMaximaMs == 6000 && one.Ultima == A0,
                  "la misma app sin distinguir mayusculas es un grupo (veces, media, maximo), la mas repetida primero",
                  string.Join(" | ", res.Degradaciones.Select(g => g.Nombre + "x" + g.Veces)));
            Check(!res.PuedeAfirmarQueNadaLoRetraso, "con degradaciones no se afirma que nada retraso el arranque");

            fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.AddRange(new[] { Arranque100(cuando: A0.AddDays(-30)), Lenta(cuando: A0.AddDays(-30)), Arranque100(cuando: A0) });
            res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-7));
            Check(res.Arranques.Count == 1 && res.Degradaciones.Count == 0 && res.Descartados == 0,
                  "lo anterior a la ventana pedida no cuenta y tampoco es un descarte");

            // --- Entradas de inicio: de la linea de comando al ejecutable ---
            Check(ResultadoDeArranque.NombreDeEjecutable("\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background") == "OneDrive.exe"
                  && ResultadoDeArranque.NombreDeEjecutable("C:\\Program Files\\Teams\\Teams.exe --minimized") == "Teams.exe"
                  && ResultadoDeArranque.NombreDeEjecutable("C:\\x\\app.EXE") == "app.EXE",
                  "el ejecutable sale de la linea de comando con o sin comillas (y con espacios en la ruta)");
            Check(ResultadoDeArranque.NombreDeEjecutable("C:\\Users\\a\\Start Menu\\Programs\\Startup\\x.lnk") is null
                  && ResultadoDeArranque.NombreDeEjecutable("wscript.vbs") is null
                  && ResultadoDeArranque.NombreDeEjecutable("\"sin cierre.exe") is null
                  && ResultadoDeArranque.NombreDeEjecutable("") is null && ResultadoDeArranque.NombreDeEjecutable(".exe") is null,
                  "un acceso directo, un script o un comando roto no dan ejecutable (no se adivina)");

            fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.AddRange(new[] { Arranque100(), Lenta(), Lenta(nombre: "Spooler", id: "103") });
            res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-7));
            var onedrive = new EntradaDeInicio("OneDrive", "\"C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\onedrive.exe\" /background",
                                               OrigenDeInicio.RunUsuario, EstadoDeInicio.Habilitada);
            var spotify = new EntradaDeInicio("Spotify", "C:\\Spotify\\Spotify.exe", OrigenDeInicio.RunUsuario, EstadoDeInicio.Habilitada);
            var spooler = new EntradaDeInicio("Spooler", "C:\\x\\Spooler", OrigenDeInicio.RunUsuario, EstadoDeInicio.Habilitada);
            Check(res.ImpactoDe(onedrive) is { Veces: 1, DegradacionMediaMs: 4000 }, "una entrada de inicio encuentra su impacto por el ejecutable");
            Check(res.ImpactoDe(spotify) is null && res.ImpactoDe(spooler) is null,
                  "sin evento 101 de su ejecutable no hay dato (null, no 'cero'), y un servicio 103 no se confunde con una app");

            // --- Honestidad: cada via de "no se" dice no se ---
            res = new AnalizadorDeArranque(new FuenteDeArranqueFalsa { Estado = EstadoDeLecturaDeArranque.SinPermisos }).Leer(A0);
            Check(res.Estado == EstadoDeLecturaDeArranque.SinPermisos && !res.PuedeAfirmarQueNadaLoRetraso && res.MedianaMs is null,
                  "sin permisos: NO es 'arranque sin problemas'");

            res = new AnalizadorDeArranque(new FuenteDeArranqueFalsa()).Leer(A0);
            Check(!res.PuedeAfirmarQueNadaLoRetraso,
                  "registro vacio (sin ningun arranque medido): no prueba nada, puede que Windows no este midiendo");

            fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.Add(Arranque100(cuando: A0));
            res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-1));
            Check(res.PuedeAfirmarQueNadaLoRetraso, "con arranques medidos y ninguna degradacion: ESTE si se puede afirmar");

            fuente = new FuenteDeArranqueFalsa { Truncada = true };
            fuente.Xml.Add(Arranque100(cuando: A0));
            Check(!new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-1)).PuedeAfirmarQueNadaLoRetraso, "una lectura truncada no puede afirmarlo");

            fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.AddRange(new[] { Arranque100(cuando: A0), "<roto" });
            res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-1));
            Check(res.Descartados == 1 && !res.PuedeAfirmarQueNadaLoRetraso, "un evento sin interpretar se cuenta y tampoco deja afirmarlo");

            fuente = new FuenteDeArranqueFalsa();
            for (int i = 0; i < 30; i++) fuente.Xml.Add(Arranque100(cuando: A0));
            res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-1), maximo: 10);
            Check(res.EventosLeidos == 10 && res.Arranques.Count == 10 && res.Truncada,
                  "una fuente que devuelve mas del maximo se recorta y se marca truncada");
        }
    }

    internal sealed class FuenteDeArranqueFalsa : IFuenteDeArranque
    {
        public List<string> Xml { get; } = new();
        public EstadoDeLecturaDeArranque Estado { get; set; } = EstadoDeLecturaDeArranque.Ok;
        public bool Truncada { get; set; }

        // Ignora el maximo a proposito: el analizador no debe fiarse de la fuente.
        public LecturaDeArranque Leer(DateTimeOffset desde, int maximo)
            => new(Xml.ToList(), Estado, Estado == EstadoDeLecturaDeArranque.Ok ? null : "motivo de prueba", Truncada);
    }
}
