using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private const string Cfa = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\";

        /// <summary>
        /// Un evento de Defender con los nombres de campo del manifiesto de ESTE Windows (leidos con <c>Get-WinEvent -ListProvider</c> el
        /// 2026-11-09): 1123/1124/1127/1128 traen «Path» y «Process Name»; el 5007, «Old Value» y «New Value».
        /// </summary>
        private static string Def(int id, DateTimeOffset t, params (string N, string V)[] d)
            => Ev(id, AnalizadorDeCarpetasProtegidas.ProveedorDefender, AnalizadorDeCarpetasProtegidas.RegistroDefender, t, d);

        private static string Bloqueo(int id, DateTimeOffset t, string proceso, string ruta = @"C:\Users\ana\Documents\tesis.docx")
            => Def(id, t, ("Product Name", "Antivirus de Microsoft Defender"), ("Path", ruta), ("Process Name", proceso), ("User", @"EQUIPO\ana"));

        private static string Cambio(DateTimeOffset t, string? anterior, string? nuevo)
            => Def(5007, t, ("Old Value", anterior ?? ""), ("New Value", nuevo ?? ""));

        private static LecturaDeCarpetasProtegidas Lect(int? modo = 1, IReadOnlyList<string>? permitidas = null, bool? rtp = true, string? motor = "Normal",
                                                        IEnumerable<string>? xmls = null, int descartados = 0, IReadOnlyList<string>? extra = null, params string[] noLeido)
            => new(modo, extra ?? Array.Empty<string>(), permitidas ?? Array.Empty<string>(), rtp, motor, (xmls ?? Array.Empty<string>()).Select(P).ToList(),
                   noLeido, descartados, AnalizadorDeCarpetasProtegidas.PeriodoPorOmision);

        private static ResultadoDeAnalisis Cfa_(LecturaDeCarpetasProtegidas l) => AnalizadorDeCarpetasProtegidas.Analizar(l);

        private static string IdsCfa(ResultadoDeAnalisis r) => string.Join(",", r.Hallazgos.Select(h => h.Id + ":" + h.Severidad)) + " | no evaluado: " + string.Join(" / ", r.NoEvaluado);

        public static void ProbarRansomware()
        {
            Console.WriteLine("24. Protección contra ransomware (acceso controlado a carpetas de Defender)");
            DateTimeOffset t = AhoraAlr;

            // --- Listas tal como las da Windows ---
            Check(AnalizadorDeCarpetasProtegidas.ListaLegible(new[] { "N/A: Must be an administrator to view exclusions" }) is null,
                "«N/A: Must be an administrator...» (lo que Windows da sin administrador, comprobado en este equipo) = no leído, nunca «lista vacía»");
            Check(AnalizadorDeCarpetasProtegidas.ListaLegible(null) is null, "sin dato = no leído");
            Check(AnalizadorDeCarpetasProtegidas.ListaLegible(new[] { " C:\\a.exe ", "", null }) is { Count: 1 } l1 && l1[0] == "C:\\a.exe", "se quitan vacíos y espacios");
            Check(AnalizadorDeCarpetasProtegidas.ListaLegible(Array.Empty<string>()) is { Count: 0 }, "una lista vacía de verdad es vacía");
            Check(AnalizadorDeCarpetasProtegidas.Numero("0x1") == 1 && AnalizadorDeCarpetasProtegidas.Numero("2") == 2 && AnalizadorDeCarpetasProtegidas.Numero("0x") is null
                  && AnalizadorDeCarpetasProtegidas.Numero("activado") is null && AnalizadorDeCarpetasProtegidas.Numero("-1") is null, "valores del registro: 0x1 y 2 se leen; lo demás no se adivina");

            // --- El 5007 REAL de este equipo: es de otro ajuste de Defender y no cuenta ---
            string real;
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("evento-5007-real.xml")!)
            using (var r = new StreamReader(s)) real = r.ReadToEnd();
            EventoDeWindows e5007 = P(real);
            Check(e5007.Id == 5007 && e5007.Proveedor == AnalizadorDeCarpetasProtegidas.ProveedorDefender && e5007.Canal == AnalizadorDeCarpetasProtegidas.RegistroDefender
                  && e5007.Dato("New Value").Contains(@"\Features\Controls\386"), "un 5007 REAL se interpreta (proveedor, canal y «New Value»)");
            Check(AnalizadorDeCarpetasProtegidas.CambioDe(e5007) is null, "un 5007 real de OTRO ajuste no es un cambio de las carpetas protegidas");
            Check(AnalizadorDeCarpetasProtegidas.Relevantes(Lect(xmls: new[] { real, real })) == 0, "los 5007 de otros ajustes no cuentan como «relevantes»");

            var ca = AnalizadorDeCarpetasProtegidas.CambioDe(P(Cambio(t, Cfa + "EnableControlledFolderAccess = 0x1", Cfa + "EnableControlledFolderAccess = 0x0")));
            Check(ca is { Ajuste: "EnableControlledFolderAccess", Anterior: "0x1", Nuevo: "0x0" }, "un 5007 del CFA: ajuste, valor anterior y nuevo", ca?.ToString());
            var cp = AnalizadorDeCarpetasProtegidas.CambioDe(P(Cambio(t, null, @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications\C:\x\a = b.exe = 0x0")));
            Check(cp is { Ajuste: @"AllowedApplications\C:\x\a = b.exe", Anterior: null, Nuevo: "0x0" }, "por directiva también; y un « = » dentro de la ruta no la corta (se parte por el ÚLTIMO)", cp?.ToString());
            var cd = AnalizadorDeCarpetasProtegidas.CambioDe(P(Cambio(t, Cfa + "ProtectedFolders\\D:\\Fotos = 0x0", Cfa + "EnableControlledFolderAccess = 0x1")));
            Check(cd is { Ajuste: "EnableControlledFolderAccess", Anterior: null, Nuevo: "0x1" }, "si el viejo y el nuevo son de ajustes distintos, el viejo no se toma como valor anterior", cd?.ToString());
            Check(AnalizadorDeCarpetasProtegidas.CambioDe(P(Ev(5007, "Otro-Proveedor", AnalizadorDeCarpetasProtegidas.RegistroDefender, t, ("New Value", Cfa + "EnableControlledFolderAccess = 0x0")))) is null,
                "un 5007 de OTRO proveedor no cuenta");

            // --- Estados ---
            ResultadoDeAnalisis activo = Cfa_(Lect(1));
            Check(activo.Hallazgos.Unico() is { Id: "CFA-ACTIVO", Severidad: Severidad.Info } && activo.Completo, "activado y todo leído: una nota, completa", IdsCfa(activo));
            Check(Cfa_(Lect(1, extra: new[] { @"D:\Fotos", @"E:\Trabajo" })).Hallazgos.Unico().Detalle.Contains("2 carpetas más"), "cuenta las carpetas que añadió el usuario");
            ResultadoDeAnalisis sinAdmin = Cfa_(new LecturaDeCarpetasProtegidas(1, Array.Empty<string>(), null, true, "Normal", Array.Empty<EventoDeWindows>(), Array.Empty<string>(), 0, TimeSpan.FromDays(30)));
            Check(!sinAdmin.Completo && sinAdmin.NoEvaluado.Count == 1 && sinAdmin.NoEvaluado[0].Contains("administrador"), "activado pero sin poder ver los programas con permiso: incompleta, y dice por qué", IdsCfa(sinAdmin));
            ResultadoDeAnalisis apagadoSinAdmin = Cfa_(new LecturaDeCarpetasProtegidas(0, Array.Empty<string>(), null, true, "Normal", Array.Empty<EventoDeWindows>(), Array.Empty<string>(), 0, TimeSpan.FromDays(30)));
            Check(apagadoSinAdmin.Hallazgos.Unico() is { Id: "CFA-APAGADO", Severidad: Severidad.Media } && apagadoSinAdmin.Completo,
                "apagado: Media; la lista de permisos no importa si no hay protección (no deja la revisión incompleta)", IdsCfa(apagadoSinAdmin));
            Check(Cfa_(Lect(2)).Hallazgos.Unico() is { Id: "CFA-AUDITORIA", Severidad: Severidad.Baja }, "modo auditoría: Baja (anota, no bloquea)");
            Check(Cfa_(Lect(3)).Hallazgos.Unico() is { Id: "CFA-SOLO-DISCOS", Severidad: Severidad.Media } hd && hd.Detalle.Contains("sectores del disco"), "solo discos: Media, las carpetas no están protegidas");
            Check(Cfa_(Lect(4)).Hallazgos.Unico().Id == "CFA-SOLO-DISCOS", "auditoría de discos: igual");
            ResultadoDeAnalisis raro = Cfa_(Lect(7));
            Check(raro.Hallazgos.Count == 0 && raro.NoEvaluado.Count == 1 && raro.NoEvaluado[0].Contains("desconocido (7)"), "un valor desconocido: no evaluado, nunca «protegido»", IdsCfa(raro));
            ResultadoDeAnalisis nulo = Cfa_(Lect(null));
            Check(nulo.Hallazgos.Count == 0 && !nulo.Completo, "sin poder leer el modo: no evaluado", IdsCfa(nulo));

            // --- ¿Manda Defender? ---
            ResultadoDeAnalisis pasivo = Cfa_(Lect(0, motor: "Passive Mode"));
            Check(pasivo.Hallazgos.Unico() is { Id: "CFA-OTRO-ANTIVIRUS", Severidad: Severidad.Info } && !pasivo.Completo,
                "Defender pasivo (hay otro antivirus): una nota y «no se sabe»; no se acusa «apagado», que no aplica", IdsCfa(pasivo));
            Check(Cfa_(Lect(0, motor: "EDR Block Mode")).Hallazgos.Unico().Id == "CFA-OTRO-ANTIVIRUS", "modo EDR: igual");
            ResultadoDeAnalisis motorRaro = Cfa_(Lect(1, motor: "Modo Marciano"));
            Check(motorRaro.Hallazgos.Count == 0 && motorRaro.NoEvaluado.Count == 1 && motorRaro.NoEvaluado[0].Contains("Modo Marciano"), "un modo del motor desconocido: no evaluado", IdsCfa(motorRaro));
            Check(!Cfa_(Lect(1, motor: null)).Completo, "sin saber el modo del motor: incompleta");
            ResultadoDeAnalisis sinRtp = Cfa_(Lect(1, rtp: false));
            Check(sinRtp.Hallazgos.First() is { Id: "CFA-SIN-TIEMPO-REAL", Severidad: Severidad.Alta }, "tiempo real apagado: Alta (las carpetas no bloquean aunque estén activadas)", IdsCfa(sinRtp));
            Check(!Cfa_(Lect(1, rtp: null)).Completo, "sin saber el tiempo real: incompleta");

            // --- Apagado hace poco ---
            ResultadoDeAnalisis rec = Cfa_(Lect(0, xmls: new[] { real, Cambio(t.AddDays(-2), Cfa + "EnableControlledFolderAccess = 0x1", Cfa + "EnableControlledFolderAccess = 0x0") }));
            Check(rec.Hallazgos.Any(h => h is { Id: "CFA-APAGADO-RECIENTE", Severidad: Severidad.Media } && h.Detalle.Contains("«activado»") && h.Detalle.Contains("no dice quién")),
                "lo apagaron hace dos días: Media, con el estado anterior y sin inventar quién", IdsCfa(rec));
            Check(!Cfa_(Lect(1, xmls: new[] { Cambio(t.AddDays(-3), Cfa + "EnableControlledFolderAccess = 0x1", Cfa + "EnableControlledFolderAccess = 0x0"),
                                               Cambio(t.AddDays(-1), Cfa + "EnableControlledFolderAccess = 0x0", Cfa + "EnableControlledFolderAccess = 0x1") }))
                       .Hallazgos.Any(h => h.Id == "CFA-APAGADO-RECIENTE"), "si después lo volvieron a activar, no se avisa");
            Check(!Cfa_(Lect(0, xmls: new[] { Cambio(t.AddDays(-1), null, Cfa + "EnableControlledFolderAccess = 0x0") })).Hallazgos.Any(h => h.Id == "CFA-APAGADO-RECIENTE"),
                "sin saber el valor anterior no se afirma que «se apagó»");
            Check(Cfa_(Lect(0, xmls: new[] { Cambio(t.AddDays(-5), Cfa + "EnableControlledFolderAccess = 0x1", Cfa + "EnableControlledFolderAccess = 0x0"),
                                               Cambio(t.AddDays(-1), Cfa + "ProtectedFolders\\D:\\x = 0x0", null) }))
                       .Hallazgos.Any(h => h.Id == "CFA-APAGADO-RECIENTE"), "un cambio de OTRO ajuste después no tapa el apagado (se mira el último del modo)");

            // --- Bloqueos ---
            ResultadoDeAnalisis tres = Cfa_(Lect(1, xmls: new[]
            {
                Bloqueo(1123, t.AddHours(-1), @"C:\Program Files\Juego\juego.exe"), Bloqueo(1123, t.AddHours(-2), @"C:\PROGRAM FILES\JUEGO\JUEGO.EXE"),
                Bloqueo(1123, t.AddHours(-30), @"C:\Program Files\Juego\juego.exe")
            }));
            HallazgoDeSistema? hj = tres.Hallazgos.Where(h => h.Id == "CFA-BLOQUEO").ToList().Unico();
            Check(hj is { Severidad: Severidad.Baja, Sujeto: "juego.exe" } && hj.Detalle.Contains("3 veces") && hj.Detalle.Contains("tesis.docx") && hj.Detalle.Contains("no prueba que sea ransomware"),
                "3 bloqueos del mismo programa (sin distinguir mayúsculas): UN aviso Baja, con el recuento y el archivo", IdsCfa(tres));
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1123, t, @"C:\Users\ana\AppData\Local\Temp\x7\cifrar.exe") })).Hallazgos.Where(h => h.Id == "CFA-BLOQUEO").ToList().Unico() is { Severidad: Severidad.Alta } ht
                  && ht.Recomendacion.Contains("no le des permiso"), "bloqueado un programa desde Temp: Alta");
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1123, t, @"C:\Users\ana\Descargas\factura.exe") })).Hallazgos.Where(h => h.Id == "CFA-BLOQUEO").ToList().Unico().Severidad == Severidad.Alta, "desde Descargas (Windows en español): Alta");
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1123, t, @"C:\Users\ana\AppData\Local\Discord\app-1.0\Discord.exe") })).Hallazgos.Where(h => h.Id == "CFA-BLOQUEO").ToList().Unico().Severidad == Severidad.Baja,
                "AppData en general NO es «poco habitual» (ahí viven Discord, Teams...)");
            Check(Cfa_(Lect(2, xmls: new[] { Bloqueo(1124, t, @"C:\Program Files\Editor\ed.exe") })).Hallazgos.Where(h => h.Id == "CFA-HABRIA-BLOQUEADO").ToList().Unico() is { Severidad: Severidad.Info } ha
                  && ha.Detalle.Contains("lo dejó hacerlo"), "auditoría: un programa normal habría sido bloqueado = nota");
            Check(Cfa_(Lect(2, xmls: new[] { Bloqueo(1124, t, @"C:\Windows\Temp\a.exe") })).Hallazgos.Where(h => h.Id == "CFA-HABRIA-BLOQUEADO").ToList().Unico().Severidad == Severidad.Media, "auditoría desde Temp: Media");
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1127, t, @"C:\Program Files\Disco\part.exe", @"\Device\Harddisk0\DR0") })).Hallazgos.Where(h => h.Id == "CFA-BLOQUEO-DISCO").ToList().Unico() is { Severidad: Severidad.Media } hdk
                  && hdk.Detalle.Contains("sectores del disco"), "escribir en los sectores del disco bloqueado: Media");
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1128, t, @"C:\Program Files\Disco\part.exe") })).Hallazgos.Where(h => h.Id == "CFA-HABRIA-BLOQUEADO-DISCO").ToList().Unico().Severidad == Severidad.Baja, "...en auditoría: Baja");
            Check(Cfa_(Lect(1, xmls: new[] { Ev(1123, "Otro-Proveedor", AnalizadorDeCarpetasProtegidas.RegistroDefender, t, ("Process Name", @"C:\Temp\x.exe")) })).Hallazgos.All(h => h.Id == "CFA-ACTIVO"),
                "un 1123 de OTRO proveedor no cuenta");
            Check(Cfa_(Lect(1, xmls: new[] { Bloqueo(1123, t, ""), Bloqueo(1124, t, "") })).Hallazgos.Count(h => h.Sujeto == "(programa sin nombre)") == 2, "sin nombre de programa: se dice, no se cae");
            Check(AnalizadorDeCarpetasProtegidas.Relevantes(Lect(xmls: new[] { real, Bloqueo(1123, t, "a.exe"), Cambio(t, null, Cfa + "EnableControlledFolderAccess = 0x1") })) == 2,
                "«relevantes» = bloqueos + cambios del CFA (el 5007 de otro ajuste no)");

            // --- Programas con permiso ---
            ResultadoDeAnalisis perm = Cfa_(Lect(1, permitidas: new[] { @"C:\Program Files\Juego\juego.exe", @"C:\Users\ana\Downloads\herramienta.exe" }));
            Check(perm.Hallazgos.Where(h => h.Id == "CFA-PERMITIDO-RARO").ToList().Unico() is { Severidad: Severidad.Media, Sujeto: "herramienta.exe" } && perm.Completo,
                "con permiso y en Descargas: Media; el de Program Files no se acusa", IdsCfa(perm));
            ResultadoDeAnalisis nuevo = Cfa_(Lect(1, xmls: new[]
            {
                Cambio(t.AddDays(-1), null, Cfa + @"AllowedApplications\C:\Program Files\Editor\ed.exe = 0x0"),
                Cambio(t.AddDays(-1), null, Cfa + @"AllowedApplications\C:\Users\ana\AppData\Local\Temp\z\z.exe = 0x0"),
                Cambio(t.AddDays(-1), Cfa + @"AllowedApplications\C:\Program Files\Viejo\v.exe = 0x0", null)
            }));
            Check(nuevo.Hallazgos.Count(h => h.Id == "CFA-PERMISO-NUEVO" && h.Severidad == Severidad.Info && h.Sujeto == "ed.exe") == 1
                  && nuevo.Hallazgos.Count(h => h.Id == "CFA-PERMISO-NUEVO-RARO" && h.Severidad == Severidad.Media && h.Sujeto == "z.exe") == 1
                  && nuevo.Hallazgos.All(h => h.Sujeto != "v.exe"),
                "permiso nuevo (lo dice el 5007, aun sin administrador): nota; desde Temp: Media; un permiso QUITADO no se avisa", IdsCfa(nuevo));

            // --- Lo no leído ---
            ResultadoDeAnalisis desc = Cfa_(Lect(1, descartados: 3, noLeido: new[] { "No se pudo leer el registro de Defender (X): no se revisaron bloqueos." }));
            Check(desc.NoEvaluado.Count == 2 && desc.NoEvaluado.Any(n => n.StartsWith("3 evento(s)")) && desc.NoEvaluado.Any(n => n.Contains("no se revisaron bloqueos")),
                "eventos que no se entendieron y registro no leído: incompleta, con los motivos", IdsCfa(desc));

            // Orden: lo grave primero.
            ResultadoDeAnalisis mix = Cfa_(Lect(0, xmls: new[] { Bloqueo(1123, t, @"C:\Temp\x.exe"), Bloqueo(1124, t, @"C:\Program Files\a.exe") }));
            Check(mix.Hallazgos.First().Severidad == Severidad.Alta && mix.Hallazgos.Last().Severidad == Severidad.Info, "los hallazgos salen de más grave a menos grave", IdsCfa(mix));
        }
    }
}
