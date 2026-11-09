using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static class ExtensionesDeAlertas
    {
        /// <summary>El unico hallazgo; con cero o varios, uno vacio que hace FALLAR la comprobacion (sin tirar el programa).</summary>
        public static HallazgoDeSistema Unico(this IReadOnlyList<HallazgoDeSistema> l)
            => l.Count == 1 ? l[0] : new HallazgoDeSistema("(" + l.Count + " hallazgos)", Severidad.Info, "", "", "");
    }

    internal static partial class Program
    {
        private static readonly DateTimeOffset AhoraAlr = new(2026, 11, 9, 15, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Un evento con la forma de los de Windows (la de <c>EventRecord.ToXml()</c>) y los nombres de campo DOCUMENTADOS por Microsoft para cada
        /// número. Los de Seguridad no se pudieron sacar de este equipo sin administrador: cruzarlos con eventos reales queda pendiente (§2aj).
        /// </summary>
        private static string Ev(int id, string proveedor, string canal, DateTimeOffset t, params (string N, string V)[] datos)
            => "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='" + proveedor + "'/><EventID>" + id + "</EventID>" +
               "<TimeCreated SystemTime='" + t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") + "'/><Channel>" + canal + "</Channel><Computer>EQUIPO</Computer></System><EventData>" +
               string.Concat(datos.Select(d => "<Data Name='" + d.N + "'>" + SecurityElement.Escape(d.V) + "</Data>")) + "</EventData></Event>";

        private static string Seg(int id, DateTimeOffset t, params (string, string)[] d) => Ev(id, "Microsoft-Windows-Security-Auditing", "Security", t, d);

        private static EventoDeWindows P(string xml)
        {
            if (!ParserDeEventoDeWindows.TryParse(xml, out EventoDeWindows? e, out string? m)) throw new InvalidOperationException("no se pudo interpretar: " + m);
            return e!;
        }

        private static readonly Dictionary<Guid, Auditoria?> AuditoriaCompleta = new()
        {
            [AnalizadorDeAlertas.InicioDeSesion] = Auditoria.Exito | Auditoria.Fallo,
            [AnalizadorDeAlertas.CuentasDeUsuario] = Auditoria.Exito,
            [AnalizadorDeAlertas.GruposDeSeguridad] = Auditoria.Exito,
            [AnalizadorDeAlertas.OtrosAccesosAObjetos] = Auditoria.Exito
        };

        private static ResultadoDeAnalisis Alr(IEnumerable<string> xmls, Dictionary<Guid, Auditoria?>? auditoria = null, params string[] noLeido)
            => AnalizadorDeAlertas.Analizar(new LecturaDeAlertas(xmls.Select(P).ToList(), auditoria ?? AuditoriaCompleta, noLeido, 0, TimeSpan.FromDays(7)));

        private static string IdsAlr(ResultadoDeAnalisis r) => string.Join(",", r.Hallazgos.Select(h => h.Id + ":" + h.Severidad));

        public static void ProbarAlertas()
        {
            Console.WriteLine("23. Señales de intrusión en los registros de Windows");

            // El evento REAL de este equipo (7045 del servicio de Chrome, con el nombre del equipo cambiado).
            string real;
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("evento-7045-real.xml")!)
            using (var r = new StreamReader(s)) real = r.ReadToEnd();
            Check(ParserDeEventoDeWindows.TryParse(real, out EventoDeWindows? e7045, out string? m) && e7045!.Id == 7045 && e7045.Proveedor == "Service Control Manager" && e7045.Canal == "System"
                  && e7045.Dato("ServiceName").StartsWith("Google Chrome Elevation Service") && e7045.Dato("ImagePath").Contains(@"\Google\Chrome\Application\") && e7045.Fecha.Year == 2026,
                "un 7045 REAL se interpreta: proveedor, canal, fecha y campos", m);
            Check(e7045!.Dato("StartType") == "inicio por solicitud", "(los campos de texto vienen traducidos: por eso no se usan para decidir)");
            ResultadoDeAnalisis rr = Alr(new[] { real });
            HallazgoDeSistema? chrome = rr.Hallazgos.SingleOrDefault();
            Check(chrome is { Id: "ALR-SERVICIO-INSTALADO", Severidad: Severidad.Info } && chrome.Detalle.Contains("Es normal al instalar programas"), "el servicio real de Chrome: solo una nota (Program Files)", IdsAlr(rr));

            // Defensas del parser.
            string conDtd = "<!DOCTYPE Event [<!ENTITY a 'b'>]>" + Seg(4720, AhoraAlr, ("TargetUserName", "&a;"));
            Check(ParserDeEventoDeWindows.TryParse(Seg(4720, AhoraAlr, ("TargetUserName", "x")), out _, out _) && !ParserDeEventoDeWindows.TryParse(conDtd, out _, out _),
                "un evento válido con un DTD delante se rechaza (sin entidades: nada de expansiones ni archivos externos)");
            Check(!ParserDeEventoDeWindows.TryParse(Seg(4720, AhoraAlr).Replace("<EventID>4720</EventID>", ""), out _, out string? sinId) && sinId!.Contains("número"), "sin número de evento: se descarta");
            Check(ParserDeEventoDeWindows.TryParse(Seg(4720, AhoraAlr, ("TargetUserName", "malo\nlínea2")), out EventoDeWindows? ctl, out _) && ctl!.Dato("TargetUserName") == "malo línea2",
                "un salto de línea dentro de un nombre se limpia (no rompe la nota de Markdown)");

            // 1102: registro de Seguridad borrado (lo escribe el proveedor Eventlog en el canal Security).
            string borrado = Ev(1102, "Microsoft-Windows-Eventlog", "Security", AhoraAlr.AddHours(-3), ("SubjectUserName", "intruso"), ("SubjectDomainName", "EQUIPO"));
            ResultadoDeAnalisis rb = Alr(new[] { borrado });
            Check(rb.Hallazgos.Unico() is { Id: "ALR-REGISTRO-BORRADO", Severidad: Severidad.Alta } hb && hb.Detalle.Contains("EQUIPO\\intruso"), "alguien borró el registro de Seguridad: Alta, con la cuenta", IdsAlr(rb));
            Check(Alr(new[] { Ev(104, "Microsoft-Windows-Eventlog", "System", AhoraAlr) }).Hallazgos.Unico().Titulo.Contains("de Sistema"), "el de Sistema (104) también");
            Check(Alr(new[] { Ev(1102, "Otro-Proveedor", "Security", AhoraAlr) }).Hallazgos.Count == 0, "un 1102 de OTRO proveedor no cuenta (cualquiera puede escribir eventos con ese número)");

            string cuenta = Seg(4720, AhoraAlr.AddDays(-1), ("TargetUserName", "soporte2"), ("TargetDomainName", "EQUIPO"), ("SubjectUserName", "ana"), ("SubjectDomainName", "EQUIPO"));
            Check(Alr(new[] { cuenta }).Hallazgos.Unico() is { Id: "ALR-CUENTA-CREADA", Severidad: Severidad.Media } hc && hc.Titulo.Contains("EQUIPO\\soporte2") && hc.Detalle.Contains("EQUIPO\\ana"), "una cuenta creada: Media, quién y por quién");

            string admin = Seg(4732, AhoraAlr, ("MemberName", "-"), ("MemberSid", "S-1-5-21-1-2-3-1005"), ("TargetUserName", "Administradores"), ("TargetSid", AnalizadorDeAlertas.SidAdministradores), ("SubjectUserName", "ana"));
            Check(Alr(new[] { admin }).Hallazgos.Unico() is { Id: "ALR-ADMIN-AGREGADO", Severidad: Severidad.Alta } ha && ha.Detalle.Contains("S-1-5-21-1-2-3-1005"), "alguien añadido a Administradores (por el SID, no por el nombre traducido): Alta");
            string otroGrupo = Seg(4732, AhoraAlr, ("TargetUserName", "Administrators"), ("TargetSid", "S-1-5-32-545"), ("MemberSid", "S-1-5-21-1"));
            Check(Alr(new[] { otroGrupo }).Hallazgos.Count == 0, "un grupo LLAMADO «Administrators» pero con otro SID (Usuarios) no cuenta: manda el SID");
            Check(Alr(new[] { Seg(4732, AhoraAlr, ("TargetSid", AnalizadorDeAlertas.SidEscritorioRemoto), ("MemberName", "CN=x")) }).Hallazgos.Unico().Id == "ALR-RDP-AGREGADO", "añadido a «Usuarios de escritorio remoto»: Media");

            string adminIntegrado = Seg(4722, AhoraAlr, ("TargetUserName", "Administrador"), ("TargetSid", "S-1-5-21-9-9-9-500"));
            Check(Alr(new[] { adminIntegrado }).Hallazgos.Unico() is { Severidad: Severidad.Alta } ai && ai.Titulo.Contains("cuenta integrada de Administrador"), "se activó el Administrador integrado (RID 500): Alta");
            Check(Alr(new[] { Seg(4722, AhoraAlr, ("TargetUserName", "pepe"), ("TargetSid", "S-1-5-21-9-9-9-1001")) }).Hallazgos.Unico().Severidad == Severidad.Baja, "otra cuenta activada: Baja");

            Check(Alr(new[] { Seg(4724, AhoraAlr, ("SubjectUserSid", "S-1-5-21-1-500"), ("TargetSid", "S-1-5-21-1-1001"), ("TargetUserName", "ana")) }).Hallazgos.Unico().Id == "ALR-CLAVE-CAMBIADA", "otra cuenta cambió la contraseña: Media");
            Check(Alr(new[] { Seg(4724, AhoraAlr, ("SubjectUserSid", "S-1-5-21-1-1001"), ("TargetSid", "S-1-5-21-1-1001")) }).Hallazgos.Count == 0, "uno mismo restableciendo la suya: nada");

            var rdp = Enumerable.Range(0, 3).Select(i => Seg(4624, AhoraAlr.AddHours(-i), ("LogonType", "10"), ("TargetUserName", "ana"), ("TargetDomainName", "EQUIPO"), ("IpAddress", "203.0.113.7")))
                      .Append(Seg(4624, AhoraAlr, ("LogonType", "2"), ("TargetUserName", "ana")));
            ResultadoDeAnalisis rr2 = Alr(rdp);
            Check(rr2.Hallazgos.Unico() is { Id: "ALR-ESCRITORIO-REMOTO", Severidad: Severidad.Media } hr && hr.Detalle.StartsWith("3 veces") && hr.Detalle.Contains("203.0.113.7"),
                "3 entradas por Escritorio remoto desde la misma IP: un solo aviso con el recuento; un inicio normal (tipo 2) no cuenta", IdsAlr(rr2));

            var fallos = Enumerable.Range(0, 25).Select(i => Seg(4625, AhoraAlr.AddMinutes(-i), ("IpAddress", "198.51.100.9"), ("TargetUserName", "admin")));
            Check(Alr(fallos).Hallazgos.Unico() is { Id: "ALR-FUERZA-BRUTA", Severidad: Severidad.Media } hf && hf.Detalle.Contains("198.51.100.9 (25)"), "25 contraseñas fallidas: Media, con el origen");
            Check(Alr(Enumerable.Range(0, 120).Select(i => Seg(4625, AhoraAlr.AddMinutes(-i), ("IpAddress", "-")))).Hallazgos.Unico() is { Severidad: Severidad.Alta } hf2 && hf2.Detalle.Contains("este equipo (120)"),
                "120 fallidas: Alta (sin dirección = este equipo)");
            Check(Alr(Enumerable.Range(0, 19).Select(i => Seg(4625, AhoraAlr.AddMinutes(-i)))).Hallazgos.Count == 0, "19 fallidas (por debajo del umbral): nada (equivocarse es normal)");

            Check(Alr(new[] { Seg(4740, AhoraAlr, ("TargetUserName", "ana")) }).Hallazgos.Unico().Id == "ALR-CUENTA-BLOQUEADA", "una cuenta bloqueada por contraseñas fallidas: Media");

            string tareaRara = Seg(4698, AhoraAlr, ("TaskName", @"\Actualizador"), ("SubjectUserName", "ana"),
                ("TaskContent", "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc SQBFAFgA</Arguments></Exec></Actions></Task>"));
            Check(Alr(new[] { tareaRara }).Hallazgos.Unico() is { Id: "ALR-TAREA-CREADA", Severidad: Severidad.Media } ht && ht.Detalle.Contains("powershell.exe -w hidden -enc SQBFAFgA"),
                "una tarea con «powershell -enc»: Media, con el comando a la vista");
            string tareaNormal = Seg(4698, AhoraAlr, ("TaskName", @"\GoogleUpdater"), ("TaskContent", "<Task><Exec><Command>C:\\Program Files\\Google\\updater.exe</Command></Exec></Task>"));
            Check(Alr(new[] { tareaNormal }).Hallazgos.Unico().Severidad == Severidad.Info, "una tarea de un programa en Program Files: nota");

            string servicioRaro = Ev(7045, "Service Control Manager", "System", AhoraAlr, ("ServiceName", "WinUpdSvc"), ("ImagePath", @"C:\Users\ana\AppData\Local\Temp\svc.exe"));
            Check(Alr(new[] { servicioRaro }).Hallazgos.Unico().Severidad == Severidad.Media, "un servicio instalado desde Temp: Media");
            // Hallazgo REAL (30 días en el equipo de pruebas: 61 eventos 7045 de pocos servicios; «Claude» una vez por actualización, cada una desde
            // una carpeta con la versión en el nombre).
            var repetido = Enumerable.Range(0, 9).Select(i => Ev(7045, "Service Control Manager", "System", AhoraAlr.AddDays(-i), ("ServiceName", "Claude"), ("ImagePath", @"""C:\Program Files\Claude\app-1." + i + @"\claude-svc.exe""")))
                .Append(Ev(7045, "Service Control Manager", "System", AhoraAlr, ("ServiceName", "Claude"), ("ImagePath", @"C:\Users\ana\AppData\Local\Temp\claude-svc.exe")));
            ResultadoDeAnalisis rrep = Alr(repetido);
            Check(rrep.Hallazgos.Count == 2 && rrep.Hallazgos[0] is { Severidad: Severidad.Media } && rrep.Hallazgos[1].Titulo == "Se instaló el servicio «Claude» (9 veces)"
                  && rrep.Hallazgos[1].Detalle.StartsWith("La última, el") && rrep.Hallazgos[1].Detalle.Contains(@"app-1.0\") && rrep.Hallazgos[1].Detalle.Contains("al actualizar"),
                "el mismo servicio reinstalado 9 veces desde carpetas con versión: UN aviso con el recuento y la ruta de la última; uno con el mismo nombre desde Temp va aparte (Media)", IdsAlr(rrep));
            Check(AnalizadorDeAlertas.Raro(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe") == false && AnalizadorDeAlertas.Raro(@"C:\ProgramData\x\y.exe")
                  && AnalizadorDeAlertas.Raro("mshta.exe http://x") && !AnalizadorDeAlertas.Raro(@"""C:\Program Files\X\x.exe"" -run"), "qué cuenta como carpeta o comando poco habitual");

            // Auditoria: lo que Windows no audita es «no evaluado», con su consecuencia.
            ResultadoDeAnalisis completa = Alr(Array.Empty<string>());
            Check(completa.Completo && completa.Hallazgos.Count == 0, "con toda la auditoría activa y nada que decir: completa y sin hallazgos");
            var parcial = new Dictionary<Guid, Auditoria?>(AuditoriaCompleta) { [AnalizadorDeAlertas.InicioDeSesion] = Auditoria.Exito, [AnalizadorDeAlertas.OtrosAccesosAObjetos] = Auditoria.Nada, [AnalizadorDeAlertas.GruposDeSeguridad] = null };
            ResultadoDeAnalisis rp = Alr(Array.Empty<string>(), parcial);
            Check(!rp.Completo && rp.NoEvaluado.Count == 3 && rp.NoEvaluado.Any(n => n.Contains("intentos fallidos")) && rp.NoEvaluado.Any(n => n.StartsWith("No se pudo saber") && n.Contains("Administradores"))
                  && rp.NoEvaluado.Any(n => n.Contains("tareas programadas") && n.Contains("por omisión")),
                "sin auditar fallos, tareas, o sin saber la de grupos: cada una se dice con lo que no se puede ver", string.Join(" | ", rp.NoEvaluado));
            ResultadoDeAnalisis sinLeer = Alr(Array.Empty<string>(), null, "No se pudo leer el registro de Seguridad (hace falta ser administrador): no se revisaron las cuentas.");
            Check(!sinLeer.Completo && sinLeer.Hallazgos.Count == 0, "sin poder leer el registro: incompleta, NUNCA «sin alertas»");
            Check(!AnalizadorDeAlertas.Analizar(new LecturaDeAlertas(new List<EventoDeWindows>(), AuditoriaCompleta, Array.Empty<string>(), 3, TimeSpan.FromDays(7))).Completo, "eventos que no se pudieron interpretar: incompleta");

            ResultadoDeAnalisis todo = Alr(new[] { borrado, cuenta, admin, tareaRara, servicioRaro, real }.Concat(rdp).Concat(fallos));
            Check(todo.Hallazgos.First().Severidad == Severidad.Alta && todo.Hallazgos.Last().Severidad == Severidad.Info, "del más grave al menos grave");

            var textos = todo.Hallazgos.SelectMany(h => new[] { h.Titulo, h.Detalle, h.Recomendacion }).Concat(rp.NoEvaluado).ToList();
            var sinTilde = new Regex(@"\b(creo|anadio|anadido|anadida|sesion|intrusion|accion|direccion|contrasena|contrasenas|automatico|dias|mas|tambien|aqui|esta auditando|programo|instalo|borro|activo la|evaluo)\b");
            string[] malas = textos.Where(t => sinTilde.IsMatch(t)).ToArray();
            Check(malas.Length == 0, "textos con tildes (" + textos.Count + " textos)", string.Join(" || ", malas.Take(3)));
        }
    }
}
