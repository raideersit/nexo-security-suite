using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Alertas
{
    /// <summary>Lo que se pudo leer de los registros de Windows para buscar señales de intrusion.</summary>
    public sealed record LecturaDeAlertas(
        IReadOnlyList<EventoDeWindows> Eventos,
        /// <summary>Por subcategoria de auditoria: lo que Windows audita, o null si no se pudo saber.</summary>
        IReadOnlyDictionary<Guid, Nexo.Modules.Threats.Alertas.Auditoria?> Auditoria,
        /// <summary>Lo que no se pudo leer (registro sin permisos, truncado...). Cada texto ya explica que no se reviso.</summary>
        IReadOnlyList<string> NoLeido,
        int Descartados,
        TimeSpan Periodo);

    [Flags]
    public enum Auditoria
    {
        Nada = 0,
        Exito = 1,
        Fallo = 2
    }

    /// <summary>
    /// Señales de que alguien entro o tomo control del equipo, sacadas de los registros de Seguridad y de Sistema de Windows (solo LECTURA).
    /// Decide con datos que no dependen del idioma (numeros de evento, SID, tipos de inicio de sesion, rutas): Windows traduce los nombres de
    /// grupos y varios campos («Administradores», «inicio por solicitud»). Reglas de honestidad:
    ///  - Lo que Windows no audita no se puede ver: cada subcategoria apagada (o que no se pudo consultar) es «no evaluado», con su consecuencia.
    ///  - Un hallazgo no prueba una intrusion: muchas cosas las hace el propio usuario (crear una cuenta, instalar un programa). Se muestra y
    ///    el usuario decide. Solo «alguien borró el registro de auditoría» se trata como alerta grave por si sola.
    /// </summary>
    public static class AnalizadorDeAlertas
    {
        public static readonly Guid InicioDeSesion = new("0CCE9215-69AE-11D9-BED3-505054503030");
        public static readonly Guid CuentasDeUsuario = new("0CCE9235-69AE-11D9-BED3-505054503030");
        public static readonly Guid GruposDeSeguridad = new("0CCE9237-69AE-11D9-BED3-505054503030");
        public static readonly Guid OtrosAccesosAObjetos = new("0CCE9227-69AE-11D9-BED3-505054503030");

        public const string SidAdministradores = "S-1-5-32-544";
        public const string SidEscritorioRemoto = "S-1-5-32-555";
        public const int UmbralFuerzaBruta = 20;
        public const int UmbralFuerzaBrutaAlta = 100;

        /// <summary>Los eventos que se piden a Windows: (registro, numero).</summary>
        public static readonly IReadOnlyList<(string Registro, int Id)> Consultados = new[]
        {
            ("Security", 1102), ("Security", 4720), ("Security", 4722), ("Security", 4724), ("Security", 4728), ("Security", 4732), ("Security", 4756),
            ("Security", 4624), ("Security", 4625), ("Security", 4740), ("Security", 4698), ("System", 104), ("System", 7045)
        };

        private static readonly string[] CarpetasRaras = { @"\appdata\", @"\temp\", @"\users\public\", @"\downloads\", @"\descargas\", @"\programdata\" };
        private static readonly Regex Sospechoso = new(@"(?i)\b(powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\b|mshta(\.exe)?\b|rundll32(\.exe)?\b.*https?://|cmd(\.exe)?\s+/c\b.*https?://|certutil(\.exe)?\b.*-urlcache|bitsadmin(\.exe)?\b.*/transfer)",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        private static readonly Regex ComandoDeTarea = new(@"(?i)<Command>\s*(?<c>[^<]{1,1000})\s*</Command>\s*(?:<Arguments>\s*(?<a>[^<]{0,1000})\s*</Arguments>)?", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        public static ResultadoDeAnalisis Analizar(LecturaDeAlertas l)
        {
            if (l is null) throw new ArgumentNullException(nameof(l));
            var hs = new List<HallazgoDeSistema>();
            var no = new List<string>(l.NoLeido);
            string periodo = (int)Math.Round(l.Periodo.TotalDays) + (Math.Round(l.Periodo.TotalDays) == 1 ? " día" : " días");
            if (l.Descartados > 0) no.Add(l.Descartados + " evento(s) no se pudieron interpretar y no se revisaron.");

            void Exigir(Guid sub, Auditoria necesaria, string sinEllo)
            {
                if (!l.Auditoria.TryGetValue(sub, out Auditoria? a) || a is null) no.Add("No se pudo saber si Windows audita esto: " + sinEllo + ".");
                else if ((a.Value & necesaria) == 0) no.Add("Windows no lo está auditando: " + sinEllo + ".");
            }
            Exigir(InicioDeSesion, Auditoria.Exito, "no se pueden ver los inicios de sesión por Escritorio remoto");
            Exigir(InicioDeSesion, Auditoria.Fallo, "no se pueden ver los intentos fallidos de contraseña");
            Exigir(CuentasDeUsuario, Auditoria.Exito, "no se pueden ver cuentas creadas, activadas o con la contraseña cambiada por otro");
            Exigir(GruposDeSeguridad, Auditoria.Exito, "no se puede ver si alguien se añadió a Administradores");
            Exigir(OtrosAccesosAObjetos, Auditoria.Exito, "no se pueden ver las tareas programadas creadas (es normal: Windows no lo audita por omisión)");

            IEnumerable<EventoDeWindows> Ev(int id) => l.Eventos.Where(e => e.Id == id);
            string Quien(EventoDeWindows e) => Nombre(e, "SubjectDomainName", "SubjectUserName");
            string Fecha(EventoDeWindows e) => e.Fecha.ToLocalTime().ToString("dd-MM-yyyy HH:mm");

            // 1102 / 104: alguien borro un registro (borrar huellas).
            foreach (EventoDeWindows e in l.Eventos.Where(e => e.Proveedor == "Microsoft-Windows-Eventlog" && (e.Id == 1102 || e.Id == 104)))
            {
                string cual = e.Id == 1102 ? "de Seguridad" : "de Sistema";
                string quien = e.Id == 1102 ? Quien(e) : Nombre(e, "SubjectDomainName", "SubjectUserName");
                hs.Add(new HallazgoDeSistema("ALR-REGISTRO-BORRADO", Severidad.Alta, "Alguien borró el registro " + cual + " de Windows",
                    "El " + Fecha(e) + (quien.Length > 0 ? ", la cuenta «" + quien + "»" : "") + " vació el registro " + cual + ". Es lo que hace un intruso para borrar sus huellas (también puede hacerlo un programa de limpieza o tú mismo).",
                    "Si no fuiste tú ni un programa que conozcas, trátalo como una intrusión: cambia tus contraseñas desde otro equipo y analiza este.", quien.Length > 0 ? quien : null));
            }

            foreach (EventoDeWindows e in Ev(4720))
                hs.Add(new HallazgoDeSistema("ALR-CUENTA-CREADA", Severidad.Media, "Se creó la cuenta «" + Nombre(e, "TargetDomainName", "TargetUserName") + "»",
                    "El " + Fecha(e) + ", por la cuenta «" + Quien(e) + "».", "Si no la creaste tú, desactívala y revisa quién más tiene acceso al equipo.", e.Dato("TargetUserName")));

            foreach (EventoDeWindows e in Ev(4722))
            {
                string sid = e.Dato("TargetSid");
                bool integrada = sid.EndsWith("-500", StringComparison.Ordinal) || sid.EndsWith("-501", StringComparison.Ordinal);
                hs.Add(new HallazgoDeSistema("ALR-CUENTA-ACTIVADA", integrada ? Severidad.Alta : Severidad.Baja,
                    (integrada ? (sid.EndsWith("-500", StringComparison.Ordinal) ? "Se activó la cuenta integrada de Administrador" : "Se activó la cuenta de Invitado") : "Se activó la cuenta «" + e.Dato("TargetUserName") + "»"),
                    "El " + Fecha(e) + ", por la cuenta «" + Quien(e) + "»." + (integrada ? " Windows la trae apagada a propósito: es un blanco habitual." : ""),
                    integrada ? "Si no la activaste tú, vuelve a desactivarla y cambia tus contraseñas." : "Si no la activaste tú, revísala.", e.Dato("TargetUserName")));
            }

            foreach (EventoDeWindows e in Ev(4724).Where(e => e.Dato("SubjectUserSid") != e.Dato("TargetSid") && e.Dato("SubjectUserSid") != "S-1-5-18"))
                hs.Add(new HallazgoDeSistema("ALR-CLAVE-CAMBIADA", Severidad.Media, "Otra cuenta cambió la contraseña de «" + e.Dato("TargetUserName") + "»",
                    "El " + Fecha(e) + ", la cuenta «" + Quien(e) + "» restableció la contraseña de «" + Nombre(e, "TargetDomainName", "TargetUserName") + "».", "Si no lo hiciste tú, recupera esa cuenta y cambia la contraseña.", e.Dato("TargetUserName")));

            foreach (EventoDeWindows e in Ev(4732).Concat(Ev(4728)).Concat(Ev(4756)))
            {
                string grupo = e.Dato("TargetSid");
                string miembro = e.Dato("MemberName") is { Length: > 1 } mn && mn != "-" ? mn : e.Dato("MemberSid");
                if (grupo == SidAdministradores)
                    hs.Add(new HallazgoDeSistema("ALR-ADMIN-AGREGADO", Severidad.Alta, "Alguien se añadió al grupo Administradores",
                        "El " + Fecha(e) + ", la cuenta «" + Quien(e) + "» añadió a «" + miembro + "» al grupo Administradores. Con eso tiene control total del equipo.",
                        "Si no lo hiciste tú, quítala del grupo y revisa esa cuenta.", miembro));
                else if (grupo == SidEscritorioRemoto)
                    hs.Add(new HallazgoDeSistema("ALR-RDP-AGREGADO", Severidad.Media, "Alguien se añadió a «Usuarios de escritorio remoto»",
                        "El " + Fecha(e) + ", la cuenta «" + Quien(e) + "» añadió a «" + miembro + "»: podrá entrar al equipo a distancia.", "Si no lo hiciste tú, quítala del grupo.", miembro));
            }

            // 4624 tipo 10 = Escritorio remoto (RemoteInteractive). Un aviso por cuenta y origen.
            foreach (var g in Ev(4624).Where(e => e.Dato("LogonType") == "10").GroupBy(e => (Nombre(e, "TargetDomainName", "TargetUserName"), e.Dato("IpAddress"))))
                hs.Add(new HallazgoDeSistema("ALR-ESCRITORIO-REMOTO", Severidad.Media, "Entraron por Escritorio remoto como «" + g.Key.Item1 + "»",
                    g.Count() + (g.Count() == 1 ? " vez" : " veces") + " en los últimos " + periodo + (g.Key.Item2 is { Length: > 1 } ip && ip != "-" ? ", desde " + ip : "") + "; la última, el " + Fecha(g.OrderByDescending(x => x.Fecha).First()) + ".",
                    "Si no fuiste tú, desactiva el Escritorio remoto (Configuración > Sistema > Escritorio remoto) y cambia esa contraseña.", g.Key.Item1));

            // 4625: contraseñas fallidas. Se agrupan por origen; las locales sin direccion cuentan juntas.
            List<EventoDeWindows> fallidos = Ev(4625).ToList();
            if (fallidos.Count >= UmbralFuerzaBruta)
            {
                string origenes = string.Join(", ", fallidos.GroupBy(e => e.Dato("IpAddress") is { Length: > 1 } ip && ip != "-" ? ip : "este equipo")
                                                            .OrderByDescending(x => x.Count()).Take(4).Select(x => x.Key + " (" + x.Count() + ")"));
                hs.Add(new HallazgoDeSistema("ALR-FUERZA-BRUTA", fallidos.Count >= UmbralFuerzaBrutaAlta ? Severidad.Alta : Severidad.Media,
                    fallidos.Count + " intentos fallidos de contraseña en " + periodo,
                    "Origen: " + origenes + ". Muchos intentos seguidos son lo que hace un programa que prueba contraseñas.",
                    "Usa contraseñas largas, desactiva el Escritorio remoto si no lo usas y revisa el firewall."));
            }

            foreach (var g in Ev(4740).GroupBy(e => e.Dato("TargetUserName")))
                hs.Add(new HallazgoDeSistema("ALR-CUENTA-BLOQUEADA", Severidad.Media, "La cuenta «" + g.Key + "» se bloqueó por contraseñas fallidas",
                    g.Count() + (g.Count() == 1 ? " vez" : " veces") + " en " + periodo + ".", "Si no fuiste tú equivocándote, alguien está probando contraseñas.", g.Key));

            foreach (EventoDeWindows e in Ev(4698))
            {
                Match m = ComandoDeTarea.Match(e.Dato("TaskContent"));
                string cmd = m.Success ? (m.Groups["c"].Value.Trim() + " " + m.Groups["a"].Value.Trim()).Trim() : "";
                bool raro = Raro(cmd);
                hs.Add(new HallazgoDeSistema("ALR-TAREA-CREADA", raro ? Severidad.Media : Severidad.Info, "Se creó la tarea programada «" + e.Dato("TaskName") + "»",
                    "El " + Fecha(e) + ", por «" + Quien(e) + "»." + (cmd.Length > 0 ? " Ejecuta: «" + Recortar(cmd, 160) + "»." : "") + (raro ? " Corre desde una carpeta poco habitual o con un comando de los que usa el malware." : ""),
                    raro ? "Si no la reconoces, desactívala en el Programador de tareas y analiza ese archivo." : "Si no la reconoces, revísala en el Programador de tareas.", e.Dato("TaskName")));
            }

            // Un aviso por servicio (y por programa), no por instalacion: en un equipo real, 30 dias dieron 61 eventos 7045 de pocos servicios
            // (cada actualizacion de un programa vuelve a instalar el suyo, a menudo desde una carpeta con la version en el nombre: por eso se
            // agrupa por NOMBRE y no por ruta). Uno raro nunca se mezcla con uno normal del mismo nombre; se muestra la ruta de la ultima vez.
            foreach (var g in Ev(7045).Where(e => e.Proveedor == "Service Control Manager").GroupBy(e => (e.Dato("ServiceName"), Raro(e.Dato("ImagePath")))))
            {
                EventoDeWindows e = g.OrderByDescending(x => x.Fecha).First();
                string ruta = e.Dato("ImagePath");
                bool raro = g.Key.Item2;
                int veces = g.Count();
                hs.Add(new HallazgoDeSistema("ALR-SERVICIO-INSTALADO", raro ? Severidad.Media : Severidad.Info, "Se instaló el servicio «" + g.Key.Item1 + "»" + (veces > 1 ? " (" + veces + " veces)" : ""),
                    (veces > 1 ? "La última, el " : "El ") + Fecha(e) + ". Programa: «" + Recortar(ruta, 160) + "»." +
                    (raro ? " Está en una carpeta poco habitual para un servicio o usa un comando de los que usa el malware." : veces > 1 ? " Se repite al actualizar un programa: es normal." : " Es normal al instalar programas."),
                    raro ? "Si no lo reconoces, analiza ese archivo con Nexo y detén el servicio." : "Si no instalaste nada ese día, revísalo.", g.Key.Item1));
            }

            return new ResultadoDeAnalisis(hs.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ToList(), no);
        }

        public static bool Raro(string comando)
        {
            if (string.IsNullOrWhiteSpace(comando)) return false;
            string c = comando.ToLowerInvariant().Replace('/', '\\');
            if (CarpetasRaras.Any(x => c.Contains(x)) && !c.Contains(@"\programdata\microsoft\windows defender\")) return true;
            try { return Sospechoso.IsMatch(comando); } catch (RegexMatchTimeoutException) { return true; }
        }

        private static string Nombre(EventoDeWindows e, string dominio, string usuario)
        {
            string u = e.Dato(usuario), d = e.Dato(dominio);
            if (u.Length == 0 || u == "-") return "";
            return d.Length > 0 && d != "-" ? d + "\\" + u : u;
        }

        private static string Recortar(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";
    }
}
