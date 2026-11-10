using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Ransomware
{
    /// <summary>
    /// Lo que se leyo de Windows sobre el «Acceso controlado a carpetas» (Controlled Folder Access, CFA) de Microsoft Defender: la capa
    /// anti-ransomware que SI bloquea de verdad (la de Nexo no puede sin un minifiltro, Salida 0 §2). Todo es SOLO LECTURA.
    /// </summary>
    /// <param name="ModoCrudo">El valor de <c>EnableControlledFolderAccess</c> (0-4), o null si no se pudo leer.</param>
    /// <param name="CarpetasExtra">Carpetas que el usuario añadio a las protegidas (las de serie no se listan), o null si no se pudo leer.</param>
    /// <param name="AplicacionesPermitidas">Programas con permiso para escribir en las carpetas protegidas, o null si no se pudo leer (sin administrador, Windows no lo dice).</param>
    /// <param name="TiempoReal">Si la proteccion en tiempo real de Defender esta encendida, o null si no se supo.</param>
    /// <param name="ModoDelMotor">El <c>AMRunningMode</c> de Defender («Normal», «Passive Mode», «EDR Block Mode»...), o null si no se supo.</param>
    /// <param name="Eventos">Eventos del registro «Microsoft-Windows-Windows Defender/Operational» (1123, 1124, 1127, 1128 y 5007) del periodo.</param>
    /// <param name="NoLeido">Lo que no se pudo leer (registro inaccesible, tope alcanzado...). Cada texto ya explica que no se reviso.</param>
    public sealed record LecturaDeCarpetasProtegidas(
        int? ModoCrudo,
        IReadOnlyList<string>? CarpetasExtra,
        IReadOnlyList<string>? AplicacionesPermitidas,
        bool? TiempoReal,
        string? ModoDelMotor,
        IReadOnlyList<EventoDeWindows> Eventos,
        IReadOnlyList<string> NoLeido,
        int Descartados,
        TimeSpan Periodo);

    /// <summary>Los valores de <c>EnableControlledFolderAccess</c> (documentados en <c>Set-MpPreference</c>).</summary>
    public enum ModoDeCarpetasProtegidas
    {
        Desactivado = 0,
        Activado = 1,
        /// <summary>Solo anota en el registro lo que habria bloqueado; no bloquea nada.</summary>
        Auditoria = 2,
        /// <summary>Solo protege los sectores del disco (arranque), NO las carpetas.</summary>
        SoloDiscos = 3,
        AuditoriaSoloDiscos = 4
    }

    /// <summary>
    /// Reglas sobre la proteccion contra ransomware de Windows. Nexo no la reimplementa: la mira y explica. Honestidad:
    ///  - Lo que no se pudo leer es «no evaluado», nunca «protegido».
    ///  - Con otro antivirus como principal, Defender no aplica estas carpetas: no se sabe si el otro protege, y se dice.
    ///  - Un bloqueo es que Windows hizo su trabajo; no prueba que el programa sea ransomware (muchos programas legitimos guardan en
    ///    Documentos y Windows los bloquea hasta que se les da permiso).
    /// Decide sin depender del idioma: numeros de evento, proveedor, valores numericos y rutas del registro (no los textos traducidos).
    /// </summary>
    public static class AnalizadorDeCarpetasProtegidas
    {
        public const string ProveedorDefender = "Microsoft-Windows-Windows Defender";
        public const string RegistroDefender = "Microsoft-Windows-Windows Defender/Operational";
        public const int Bloqueado = 1123, Auditado = 1124, DiscoBloqueado = 1127, DiscoAuditado = 1128, ConfiguracionCambiada = 5007;
        public static readonly IReadOnlyList<int> Consultados = new[] { Bloqueado, Auditado, DiscoBloqueado, DiscoAuditado, ConfiguracionCambiada };
        public static readonly TimeSpan PeriodoPorOmision = TimeSpan.FromDays(30);

        /// <summary>La parte comun de la ruta del registro de todos los ajustes del CFA (local o por directiva).</summary>
        private const string ClaveCfa = @"\Controlled Folder Access\";

        /// <summary>Donde un programa legitimo instalado no suele vivir. AppData en general NO (Discord, Teams... viven ahi).</summary>
        private static readonly string[] CarpetasPocoHabituales =
        {
            @"\appdata\local\temp\", @"\windows\temp\", @"\temp\", @"\downloads\", @"\descargas\", @"\$recycle.bin\", @"\users\public\"
        };

        public static bool EnCarpetaPocoHabitual(string ruta)
        {
            string r = (ruta ?? "").Replace('/', '\\').ToLowerInvariant();
            return CarpetasPocoHabituales.Any(c => r.Contains(c));
        }

        /// <summary>
        /// Una lista tal como la da Windows. Sin administrador, Defender devuelve UN texto en vez de la lista («N/A: Must be an administrator to
        /// view exclusions», en ingles aunque Windows este en español; comprobado en este equipo): eso es «no se pudo leer» (null), nunca «lista vacia».
        /// </summary>
        public static IReadOnlyList<string>? ListaLegible(IEnumerable<string?>? valores)
        {
            if (valores is null) return null;
            var l = new List<string>();
            foreach (string? v in valores)
            {
                if (v is null) continue;
                string t = v.Trim();
                if (t.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) return null;
                if (t.Length > 0) l.Add(t);
            }
            return l;
        }

        public static string Nombre(ModoDeCarpetasProtegidas m) => m switch
        {
            ModoDeCarpetasProtegidas.Activado => "activado",
            ModoDeCarpetasProtegidas.Auditoria => "solo auditoría (anota, no bloquea)",
            ModoDeCarpetasProtegidas.SoloDiscos => "solo los sectores del disco (las carpetas no)",
            ModoDeCarpetasProtegidas.AuditoriaSoloDiscos => "solo auditoría de los sectores del disco",
            _ => "desactivado"
        };

        /// <summary>
        /// Un cambio de ajuste del CFA sacado de un 5007: lo que queda tras «\Controlled Folder Access\» en el valor viejo o el nuevo
        /// («EnableControlledFolderAccess = 0x1», «AllowedApplications\C:\x.exe = 0x0»). Null si el 5007 es de otro ajuste de Defender.
        /// </summary>
        public sealed record CambioDeCfa(DateTimeOffset Fecha, string Ajuste, string? Anterior, string? Nuevo);

        public static CambioDeCfa? CambioDe(EventoDeWindows e)
        {
            if (e.Id != ConfiguracionCambiada || !string.Equals(e.Proveedor, ProveedorDefender, StringComparison.OrdinalIgnoreCase)) return null;
            (string? ajusteV, string? valorV) = Partir(e.Dato("Old Value"));
            (string? ajusteN, string? valorN) = Partir(e.Dato("New Value"));
            string? ajuste = ajusteN ?? ajusteV;
            if (ajuste is null) return null;
            // Si el viejo y el nuevo hablan de ajustes distintos, se toma el nuevo y el viejo no cuenta como su valor anterior.
            if (ajusteN is not null && ajusteV is not null && !string.Equals(ajusteN, ajusteV, StringComparison.OrdinalIgnoreCase)) valorV = null;
            return new CambioDeCfa(e.Fecha, ajuste, ajusteV is null ? null : valorV, ajusteN is null ? null : valorN);
        }

        private static (string? Ajuste, string? Valor) Partir(string texto)
        {
            int i = texto.IndexOf(ClaveCfa, StringComparison.OrdinalIgnoreCase);
            if (i < 0) return (null, null);
            string resto = texto.Substring(i + ClaveCfa.Length);
            int igual = resto.LastIndexOf(" = ", StringComparison.Ordinal);
            return igual < 0 ? (resto.Trim(), null) : (resto.Substring(0, igual).Trim(), resto.Substring(igual + 3).Trim());
        }

        /// <summary>«0x1» o «1» → 1. Cualquier otra cosa → null (no se adivina).</summary>
        public static int? Numero(string? valor)
        {
            if (string.IsNullOrWhiteSpace(valor)) return null;
            string v = valor.Trim();
            if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(v.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int h) ? h : null;
            return int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out int d) ? d : null;
        }

        /// <summary>Los eventos que hablan de esta proteccion: bloqueos, auditorias y cambios de SUS ajustes (no los cientos de 5007 de otros ajustes).</summary>
        public static int Relevantes(LecturaDeCarpetasProtegidas l)
            => l.Eventos.Count(e => string.Equals(e.Proveedor, ProveedorDefender, StringComparison.OrdinalIgnoreCase)
                                    && (e.Id is Bloqueado or Auditado or DiscoBloqueado or DiscoAuditado || CambioDe(e) is not null));

        private static string Fecha(DateTimeOffset f) => f.ToLocalTime().ToString("dd-MM-yyyy HH:mm", CultureInfo.InvariantCulture);

        private static string Programa(string ruta)
        {
            string r = (ruta ?? "").Replace('/', '\\');
            int b = r.LastIndexOf('\\');
            return b >= 0 && b + 1 < r.Length ? r.Substring(b + 1) : r;
        }

        private static string Periodo(TimeSpan p) => (int)Math.Round(p.TotalDays) + " días";

        public static ResultadoDeAnalisis Analizar(LecturaDeCarpetasProtegidas l)
        {
            if (l is null) throw new ArgumentNullException(nameof(l));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>(l.NoLeido);
            if (l.Descartados > 0)
                noEvaluado.Add(l.Descartados + " evento(s) de Defender no se pudieron interpretar: puede faltar algún bloqueo en esta revisión.");

            // ---- 1. ¿Defender es quien protege? ----
            bool defenderManda = false;
            if (l.ModoDelMotor is null)
                noEvaluado.Add("No se pudo saber si Microsoft Defender está activo: sin eso no se sabe si las carpetas protegidas funcionan.");
            else if (string.Equals(l.ModoDelMotor.Trim(), "Normal", StringComparison.OrdinalIgnoreCase))
                defenderManda = true;
            else if (l.ModoDelMotor.IndexOf("Passive", StringComparison.OrdinalIgnoreCase) >= 0 || l.ModoDelMotor.IndexOf("EDR", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                hallazgos.Add(new HallazgoDeSistema("CFA-OTRO-ANTIVIRUS", Severidad.Info, "Otro antivirus es el principal",
                    "Microsoft Defender está en modo pasivo («" + l.ModoDelMotor.Trim() + "»): otro antivirus protege el equipo y Windows no aplica sus carpetas protegidas.",
                    "Revisa en tu otro antivirus si tiene protección contra ransomware y si está encendida."));
                noEvaluado.Add("Nexo no sabe leer la protección contra ransomware de otros antivirus: no se sabe si tus carpetas están protegidas.");
            }
            else
                noEvaluado.Add("Defender informa un modo desconocido («" + l.ModoDelMotor.Trim() + "»): no se sabe si las carpetas protegidas funcionan.");

            if (defenderManda && l.TiempoReal == false)
                hallazgos.Add(new HallazgoDeSistema("CFA-SIN-TIEMPO-REAL", Severidad.Alta, "La protección en tiempo real de Defender está apagada",
                    "Sin ella, Defender no vigila nada mientras ocurre: las carpetas protegidas no bloquean aunque estén activadas, y tampoco se detectan virus al abrirlos.",
                    "Enciéndela en Seguridad de Windows > Protección antivirus y contra amenazas. Si no la apagaste tú, analiza el equipo."));
            else if (defenderManda && l.TiempoReal is null)
                noEvaluado.Add("No se pudo saber si la protección en tiempo real de Defender está encendida.");

            // ---- 2. El modo del Acceso controlado a carpetas ----
            ModoDeCarpetasProtegidas? modo = l.ModoCrudo is int m && Enum.IsDefined(typeof(ModoDeCarpetasProtegidas), m) ? (ModoDeCarpetasProtegidas)m : null;
            if (l.ModoCrudo is null)
                noEvaluado.Add("No se pudo leer si el acceso controlado a carpetas está activado.");
            else if (modo is null)
                noEvaluado.Add("El acceso controlado a carpetas tiene un valor desconocido (" + l.ModoCrudo + "): no se sabe si protege.");

            List<CambioDeCfa> cambios = l.Eventos.Select(CambioDe).Where(c => c is not null).Select(c => c!).OrderBy(c => c.Fecha).ToList();
            CambioDeCfa? ultimoModo = cambios.LastOrDefault(c => string.Equals(c.Ajuste, "EnableControlledFolderAccess", StringComparison.OrdinalIgnoreCase));

            if (defenderManda && modo is ModoDeCarpetasProtegidas md)
            {
                const string Donde = "Seguridad de Windows > Protección antivirus y contra amenazas > Protección contra ransomware > Acceso controlado a carpetas";
                switch (md)
                {
                    case ModoDeCarpetasProtegidas.Desactivado:
                        hallazgos.Add(new HallazgoDeSistema("CFA-APAGADO", Severidad.Media, "Las carpetas protegidas contra ransomware están apagadas",
                            "Windows puede impedir que programas desconocidos cambien tus Documentos, Imágenes, Vídeos, Música, Escritorio y Favoritos (lo que hace un ransomware al cifrarlos), pero está apagado.",
                            "Actívalo en " + Donde + ". Al principio puede bloquear a algún programa tuyo que guarda en Documentos (un juego, un editor): Windows avisa y se le da permiso ahí mismo."));
                        break;
                    case ModoDeCarpetasProtegidas.Auditoria:
                        hallazgos.Add(new HallazgoDeSistema("CFA-AUDITORIA", Severidad.Baja, "Las carpetas protegidas solo anotan, no bloquean",
                            "Están en modo auditoría: Windows apunta qué programas habría bloqueado, pero los deja escribir. Sirve para probar antes de activarlo.",
                            "Cuando revises qué bloquearía (abajo salen los programas), actívalo en " + Donde + "."));
                        break;
                    case ModoDeCarpetasProtegidas.SoloDiscos:
                    case ModoDeCarpetasProtegidas.AuditoriaSoloDiscos:
                        hallazgos.Add(new HallazgoDeSistema("CFA-SOLO-DISCOS", Severidad.Media, "Tus carpetas no están protegidas contra ransomware",
                            "La protección está en «" + Nombre(md) + "»: vigila el arranque del disco, pero cualquier programa puede cambiar tus Documentos, Imágenes y demás.",
                            "Actívala por completo en " + Donde + "."));
                        break;
                    default:
                        int extra = l.CarpetasExtra?.Count ?? 0;
                        hallazgos.Add(new HallazgoDeSistema("CFA-ACTIVO", Severidad.Info, "Las carpetas protegidas contra ransomware están activadas",
                            "Windows impide que programas desconocidos cambien Documentos, Imágenes, Vídeos, Música, Escritorio y Favoritos" +
                            (extra > 0 ? ", y " + extra + (extra == 1 ? " carpeta más que añadiste" : " carpetas más que añadiste") : "") +
                            ". Protege esas carpetas, no todo el disco; y un programa al que diste permiso sí puede cambiarlas.",
                            "Nada que hacer. Si guardas cosas importantes en otra carpeta, añádela en " + Donde + "."));
                        break;
                }

                // Apagado hace poco: lo primero que intenta un ransomware con administrador es justo esto.
                if (md == ModoDeCarpetasProtegidas.Desactivado && ultimoModo is not null && Numero(ultimoModo.Nuevo) == 0 && Numero(ultimoModo.Anterior) is int antes && antes != 0)
                    hallazgos.Add(new HallazgoDeSistema("CFA-APAGADO-RECIENTE", Severidad.Media, "Las carpetas protegidas se apagaron hace poco",
                        "El " + Fecha(ultimoModo.Fecha) + " se apagó el acceso controlado a carpetas (antes estaba en «" + Nombre(Enum.IsDefined(typeof(ModoDeCarpetasProtegidas), antes) ? (ModoDeCarpetasProtegidas)antes : ModoDeCarpetasProtegidas.Activado) + "»). " +
                        "Windows no dice quién lo hizo. Si fuiste tú, no pasa nada; apagarlo es también lo primero que intenta un ransomware que logró permisos de administrador.",
                        "Si no lo apagaste tú, vuelve a activarlo y analiza el equipo."));

                // Programas con permiso: solo importan si la proteccion esta en marcha.
                if (md is ModoDeCarpetasProtegidas.Activado or ModoDeCarpetasProtegidas.Auditoria)
                {
                    if (l.AplicacionesPermitidas is null)
                        noEvaluado.Add("Sin permisos de administrador Windows no dice a qué programas les diste permiso para cambiar las carpetas protegidas: no se revisaron.");
                    else
                    {
                        foreach (string app in l.AplicacionesPermitidas.Where(EnCarpetaPocoHabitual))
                            hallazgos.Add(new HallazgoDeSistema("CFA-PERMITIDO-RARO", Severidad.Media, "Un programa en una carpeta poco habitual puede cambiar tus carpetas protegidas",
                                "«" + app + "» tiene permiso para escribir en las carpetas protegidas y está en una carpeta de temporales o descargas, donde no suelen vivir los programas instalados.",
                                "Si no lo reconoces, quítale el permiso en Seguridad de Windows > Protección contra ransomware > Permitir una aplicación.", Programa(app)));
                    }
                }
            }

            // ---- 3. Lo que Windows bloqueo o habria bloqueado ----
            string periodo = Periodo(l.Periodo);
            foreach (var g in l.Eventos.Where(e => string.Equals(e.Proveedor, ProveedorDefender, StringComparison.OrdinalIgnoreCase) && e.Id is Bloqueado or Auditado or DiscoBloqueado or DiscoAuditado)
                                        .GroupBy(e => (e.Id, Proceso: e.Dato("Process Name")), new ClaveDeBloqueo()))
            {
                EventoDeWindows ultimo = g.OrderByDescending(e => e.Fecha).First();
                string proceso = g.Key.Proceso.Length > 0 ? g.Key.Proceso : "(programa sin nombre)";
                bool raro = EnCarpetaPocoHabitual(proceso);
                bool disco = g.Key.Id is DiscoBloqueado or DiscoAuditado;
                bool bloqueo = g.Key.Id is Bloqueado or DiscoBloqueado;
                int n = g.Count();
                string veces = n + (n == 1 ? " vez" : " veces") + " en los últimos " + periodo + "; la última, el " + Fecha(ultimo.Fecha);
                string que = disco ? "escribir en los sectores del disco" : "cambiar «" + ultimo.Dato("Path") + "»";

                Severidad sev = (bloqueo, disco, raro) switch
                {
                    (_, _, true) when bloqueo => Severidad.Alta,
                    (_, _, true) => Severidad.Media,
                    (true, true, _) => Severidad.Media,
                    (true, false, _) => Severidad.Baja,
                    (false, true, _) => Severidad.Baja,
                    _ => Severidad.Info
                };
                string id = (bloqueo ? "CFA-BLOQUEO" : "CFA-HABRIA-BLOQUEADO") + (disco ? "-DISCO" : "");
                string titulo = bloqueo
                    ? (disco ? "Windows impidió a un programa escribir en el disco" : "Windows impidió a un programa cambiar tus carpetas protegidas")
                    : (disco ? "Un programa habría sido bloqueado al escribir en el disco" : "Un programa habría sido bloqueado al cambiar tus carpetas");
                string detalle = "«" + proceso + "» intentó " + que + " (" + veces + ")." +
                    (raro ? " Está en una carpeta de temporales o descargas, donde no suelen vivir los programas instalados." : "") +
                    (bloqueo ? " Windows lo impidió." : " Está en modo auditoría: lo dejó hacerlo y solo lo anotó.") +
                    " Esto no prueba que sea ransomware: muchos programas legítimos guardan en Documentos.";
                string recomendacion = raro
                    ? "Si no lo reconoces, no le des permiso: analízalo con Nexo y bórralo."
                    : bloqueo
                        ? "Si es un programa tuyo y te molesta el bloqueo, dale permiso en Seguridad de Windows > Protección contra ransomware > Permitir una aplicación. Si no lo reconoces, analízalo."
                        : "Si no lo reconoces, analízalo antes de activar la protección.";
                hallazgos.Add(new HallazgoDeSistema(id, sev, titulo, detalle, recomendacion, Programa(proceso)));
            }

            // ---- 4. Programas a los que se dio permiso en el periodo (lo dice el 5007, aun sin administrador) ----
            foreach (CambioDeCfa c in cambios.Where(c => c.Ajuste.StartsWith("AllowedApplications\\", StringComparison.OrdinalIgnoreCase) && c.Nuevo is not null))
            {
                string app = c.Ajuste.Substring("AllowedApplications\\".Length);
                if (app.Length == 0) continue;
                bool raro = EnCarpetaPocoHabitual(app);
                hallazgos.Add(new HallazgoDeSistema(raro ? "CFA-PERMISO-NUEVO-RARO" : "CFA-PERMISO-NUEVO", raro ? Severidad.Media : Severidad.Info,
                    raro ? "Se dio permiso a un programa en una carpeta poco habitual" : "Se dio permiso a un programa para cambiar tus carpetas protegidas",
                    "El " + Fecha(c.Fecha) + " se permitió a «" + app + "»." + (raro ? " Está en una carpeta de temporales o descargas, donde no suelen vivir los programas instalados." : "") + " Windows no dice quién lo hizo.",
                    raro ? "Si no fuiste tú, quítale el permiso y analiza el programa." : "Si no fuiste tú, quítale el permiso en Seguridad de Windows > Protección contra ransomware.", Programa(app)));
            }

            return new ResultadoDeAnalisis(
                hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Sujeto, StringComparer.Ordinal).ToList(),
                noEvaluado);
        }

        /// <summary>Agrupa por numero de evento y ruta del programa sin distinguir mayusculas (Windows no las distingue en rutas).</summary>
        private sealed class ClaveDeBloqueo : IEqualityComparer<(int Id, string Proceso)>
        {
            public bool Equals((int Id, string Proceso) a, (int Id, string Proceso) b) => a.Id == b.Id && string.Equals(a.Proceso, b.Proceso, StringComparison.OrdinalIgnoreCase);
            public int GetHashCode((int Id, string Proceso) k) => HashCode.Combine(k.Id, StringComparer.OrdinalIgnoreCase.GetHashCode(k.Proceso));
        }
    }
}
