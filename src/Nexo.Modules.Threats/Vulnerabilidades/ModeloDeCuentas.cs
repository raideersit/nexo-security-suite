using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    /// <summary>Una cuenta local. El RID (final del SID) no depende del idioma: 500 = Administrador integrado, 501 = Invitado.</summary>
    public sealed record CuentaLocal(string Nombre, int Rid, bool Habilitada, bool ContrasenaNoRequerida, bool ContrasenaNoExpira, bool Bloqueada)
    {
        public const int RidAdministrador = 500, RidInvitado = 501;
    }

    /// <summary>Politica local de contrasenas. <c>EdadMaxima</c> null = las contrasenas no caducan.</summary>
    public sealed record PoliticaDeContrasenas(int LongitudMinima, TimeSpan? EdadMaxima, int Historial, int UmbralDeBloqueo);

    /// <summary>
    /// Inicio de sesion automatico. Solo se sabe SI hay una contrasena guardada en texto plano en el registro
    /// (<c>DefaultPassword</c>); su valor NUNCA se lee. El inicio automatico que guarda la clave como secreto de LSA
    /// (Sysinternals Autologon) no es visible desde aqui: es un limite, no una garantia de que no exista.
    /// </summary>
    public sealed record EstadoDeAutologon(bool Activo, string? Usuario, bool ContrasenaEnTextoPlano);

    /// <summary>
    /// Lo que se pudo leer del sistema. Cada parte es null si NO se pudo leer: eso es «no evaluado», jamas «sin problemas».
    /// </summary>
    public sealed record InstantaneaDeCuentas(
        IReadOnlyList<CuentaLocal>? Cuentas,
        PoliticaDeContrasenas? Politica,
        EstadoDeAutologon? Autologon);

    public sealed record HallazgoDeSistema(string Id, Severidad Severidad, string Titulo, string Detalle, string Recomendacion, string? Sujeto = null);

    public sealed record ResultadoDeAnalisis(IReadOnlyList<HallazgoDeSistema> Hallazgos, IReadOnlyList<string> NoEvaluado)
    {
        /// <summary>true solo si se pudo leer TODO. Con false, «sin hallazgos» significa «nada en lo que se pudo mirar».</summary>
        public bool Completo => NoEvaluado.Count == 0;

        public Severidad Maxima => Hallazgos.Count == 0 ? Severidad.Info : Hallazgos.Max(h => h.Severidad);
    }

    /// <summary>
    /// Reglas sobre cuentas, politica de contrasenas e inicio automatico. SOLO usa metadatos: no hay forma de saber aqui la
    /// contrasena de nadie, y no se intenta (no se toca la SAM: linea roja del proyecto). Una bandera
    /// «contrasena no requerida» no significa que la cuenta no tenga contrasena, sino que Windows permitiria iniciarla sin una; el
    /// texto lo dice asi y no mas.
    /// </summary>
    public static class AnalizadorDeCuentas
    {
        public static ResultadoDeAnalisis Analizar(InstantaneaDeCuentas s)
        {
            if (s is null) throw new ArgumentNullException(nameof(s));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();

            if (s.Autologon is null) noEvaluado.Add("No se pudo leer el inicio de sesion automatico: no se sabe si hay una contrasena guardada en el registro.");
            else AnalizarAutologon(s.Autologon, hallazgos);

            if (s.Cuentas is null) noEvaluado.Add("No se pudieron enumerar las cuentas locales: no se revisaron banderas de contrasena ni la cuenta Invitado.");
            else AnalizarCuentas(s.Cuentas, hallazgos);

            if (s.Politica is null) noEvaluado.Add("No se pudo leer la politica local de contrasenas: no se sabe su longitud minima ni si hay bloqueo por intentos.");
            else AnalizarPolitica(s.Politica, hallazgos);

            return new ResultadoDeAnalisis(hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ToList(), noEvaluado);
        }

        private static void AnalizarAutologon(EstadoDeAutologon a, List<HallazgoDeSistema> h)
        {
            if (!a.Activo) return;
            string quien = string.IsNullOrWhiteSpace(a.Usuario) ? "una cuenta" : "la cuenta «" + a.Usuario + "»";
            if (a.ContrasenaEnTextoPlano)
                h.Add(new HallazgoDeSistema("AUTOLOGON-CONTRASENA-EN-REGISTRO", Severidad.Alta,
                    "La contrasena del inicio automatico esta guardada en texto plano",
                    "Windows inicia sesion solo con " + quien + " y su contrasena esta escrita en el registro (DefaultPassword), donde la puede leer cualquier programa con permisos de lectura sobre esa clave. Nexo no leyo su valor.",
                    "Desactiva el inicio de sesion automatico (netplwiz) y cambia esa contrasena, porque ya no es secreta.", a.Usuario));
            else
                h.Add(new HallazgoDeSistema("AUTOLOGON-ACTIVO", Severidad.Media,
                    "El inicio de sesion automatico esta activo",
                    "Windows entra solo con " + quien + ": cualquiera con acceso fisico al equipo encendido o reiniciado tiene su sesion. No se encontro la contrasena en texto plano en el registro (puede estar guardada de otra forma que Nexo no ve).",
                    "Si no lo necesitas, desactivalo (netplwiz).", a.Usuario));
        }

        private static void AnalizarCuentas(IReadOnlyList<CuentaLocal> cuentas, List<HallazgoDeSistema> h)
        {
            foreach (CuentaLocal c in cuentas)
            {
                if (!c.Habilitada) continue; // una cuenta deshabilitada no se puede usar: no es hallazgo

                if (c.Rid == CuentaLocal.RidInvitado)
                    h.Add(new HallazgoDeSistema("CUENTA-INVITADO-ACTIVA", Severidad.Media,
                        "La cuenta Invitado esta habilitada",
                        "La cuenta Invitado («" + c.Nombre + "») permite entrar sin una cuenta propia.",
                        "Deshabilitala si no la usas (Administracion de equipos > Usuarios locales).", c.Nombre));

                if (c.ContrasenaNoRequerida)
                {
                    bool admin = c.Rid == CuentaLocal.RidAdministrador;
                    h.Add(new HallazgoDeSistema("CUENTA-SIN-CONTRASENA-REQUERIDA", admin ? Severidad.Alta : Severidad.Media,
                        admin ? "El Administrador integrado no exige contrasena" : "Una cuenta no exige contrasena",
                        "La cuenta «" + c.Nombre + "» tiene la bandera «contrasena no requerida»: Windows permitiria iniciarla sin contrasena. Eso no significa que no tenga una; Nexo no puede saberlo.",
                        "Ponle una contrasena y quita esa bandera, o deshabilita la cuenta.", c.Nombre));
                }

                if (c.Rid == CuentaLocal.RidAdministrador)
                    h.Add(new HallazgoDeSistema("CUENTA-ADMIN-INTEGRADA-ACTIVA", Severidad.Baja,
                        "El Administrador integrado esta habilitado",
                        "La cuenta «" + c.Nombre + "» es el Administrador integrado de Windows, con un nombre y un RID conocidos por cualquier atacante.",
                        "Si no la necesitas, deshabilitala y usa una cuenta de administrador propia.", c.Nombre));

                if (c.ContrasenaNoExpira)
                    h.Add(new HallazgoDeSistema("CUENTA-CONTRASENA-NO-EXPIRA", Severidad.Info,
                        "La contrasena de una cuenta no caduca",
                        "La contrasena de «" + c.Nombre + "» esta marcada como que nunca expira. Hoy no se recomienda forzar la caducidad periodica; esto solo importa si esa contrasena es debil o se filtro.",
                        "Nada que hacer por esto solo; usa una contrasena larga y unica.", c.Nombre));

                if (c.Bloqueada)
                    h.Add(new HallazgoDeSistema("CUENTA-BLOQUEADA", Severidad.Baja,
                        "Una cuenta esta bloqueada ahora mismo",
                        "La cuenta «" + c.Nombre + "» esta bloqueada, lo que suele pasar tras varios intentos fallidos de iniciar sesion.",
                        "Si no fuiste tu, alguien podria estar probando contrasenas: revisa los inicios de sesion fallidos.", c.Nombre));
            }
        }

        private static void AnalizarPolitica(PoliticaDeContrasenas p, List<HallazgoDeSistema> h)
        {
            if (p.LongitudMinima <= 0)
                h.Add(new HallazgoDeSistema("POLITICA-SIN-LONGITUD-MINIMA", Severidad.Media,
                    "La politica local no exige una longitud minima de contrasena",
                    "La longitud minima es 0: Windows acepta contrasenas de cualquier tamano, incluso vacias, en las cuentas locales.",
                    "Fija una longitud minima de al menos 8 (mejor 12) en la directiva de seguridad local."));
            else if (p.LongitudMinima < 8)
                h.Add(new HallazgoDeSistema("POLITICA-LONGITUD-CORTA", Severidad.Baja,
                    "La longitud minima de contrasena es corta",
                    "La politica local exige solo " + p.LongitudMinima + " caracteres.",
                    "Subela a 8 o mas (mejor 12) en la directiva de seguridad local."));

            if (p.UmbralDeBloqueo <= 0)
                h.Add(new HallazgoDeSistema("POLITICA-SIN-BLOQUEO-POR-INTENTOS", Severidad.Baja,
                    "No hay bloqueo de cuenta tras intentos fallidos",
                    "El umbral de bloqueo es 0: se pueden probar contrasenas sin limite de intentos contra las cuentas locales.",
                    "Fija un umbral (por ejemplo 10 intentos) en la directiva de seguridad local."));
        }
    }
}
