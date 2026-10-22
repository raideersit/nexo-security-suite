using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Firewall
{
    /// <summary>Resultado de validar la ruta de un ejecutable para una regla.</summary>
    public readonly struct ResultadoDeRuta
    {
        private ResultadoDeRuta(bool aceptada, string ruta, string motivo)
        {
            Aceptada = aceptada;
            Ruta = ruta;
            Motivo = motivo;
        }

        public bool Aceptada { get; }
        public string Ruta { get; }
        public string Motivo { get; }

        public static ResultadoDeRuta Ok(string ruta) => new ResultadoDeRuta(true, ruta, "");
        public static ResultadoDeRuta No(string ruta, string motivo) => new ResultadoDeRuta(false, ruta, motivo);
    }

    /// <summary>
    /// Decide sobre que ejecutables puede Nexo crear reglas. Equivale a
    /// GuardiaDeRutas del limpiador: el servicio corre como LocalSystem y no
    /// confia en quien le pide el cambio (regla de oro de la Salida 0).
    ///
    /// Dos defensas distintas:
    ///   1. La ruta es una ruta de ejecutable bien formada y existente, sin
    ///      comodines ni segmentos '..' que apunten a otra cosa distinta de la
    ///      que el usuario vio.
    ///   2. BLOQUEAR esta prohibido para procesos de los que depende el sistema o
    ///      su seguridad. Permitir no tiene esa restriccion.
    /// </summary>
    public sealed class GuardiaDeReglas
    {
        /// <summary>
        /// Ejecutables que Nexo nunca bloquea. Bloquear svchost.exe deja sin red a
        /// medio Windows (incluido Windows Update); bloquear Defender contradice la
        /// regla del proyecto de complementarlo, no desactivarlo. Los que acaban en
        /// '*' comparan por prefijo.
        /// </summary>
        public static readonly IReadOnlyList<string> ProtegidosPorDefecto = new[]
        {
            "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
            "csrss.exe", "smss.exe", "system", "dns.exe",
            "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "SecurityHealthService.exe",
            "MsSense.exe",
            "Nexo*"
        };

        // Letra de unidad o UNC. Se valida con regex y no con Path.IsPathRooted para
        // que el resultado sea el mismo en Linux, donde se corren las pruebas.
        private static readonly Regex RutaWindows =
            new Regex(@"^(?:[A-Za-z]:\\|\\\\[^\\/:*?""<>|]+\\[^\\/:*?""<>|]+)", RegexOptions.Compiled);

        private static readonly char[] Prohibidos = { '*', '?', '"', '<', '>', '|', '\0' };

        private readonly IReadOnlyList<string> _protegidos;
        private readonly Func<string, bool> _existe;

        /// <param name="protegidos">Sustituye la lista por defecto (solo para pruebas).</param>
        /// <param name="adicionales">
        /// Nombres extra que el usuario quiere proteger. Se SUMAN a la lista de base: la
        /// configuracion solo puede ampliar la proteccion, nunca quitar svchost o Defender.
        /// </param>
        public GuardiaDeReglas(
            IEnumerable<string>? protegidos = null, Func<string, bool>? existe = null,
            IEnumerable<string>? adicionales = null)
        {
            _protegidos = (protegidos ?? ProtegidosPorDefecto)
                .Concat((adicionales ?? Enumerable.Empty<string>()).Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => a.Trim()))
                .ToList();
            _existe = existe ?? File.Exists;
        }

        private static readonly char[] NoEsNombre = { '\\', '/', '*', '?', ':', '"', '<', '>', '|', '\0' };

        /// <summary>
        /// Lee la lista adicional: un nombre de ejecutable por linea ('#' comenta; un '*' final
        /// compara por prefijo). Un nombre con ruta o con '*' en medio se ignora y se devuelve
        /// en <paramref name="ignoradas"/>: aqui solo se admiten nombres, no rutas. Si el archivo
        /// no existe o no se puede leer, la lista adicional queda vacia y la de base sigue intacta.
        /// </summary>
        public static IReadOnlyList<string> LeerAdicionales(string ruta, out IReadOnlyList<string> ignoradas)
        {
            var validas = new List<string>();
            var malas = new List<string>();
            ignoradas = malas;

            string[] lineas;
            try { lineas = File.ReadAllLines(ruta); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return validas; }

            foreach (string cruda in lineas)
            {
                string l = cruda.Trim();
                if (l.Length == 0 || l.StartsWith('#')) continue;

                string cuerpo = l.EndsWith('*') ? l[..^1] : l;
                if (cuerpo.Length == 0 || cuerpo.IndexOfAny(NoEsNombre) >= 0) malas.Add(l);
                else validas.Add(l);
            }
            return validas;
        }

        public bool EstaProtegido(string rutaExe)
        {
            string nombre = NombreDe(rutaExe);
            return _protegidos.Any(p => Coincide(nombre, p));
        }

        /// <summary>Valida la ruta de un ejecutable sin mirar todavia que se hara con ella.</summary>
        public ResultadoDeRuta ValidarRuta(string? ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta))
                return ResultadoDeRuta.No(ruta ?? "", "ruta vacia");

            string r = ruta.Trim();

            if (r.IndexOfAny(Prohibidos) >= 0)
                return ResultadoDeRuta.No(r, "contiene caracteres no permitidos (comodines o de control)");

            if (!RutaWindows.IsMatch(r))
                return ResultadoDeRuta.No(r, "no es una ruta absoluta de Windows (C:\\... o \\\\servidor\\recurso)");

            if (r.Length >= 260)
                return ResultadoDeRuta.No(r, "ruta demasiado larga");

            // '..' se rechaza en vez de normalizarlo: la regla debe apuntar a lo que
            // el usuario vio escrito, no a donde acabe resolviendose.
            if (r.Split('\\', '/').Any(seg => seg == ".." || seg == "."))
                return ResultadoDeRuta.No(r, "contiene segmentos '.' o '..'");

            if (!r.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return ResultadoDeRuta.No(r, "no es un ejecutable (.exe)");

            if (!_existe(r))
                return ResultadoDeRuta.No(r, "el archivo no existe (¿errata?)");

            return ResultadoDeRuta.Ok(r);
        }

        /// <summary>Ruta valida y, ademas, permitida para la accion pedida.</summary>
        public ResultadoDeRuta Validar(string? ruta, AccionDeRegla accion)
        {
            ResultadoDeRuta v = ValidarRuta(ruta);
            if (!v.Aceptada) return v;

            if (accion == AccionDeRegla.Bloquear && EstaProtegido(v.Ruta))
                return ResultadoDeRuta.No(v.Ruta,
                    "proceso protegido (sistema, Windows Defender o Nexo): no se bloquea");

            return v;
        }

        public static string NombreDe(string ruta)
        {
            int i = ruta.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 ? ruta[(i + 1)..] : ruta;
        }

        private static bool Coincide(string nombre, string patron)
            => patron.EndsWith('*')
                ? nombre.StartsWith(patron[..^1], StringComparison.OrdinalIgnoreCase)
                : string.Equals(nombre, patron, StringComparison.OrdinalIgnoreCase);
    }
}
