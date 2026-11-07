using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        /// <summary>
        /// Formas SIEMPRE incorrectas sin tilde o sin eñe en español. No incluye «esta», «este» ni «solo»: pueden ir sin tilde según el caso
        /// (demostrativo, o «solo» sin tilde por norma actual).
        /// </summary>
        private static readonly string[] SinTilde =
        {
            "contrasena", "contrasenas", "politica", "sesion", "version", "versiones_", "revision", "configuracion", "conexion", "informacion",
            "aplicacion", "actualizacion", "automatico", "automatica", "automaticamente", "minima", "unica", "periodica", "publicas", "fisico",
            "trafico", "tamano", "anos", "espanol", "codigo", "linea", "debil", "despues", "asi", "mas", "ningun", "limite", "dia", "vacia",
            "vacias", "vacios", "podria", "permitiria", "atraeria", "tardo", "llego", "devolvio", "agrego", "leyo", "evaluo", "encontro",
            "administracion", "conectate", "desconectate", "olvidala", "deshabilitala", "desactivalo", "actualizalo", "actualizalas", "subela"
        };

        private static readonly Regex Palabra = new Regex(@"[A-Za-zÁÉÍÓÚáéíóúñÑ]+", RegexOptions.Compiled);

        private static IEnumerable<string> TextosDe(ResultadoDeAnalisis r)
        {
            foreach (HallazgoDeSistema h in r.Hallazgos) { yield return h.Titulo; yield return h.Detalle; yield return h.Recomendacion; }
            foreach (string n in r.NoEvaluado) yield return n;
        }

        private static IEnumerable<string> TextosDe(NexoEvent e)
        {
            yield return e.Titulo;
            // Las filas de tabla de aplicaciones llevan nombres de programas (datos del equipo), no texto de Nexo.
            foreach (string l in (e.Cuerpo ?? "").Split('\n').Where(l => !l.StartsWith("| ") || l.StartsWith("| Gravedad") || l.StartsWith("| Aplicacion")))
                yield return l;
        }

        public static void ProbarTextosConTildes()
        {
            Console.WriteLine("15. Los textos van con tildes y eñes (solo español)");
            var textos = new List<string>();

            // Cuentas: todas las reglas a la vez, y cada parte sin leer.
            var cuentas = new InstantaneaDeCuentas(
                new[]
                {
                    Cuenta("Invitado", 501), Cuenta("Administrador", 500, sinClave: true, noExpira: true, bloqueada: true), Cuenta("ana", 1001, sinClave: true, noExpira: true, bloqueada: true)
                },
                new PoliticaDeContrasenas(0, null, 0, 0), new EstadoDeAutologon(true, "ana", true));
            ResultadoDeAnalisis rc = AnalizadorDeCuentas.Analizar(cuentas);
            textos.AddRange(TextosDe(rc));
            textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeCuentas(rc)));
            ResultadoDeAnalisis rcActivo = AnalizadorDeCuentas.Analizar(cuentas with { Autologon = new EstadoDeAutologon(true, "ana", false), Politica = new PoliticaDeContrasenas(7, null, 0, 5) });
            textos.AddRange(TextosDe(rcActivo));
            ResultadoDeAnalisis rcNada = AnalizadorDeCuentas.Analizar(new InstantaneaDeCuentas(null, null, null));
            textos.AddRange(TextosDe(rcNada));
            textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeCuentas(rcNada)));
            textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeCuentas(AnalizadorDeCuentas.Analizar(Sana()))));

            // Wi-Fi: cada clase de red, la conexion actual y cada estado.
            var perfiles = new[]
            {
                new PerfilCrudo("A", Xml("A", "open", "none")), new PerfilCrudo("B", Xml("B", "open", "none", modo: "manual")), new PerfilCrudo("C", Xml("C", "shared", "WEP")),
                new PerfilCrudo("D", Xml("D", "WPA2PSK", "TKIP")), new PerfilCrudo("E", Xml("E", "WPA2PSK", "AES", oculta: true)), new PerfilCrudo("F", Xml("F", "raro", "extra")),
                new PerfilCrudo("G", null), new PerfilCrudo("H", "<basura/>")
            };
            foreach (ConexionActual k in new[] { new ConexionActual("X", false, 1, 0), new ConexionActual("X", true, 2, 1), new ConexionActual("X", true, 7, 2) })
            {
                ResultadoDeAnalisis rw = AnalizadorDeWifi.Analizar(Wifi(perfiles, k));
                textos.AddRange(TextosDe(rw));
                textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeWifi(rw, EstadoDeLecturaWifi.Correcta)));
            }
            foreach (EstadoDeLecturaWifi est in new[] { EstadoDeLecturaWifi.ServicioNoActivo, EstadoDeLecturaWifi.Error, EstadoDeLecturaWifi.SinAdaptador })
            {
                ResultadoDeAnalisis rw = AnalizadorDeWifi.Analizar(new InstantaneaDeWifi(est, Array.Empty<AdaptadorWifi>()));
                textos.AddRange(TextosDe(rw));
                textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeWifi(rw, est)));
            }

            // Aplicaciones: la salida real, y cada forma de fallar.
            string[] salidas =
            {
                WingetReal,
                WingetReal.Replace("Microsoft.VisualStudio.2022.BuildTools    ", "Microsoft.VisualStudio.2022.Build…       "),
                WingetReal.Replace("21 actualizaciones disponibles.", "22 actualizaciones disponibles."),
                WingetReal.Replace("21 actualizaciones disponibles.", ""),
                WingetReal + "\nalgo mas despues del recuento",
                WingetReal.Replace("Nombre ", "Name   ").Replace("Versión", "Version"),
                "", "Error al abrir el origen.", "No se encontraron actualizaciones disponibles."
            };
            foreach (string s in salidas)
            {
                ResultadoDeAplicaciones ra = AnalizadorDeAplicaciones.Analizar(Winget(s));
                textos.AddRange(TextosDe(ra.Analisis));
                textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeAplicaciones(ra)));
            }
            foreach (EstadoDeWinget est in new[] { EstadoDeWinget.NoInstalado, EstadoDeWinget.TiempoAgotado, EstadoDeWinget.Error })
            {
                ResultadoDeAplicaciones ra = AnalizadorDeAplicaciones.Analizar(new SalidaDeWinget(est, "", -1));
                textos.AddRange(TextosDe(ra.Analisis));
                textos.AddRange(TextosDe(EventosDeVulnerabilidades.RevisionDeAplicaciones(ra)));
            }

            Check(textos.Count > 150, "se recorrieron todos los textos de las tres revisiones en todos sus casos (" + textos.Count + " textos)", textos.Count.ToString());

            var malos = new SortedSet<string>(StringComparer.Ordinal);
            foreach (string t in textos)
                foreach (Match m in Palabra.Matches(t))
                    if (Array.IndexOf(SinTilde, m.Value.ToLowerInvariant()) >= 0 && !(m.Value.Length > 1 && m.Value == m.Value.ToUpperInvariant()))
                        malos.Add(m.Value + "  →  «" + Resumen(t, m.Index) + "»");

            Check(malos.Count == 0, "ningún texto contiene una palabra sin su tilde o su eñe", string.Join(" | ", malos.Take(8)));

            // Control: el detector funciona. Con una palabra mal escrita a propósito, la encuentra.
            Check(Palabra.Matches("La contrasena de una cuenta").Any(m => Array.IndexOf(SinTilde, m.Value.ToLowerInvariant()) >= 0), "control: el detector SI encuentra «contrasena» sin eñe");
            Check(!Palabra.Matches("La contraseña de una cuenta, la política y la revisión").Any(m => Array.IndexOf(SinTilde, m.Value.ToLowerInvariant()) >= 0), "control: y no marca las palabras bien escritas");

            // Los casos ambiguos que NO son errores se conservan bien.
            string todo = string.Join("\n", textos);
            Check(todo.Contains("este equipo") && todo.Contains("olvida esta red"), "«este equipo» y «olvida esta red» (demostrativos) NO llevan tilde");
            Check(todo.Contains("donde esté") && todo.Contains("que esté completa") && todo.Contains("que esté bien"), "«donde esté», «que esté completa» y «que esté bien» (subjuntivo) SI la llevan");
            Check(todo.Contains("Estás conectado") && todo.Contains("fuiste tú") && todo.Contains("winget falló"), "«Estás conectado», «fuiste tú» y «winget falló» llevan tilde");
            Check(todo.Contains("tu casa o tu trabajo"), "«tu casa o tu trabajo» (posesivo) NO lleva tilde");
        }

        private static string Resumen(string t, int i) => t.Substring(Math.Max(0, i - 20), Math.Min(t.Length - Math.Max(0, i - 20), 50)).Replace("\n", " ");
    }
}
