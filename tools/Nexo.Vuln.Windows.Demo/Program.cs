using System;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Accounts;

namespace Nexo.Vuln.Windows.Demo
{
    internal static class Program
    {
        private static int _fallos;

        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            bool admin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            Console.WriteLine("Administrador: " + (admin ? "si" : "no") + " (no hace falta)");

            Console.WriteLine("1. Capa nativa (netapi32)");
            var cuentas = CuentasLocales.Enumerar(out uint e1);
            Check(cuentas is not null, "NetUserEnum enumera las cuentas locales", "error " + e1);
            if (cuentas is not null)
            {
                Console.WriteLine("      INFO: " + cuentas.Count + " cuentas locales: " + string.Join(", ", cuentas.Select(c => c.Nombre + "(" + c.Rid + (c.Tiene(CuentaLocalNativa.CuentaDeshabilitada) ? ",deshab." : "") + ")")));
                Check(cuentas.Any(c => c.Rid == 500), "existe el Administrador integrado (RID 500): siempre debe estar, aunque este deshabilitado");
                Check(cuentas.Any(c => c.Rid == 501), "existe el Invitado (RID 501)");
                Check(cuentas.Select(c => c.Rid).Distinct().Count() == cuentas.Count, "no hay RID repetidos (se enumero cada cuenta una vez)");
                Check(cuentas.Any(c => string.Equals(c.Nombre, Environment.UserName, StringComparison.OrdinalIgnoreCase)),
                      "la cuenta con la que corre este programa (" + Environment.UserName + ") esta en la lista", "puede ser una cuenta de Microsoft con otro nombre local");
            }

            var p = CuentasLocales.LeerPolitica(out uint e2);
            Check(p is not null, "NetUserModalsGet lee la politica local de contrasenas", "error " + e2);
            if (p is not null)
                Console.WriteLine("      INFO: longitud minima " + p.Value.LongitudMinima + ", caducidad " +
                                  (p.Value.EdadMaximaSegundos == PoliticaNativa.ParaSiempre ? "nunca" : TimeSpan.FromSeconds(p.Value.EdadMaximaSegundos).TotalDays + " dias") +
                                  ", historial " + p.Value.HistorialDeContrasenas + ", bloqueo tras " + p.Value.UmbralDeBloqueo + " intentos (0 = sin bloqueo)");

            Console.WriteLine("2. Lector completo y analizador");
            InstantaneaDeCuentas s = LectorDeCuentasWindows.Leer();
            Check(s.Cuentas is not null && s.Politica is not null && s.Autologon is not null, "se leyeron las tres partes (cuentas, politica, inicio automatico)");
            if (s.Autologon is not null)
                Console.WriteLine("      INFO: inicio automatico " + (s.Autologon.Activo ? "ACTIVO" : "inactivo") + (s.Autologon.Activo ? ", usuario " + s.Autologon.Usuario + ", contrasena en texto plano: " + (s.Autologon.ContrasenaEnTextoPlano ? "SI" : "no") : "") + " (nunca se lee el valor de la contrasena)");

            ResultadoDeAnalisis r = AnalizadorDeCuentas.Analizar(s);
            Check(r.Completo, "el analisis es completo (nada quedo sin evaluar)", string.Join("; ", r.NoEvaluado));
            Console.WriteLine("      INFO: " + r.Hallazgos.Count + " hallazgo(s):");
            foreach (HallazgoDeSistema h in r.Hallazgos)
                Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));

            // Cruce: el analisis coincide con lo que se leyo.
            if (s.Cuentas is not null)
            {
                bool invitadoHab = s.Cuentas.Any(c => c.Rid == 501 && c.Habilitada);
                Check(invitadoHab == r.Hallazgos.Any(h => h.Id == "CUENTA-INVITADO-ACTIVA"), "«Invitado habilitada» coincide con lo leido");
                bool adminHab = s.Cuentas.Any(c => c.Rid == 500 && c.Habilitada);
                Check(adminHab == r.Hallazgos.Any(h => h.Id == "CUENTA-ADMIN-INTEGRADA-ACTIVA"), "«Administrador integrado habilitado» coincide con lo leido");
            }

            // Estructural: nada de lo que sale de aqui puede llevar una contrasena.
            string todo = string.Join("\n", r.Hallazgos.Select(h => h.Titulo + h.Detalle + h.Recomendacion));
            Check(!todo.Contains("DefaultPassword=", StringComparison.OrdinalIgnoreCase), "ningun hallazgo contiene un valor de contrasena");

            ProbarWifi();
            ProbarWinget();

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void ProbarWinget()
        {
            Console.WriteLine("4. winget real (solo consulta: nunca instala ni actualiza nada)");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            SalidaDeWinget s = LectorDeWingetWindows.LeerAsync().GetAwaiter().GetResult();
            Console.WriteLine("      INFO: estado " + s.Estado + ", codigo de salida " + s.CodigoDeSalida + ", " + s.Texto.Length + " caracteres, " + sw.ElapsedMilliseconds + " ms");
            Check(s.Estado == EstadoDeWinget.Correcta && s.Texto.Length > 0, "winget se ejecuta y devuelve texto");

            ResultadoDeParseo p = ParserDeActualizacionesWinget.Parsear(s.Texto);
            Check(p.Reconocido, "la salida real, capturada por Process, se reconoce como tabla en espanol (tildes incluidas)", string.Join("; ", p.Avisos) + " | " + s.Texto.Substring(0, Math.Min(150, s.Texto.Length)).Replace("\n", "\\n"));
            Check(p.Avisos.Count == 0, "sin avisos: recuento coherente y ninguna fila ilegible", string.Join("; ", p.Avisos));

            System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(s.Texto, @"(\d+)\s+actualizaci\S+\s+disponible");
            Check(m.Success && int.Parse(m.Groups[1].Value) == p.Aplicaciones.Count, "el numero de aplicaciones leidas coincide con el que dice winget (" + p.Aplicaciones.Count + ")", m.Success ? m.Groups[1].Value : "sin recuento");
            Check(p.Aplicaciones.All(a => a.Id.Length > 0 && !a.Id.Contains(' ') && a.VersionDisponible.Length > 0), "todas tienen Id y version disponible");

            ResultadoDeAplicaciones r = AnalizadorDeAplicaciones.Analizar(s);
            Check(r.Analisis.Completo, "el analisis es completo", string.Join("; ", r.Analisis.NoEvaluado));
            Console.WriteLine("      INFO: " + r.Aplicaciones.Count + " aplicacion(es) con version nueva; hallazgos:");
            foreach (HallazgoDeSistema h in r.Analisis.Hallazgos) Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));

            // Tiempo limite: con 1 ms no puede terminar, y debe decirlo (no devolver una tabla a medias como si fuera completa).
            SalidaDeWinget corto = LectorDeWingetWindows.LeerAsync(TimeSpan.FromMilliseconds(1)).GetAwaiter().GetResult();
            Check(corto.Estado == EstadoDeWinget.TiempoAgotado && corto.Texto.Length == 0, "con un limite de 1 ms devuelve TiempoAgotado y NO una tabla a medias", corto.Estado.ToString());
            Check(!AnalizadorDeAplicaciones.Analizar(corto).Analisis.Completo, "y eso queda como «no evaluado»");
        }

        private static void ProbarWifi()
        {
            Console.WriteLine("3. Wi-Fi (native Wifi API; nunca se pide la clave)");
            bool hay = LectorDeWifiWindows.HayAdaptadorWifi();
            Console.WriteLine("      INFO: adaptador Wi-Fi presente: " + (hay ? "si" : "no"));

            InstantaneaDeWifi w = LectorDeWifiWindows.Leer();
            Console.WriteLine("      INFO: estado de lectura: " + w.Estado + ", adaptadores: " + w.Adaptadores.Count);
            Check(hay ? w.Estado == EstadoDeLecturaWifi.Correcta : w.Estado == EstadoDeLecturaWifi.SinAdaptador,
                  hay ? "con adaptador Wi-Fi la lectura es correcta" : "sin adaptador Wi-Fi el estado es SinAdaptador (un hecho)", w.Estado.ToString());

            foreach (AdaptadorWifi a in w.Adaptadores)
            {
                Console.WriteLine("      INFO: adaptador «" + a.Descripcion + "»: " + a.Perfiles.Count + " red(es) guardada(s); conexion actual: " +
                                  (a.Conexion is null ? "ninguna" : "«" + a.Conexion.Perfil + "» (seguridad " + (a.Conexion.SeguridadActiva ? "si" : "NO") + ", auth " + a.Conexion.Autenticacion + ", cifrado " + a.Conexion.Cifrado + ")"));
                int legibles = a.Perfiles.Count(p => p.Xml is not null);
                Check(legibles == a.Perfiles.Count, "todos los perfiles se pudieron leer (" + legibles + "/" + a.Perfiles.Count + ")");
                int interpretados = a.Perfiles.Count(p => p.Xml is not null && ParserDePerfilWifi.Parsear(p.Nombre, p.Xml) is not null);
                Check(interpretados == legibles, "y todos se interpretan con el parser (ninguno «formato raro»): " + interpretados + "/" + legibles);

                foreach (PerfilCrudo p in a.Perfiles.Where(p => p.Xml is not null))
                {
                    PerfilWifi? pw = ParserDePerfilWifi.Parsear(p.Nombre, p.Xml);
                    if (pw is not null) Console.WriteLine("        - «" + p.Nombre + "»: " + pw.Autenticacion + " / " + pw.Cifrado + ", " + (pw.Automatico == true ? "automatica" : "manual") + (pw.Oculta == true ? ", OCULTA" : ""));
                }
            }

            ResultadoDeAnalisis r = AnalizadorDeWifi.Analizar(w);
            Check(r.Completo, "el analisis de Wi-Fi es completo", string.Join("; ", r.NoEvaluado));
            Console.WriteLine("      INFO: " + r.Hallazgos.Count + " hallazgo(s) de Wi-Fi:");
            foreach (HallazgoDeSistema h in r.Hallazgos) Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));

            // La conexion actual solo se ejercita con datos reales si hay una conexion Wi-Fi activa; si no, al menos se comprueba el tamano de la estructura.
            Type? t = typeof(CuentaLocalNativa).Assembly.GetType("Nexo.Native.Wifi.WlanNativo+ConnectionAttributes");
            // 4 + 4 + 512 (nombre) + 68 (asociacion: 36 + 4 + 6 + 2 de relleno + 4 + 4 + 4 + 4 + 4) + 16 (seguridad) = 604
            Check(t is not null && System.Runtime.InteropServices.Marshal.SizeOf(t) == 604, "WLAN_CONNECTION_ATTRIBUTES mide 604 bytes en el codigo, como calculado del encabezado de Windows",
                  t is null ? "no se encontro el tipo" : System.Runtime.InteropServices.Marshal.SizeOf(t) + " bytes");
            bool conectado = w.Adaptadores.Any(a => a.Conexion is not null);
            Console.WriteLine("      INFO: " + (conectado ? "hay una conexion Wi-Fi activa: el camino de «conexion actual» SE ejercito con datos reales" : "no hay conexion Wi-Fi activa: el camino de «conexion actual» NO se ejercito con datos reales"));

            // Estructural: ninguna clave en ningun resultado (ni cifrada ni en claro).
            string todoXml = string.Join("\n", w.Adaptadores.SelectMany(a => a.Perfiles).Select(p => p.Xml ?? ""));
            Check(!todoXml.Contains("<protected>false</protected>", StringComparison.OrdinalIgnoreCase),
                  "ningun perfil trae la clave en texto plano (nunca se pide); solo, como mucho, cifrada");
            string salida = string.Join("\n", r.Hallazgos.Select(h => h.Titulo + h.Detalle + h.Recomendacion));
            Check(!System.Text.RegularExpressions.Regex.IsMatch(salida, "<keyMaterial|keyMaterial>", System.Text.RegularExpressions.RegexOptions.IgnoreCase), "ningun hallazgo contiene material de clave");
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }
    }
}
