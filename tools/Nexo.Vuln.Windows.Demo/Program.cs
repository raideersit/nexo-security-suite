using System;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Accounts;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
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
            ProbarPestanaDeSeguridad();
            ProbarPestanaDeContrasenas();
            ProbarVigilanteDeSesion();
            ProbarDispositivosReales();
            ProbarWireGuardReal();
            ProbarAlertasReales();
            ProbarRansomwareReal();
            ProbarSenuelosReales();
            ProbarMineriaReal();
            // Sale a Internet (NVD): solo si se pide.
            if (Environment.GetCommandLineArgs().Contains("--nvd")) ProbarNvdReal();
            else Console.WriteLine("7. NVD real: OMITIDA (sale a Internet; se ejecuta con --nvd)");

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private sealed class PortapapelesDePrueba : Nexo.Ui.Desktop.Nucleo.IPortapapeles
        {
            public string? Texto;
            public System.Threading.Tasks.Task<bool> PonerAsync(string t) { Texto = t; return System.Threading.Tasks.Task.FromResult(true); }
            public System.Threading.Tasks.Task<string?> LeerAsync() => System.Threading.Tasks.Task.FromResult(Texto);
            public System.Threading.Tasks.Task BorrarAsync() { Texto = null; return System.Threading.Tasks.Task.CompletedTask; }
        }

        private static void ProbarPestanaDeContrasenas()
        {
            Console.WriteLine("6. La pestaña «Contraseñas» con parámetros REALES de Argon2id y Pwned Passwords REAL (solo sale el prefijo 5BAA6 y uno aleatorio)");
            string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nexo-vuln-boveda-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(dir);
            string ruta = System.IO.Path.Combine(dir, "boveda.nxv");
            string maestra = "maestra-real-de-prueba-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            try
            {
                var portapapeles = new PortapapelesDePrueba();
                // Sin parametros ni consulta inyectados: los de produccion (64 MiB / 3 iteraciones / 2 hilos, y HTTPS a api.pwnedpasswords.com).
                var m = new Nexo.Ui.Desktop.ContrasenasModelo(ruta, portapapeles: portapapeles);
                Check(m.EsSinBoveda, "sin archivo: «sin bóveda»");

                var sw = System.Diagnostics.Stopwatch.StartNew();
                bool creada = m.CrearAsync(maestra, maestra).GetAwaiter().GetResult();
                long tCrear = sw.ElapsedMilliseconds;
                Check(creada && m.EsAbierta && System.IO.File.Exists(ruta), "crea la bóveda con los parámetros por omisión", m.Mensaje);
                Console.WriteLine("      INFO: crear tardó " + tCrear + " ms");

                m.NuevaEntrada(); m.EdSitio = "ejemplo.cl"; m.EdUsuario = "ana"; m.EdContrasena = "password"; m.GuardarEdicionAsync().GetAwaiter().GetResult();
                m.NuevaEntrada(); m.EdSitio = "otro.cl"; m.EdUsuario = "luis"; m.EdContrasena = "Nx-" + Guid.NewGuid().ToString("N") + "-Zq9"; m.GuardarEdicionAsync().GetAwaiter().GetResult();
                Check(m.Cantidad == 2, "2 entradas guardadas");

                byte[] disco = System.IO.File.ReadAllBytes(ruta);
                Check(disco.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes("ejemplo.cl")) < 0 && disco.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes("password")) < 0, "en el archivo real no aparecen ni el sitio ni la contraseña");

                sw.Restart();
                m.AuditarAsync().GetAwaiter().GetResult();
                Console.WriteLine("      INFO: auditar (2 consultas reales) tardó " + sw.ElapsedMilliseconds + " ms; resultado: " + m.Auditoria);
                FilaDeEntradaDePrueba(m, "ejemplo.cl", out string fPass);
                FilaDeEntradaDePrueba(m, "otro.cl", out string fOtra);
                Console.WriteLine("      INFO: «password» → " + fPass + " | cadena aleatoria → " + fOtra);
                Check(fPass.StartsWith("Filtrada (") && m.IndicadorDeAuditoria == Nexo.Ui.Desktop.Nucleo.Indicador.Alerta, "«password» sale como filtrada (millones de veces) y el resultado es alerta");
                Check(fOtra == "No aparece en filtraciones conocidas", "una cadena aleatoria nueva no aparece");

                // copiar: el modelo pone la contraseña y se borra al bloquear
                m.Seleccionada = m.Entradas.First(e => e.Sitio == "ejemplo.cl");
                m.CopiarContrasenaAsync().GetAwaiter().GetResult();
                Check(portapapeles.Texto == "password" && m.HayTextoEnElPortapapeles, "copiar pone la contraseña en el portapapeles");
                m.Bloquear();
                m.EsperarBorradoAsync().GetAwaiter().GetResult();
                Check(portapapeles.Texto is null && m.EsBloqueada && m.Cantidad == 0, "bloquear la borra del portapapeles y olvida las entradas");

                sw.Restart();
                bool mal = m.DesbloquearAsync("esta-no-es-la-maestra").GetAwaiter().GetResult();
                long tMal = sw.ElapsedMilliseconds;
                sw.Restart();
                bool bien = m.DesbloquearAsync(maestra).GetAwaiter().GetResult();
                long tBien = sw.ElapsedMilliseconds;
                Console.WriteLine("      INFO: desbloquear (mal) " + tMal + " ms · (bien) " + tBien + " ms");
                Check(!mal && bien && m.Cantidad == 2 && !m.HayAuditoria, "maestra equivocada no abre; la correcta abre con las 2 entradas y SIN los resultados de filtraciones anteriores");
                Check(tMal >= 30 && tBien >= 30, "abrir cuesta tiempo de verdad (Argon2id con los parámetros reales)");

                // Copia de seguridad: guardar, cambiar la maestra, restaurar la copia. Lo posterior se aparta, no se borra.
                string copia = System.IO.Path.Combine(dir, "respaldo", "copia.nxv");
                sw.Restart();
                bool guardada = m.GuardarCopiaAsync(copia).GetAwaiter().GetResult();
                Console.WriteLine("      INFO: guardar la copia tardó " + sw.ElapsedMilliseconds + " ms");
                byte[] bytesCopia = guardada ? System.IO.File.ReadAllBytes(copia) : Array.Empty<byte>();
                Check(guardada && bytesCopia.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes("ejemplo.cl")) < 0, "guarda la copia cifrada (sin sitio ni contraseña en claro)");
                string nueva = maestra + "-NUEVA";
                Check(m.CambiarMaestraAsync(maestra, nueva, nueva).GetAwaiter().GetResult(), "cambia la contraseña maestra después de la copia");
                m.Bloquear();
                sw.Restart();
                bool restaurada = m.RestaurarAsync(copia, maestra).GetAwaiter().GetResult();
                Console.WriteLine("      INFO: restaurar tardó " + sw.ElapsedMilliseconds + " ms; mensaje: " + m.Mensaje.Substring(0, Math.Min(90, m.Mensaje.Length)) + "...");
                Check(restaurada && m.EsBloqueada && m.Mensaje.Contains("se guardó aparte"), "restaurar la copia: queda bloqueada y avisa que la bóveda anterior se guardó aparte");
                bool conNueva = m.DesbloquearAsync(nueva).GetAwaiter().GetResult();
                bool conCopia = m.DesbloquearAsync(maestra).GetAwaiter().GetResult();
                Check(!conNueva && conCopia && m.Cantidad == 2, "ahora abre con la contraseña de la COPIA (no con la posterior) y trae las 2 entradas");
                string[] apartadas = System.IO.Directory.GetFiles(dir, "boveda.nxv.anterior-*");
                Check(apartadas.Length == 1, "la bóveda posterior quedó apartada (1 archivo), no borrada");
                var verApartada = Nexo.Modules.Identity.Boveda.Boveda.AbrirAsync(apartadas[0], nueva).GetAwaiter().GetResult();
                Check(verApartada.Abierta && verApartada.Boveda!.Entradas.Count == 2, "y la apartada sigue abriendo con la contraseña nueva");
                verApartada.Boveda?.Dispose();
                m.Dispose();
            }
            finally
            {
                try { System.IO.Directory.Delete(dir, true); } catch (System.IO.IOException) { } catch (UnauthorizedAccessException) { }
            }
        }

        private static void FilaDeEntradaDePrueba(Nexo.Ui.Desktop.ContrasenasModelo m, string sitio, out string filtracion)
            => filtracion = m.Entradas.First(e => e.Sitio == sitio).Filtracion;

        private static void ProbarPestanaDeSeguridad()
        {
            Console.WriteLine("5. La pestaña «Seguridad» de la ventana, con el adaptador REAL (ServicioDeSeguridadLocal)");
            var servicio = new Nexo.Ui.Desktop.Nucleo.ServicioDeSeguridadLocal();
            var modelo = new Nexo.Ui.Desktop.SeguridadModelo(servicio);
            Check(modelo.Titulo == "Sin revisar todavía", "al crearse no revisa nada");

            var sw = System.Diagnostics.Stopwatch.StartNew();
            modelo.RevisarTodoAsync().GetAwaiter().GetResult();
            Console.WriteLine("      INFO: «Revisar todo» tardo " + sw.ElapsedMilliseconds + " ms");

            foreach (var f in modelo.Secciones)
            {
                Console.WriteLine("      INFO: [" + f.Nombre + "] " + f.Estado + " — " + f.Resumen);
                foreach (var h in f.Hallazgos) Console.WriteLine("          · " + h.Gravedad + ": " + h.Titulo + (h.TieneSujeto ? " (" + h.Sujeto + ")" : ""));
                foreach (string n in f.NoEvaluado) Console.WriteLine("          ! " + n);
            }
            Console.WriteLine("      INFO: general: " + modelo.Titulo + " (" + modelo.Indicador + ")");

            Check(modelo.Secciones.Take(3).All(f => f.Estado != "No se pudo revisar" && f.Estado != "Sin revisar"), "las 3 secciones locales se revisaron de verdad (ninguna «No se pudo revisar»)");
            Check(modelo.Secciones[3].Estado == "Sin revisar", "la de NVD NO se ejecuto con «Revisar todo» (no sale nada a Internet sin pedirlo)");
            Check(modelo.Secciones[0].Resumen.Contains("5 cuentas locales"), "Cuentas: leyo las 5 cuentas locales del HP", modelo.Secciones[0].Resumen);
            Check(modelo.Secciones[1].Resumen.Contains("16 redes guardadas"), "Wi-Fi: leyo las 16 redes guardadas del HP", modelo.Secciones[1].Resumen);
            Check(modelo.Secciones[2].Resumen.Contains("aplicaciones con versión nueva"), "Aplicaciones: leyo la lista de winget", modelo.Secciones[2].Resumen);
            Check(modelo.Secciones[0].Hallazgos.Any(h => h.Titulo.Contains("longitud mínima")), "Cuentas: aparece el hallazgo real de la politica sin longitud minima");
            Check(modelo.Secciones[2].Hallazgos.Any(h => h.Gravedad == "Media" && h.TieneSujeto), "Aplicaciones: al menos un programa muy atacado marcado Media (Java/WinRAR)");
            Check(modelo.Indicador != Nexo.Ui.Desktop.Nucleo.Indicador.Correcto, "con esos hallazgos el general NO es verde");
            Check(!modelo.Secciones.Any(f => f.Revisando) && modelo.PuedeRevisarTodo, "al terminar, nada queda «Revisando...» y se puede volver a pulsar");

            // Una segunda revision de una sola seccion reemplaza el resultado (no lo duplica).
            int antes = modelo.Secciones[0].Hallazgos.Count;
            modelo.RevisarAsync(Nexo.Ui.Desktop.Nucleo.SeccionDeSeguridad.Cuentas).GetAwaiter().GetResult();
            Check(modelo.Secciones[0].Hallazgos.Count == antes, "revisar otra vez las cuentas da lo mismo, no duplica los hallazgos", antes + " -> " + modelo.Secciones[0].Hallazgos.Count);
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
