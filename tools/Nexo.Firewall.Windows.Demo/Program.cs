using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Firewall;
using Nexo.Modules.Threats.Windows;
using Nexo.Reports;
using Nexo.Reports.Vault;

namespace Nexo.Firewall.Windows.Demo
{
    /// <summary>
    /// Comprobaciones contra el Firewall de Windows REAL (INetFwPolicy2).
    ///
    /// Sin administrador solo se lee. Con administrador se crean reglas
    /// temporales sobre un .exe sintetico (jamas sobre un programa real), se
    /// leen de vuelta con un almacen nuevo para comprobar que Windows las guardo
    /// como se pidio, y se borran. El bloque finally retira cualquier regla que
    /// el arnes haya dejado, haya fallado lo que haya fallado.
    /// </summary>
    public static class Program
    {
        private static int _fallos;

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            Console.WriteLine("Administrador: " + (admin ? "si" : "no"));
            Console.WriteLine();

            string raiz = Path.Combine(Path.GetTempPath(), "nexo-firewall-demo-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(raiz);
            string exe = Path.Combine(raiz, "prueba-fw-sintetica.exe");
            File.WriteAllText(exe, "no es un ejecutable real; solo existe para que la ruta sea valida");

            var almacen = new AlmacenDeFirewallWindows();
            var creadas = new List<string>();

            try
            {
                LecturaDelFirewall(almacen);

                using var reportes = new ReportWriter(new VaultOptions { RutaVault = Path.Combine(raiz, "vault") });
                await reportes.InicializarVaultAsync().ConfigureAwait(false);
                var adm = new AdministradorDeFirewall(almacen, reportes, admin);

                LecturaDeBloqueos(admin);

                if (admin) await EscrituraReal(adm, almacen, exe, creadas, raiz).ConfigureAwait(false);
                else await SinAdministrador(adm, exe).ConfigureAwait(false);
            }
            finally
            {
                // Pase lo que pase, el firewall queda como estaba.
                foreach (string nombre in creadas)
                {
                    try { almacen.Eliminar(nombre); }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is InvalidOperationException)
                    {
                        Console.WriteLine("  [AVISO] No se pudo retirar la regla de prueba '" + nombre + "': " + ex.Message);
                        _fallos++;
                    }
                }
                try { Directory.Delete(raiz, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        // ============================================================
        private static void LecturaDelFirewall(AlmacenDeFirewallWindows almacen)
        {
            Console.WriteLine("1. Lectura del Firewall de Windows (no necesita administrador)");

            IReadOnlyList<PoliticaDePerfil> politicas = almacen.LeerPoliticas();
            foreach (PoliticaDePerfil p in politicas)
                Console.WriteLine($"      perfil {p.Perfil,-8} activo: {(p.FirewallActivo ? "si" : "NO")}   " +
                                  $"entrada por defecto: {p.EntradaPorDefecto}   salida por defecto: {p.SalidaPorDefecto}");
            Check(politicas.Count == 3, "lee los 3 perfiles (dominio, privado, publico)");

            IReadOnlyList<ReglaDeFirewall> reglas = almacen.Enumerar();
            Console.WriteLine($"      {reglas.Count} reglas en total, {reglas.Count(r => r.EsDeNexo)} de Nexo");
            Check(reglas.Count > 0, "enumera las reglas existentes");
            Check(reglas.Any(r => r.RutaApp is not null), "lee la ruta de aplicacion de las reglas por programa");
            Check(reglas.Any(r => r.Direccion == DireccionDeRegla.Entrante) && reglas.Any(r => r.Direccion == DireccionDeRegla.Saliente),
                  "distingue reglas entrantes y salientes");
            Check(reglas.Any(r => r.Accion == AccionDeRegla.Bloquear) || reglas.Any(r => r.Accion == AccionDeRegla.Permitir),
                  "lee la accion (bloquear/permitir)");
            Check(reglas.Any(r => r.Protocolo == 1 || r.Protocolo == 58),
                  "lee las reglas ICMP (Windows trae las de ping, deshabilitadas o no)");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task SinAdministrador(AdministradorDeFirewall adm, string exe)
        {
            Console.WriteLine("2. Sin administrador: se planea, pero no se escribe nada");

            int antes = adm.ListarDeNexo().Count;
            VistaPreviaFirewall v = adm.PrepararRegla(exe, AccionDeRegla.Bloquear);
            Check(v.Cambios.Count == 2, "el plan se puede calcular sin administrador");

            ResultadoFirewall r = await adm.AplicarAsync(v, v.Token).ConfigureAwait(false);
            Check(r.Aplicados == 0 && r.Omitidos.Count == 2, "al aplicar informa que requiere administrador");
            Check(adm.ListarDeNexo().Count == antes, "y el firewall no cambio");
            Console.WriteLine("      (ejecuta este arnes como administrador para probar la escritura real)");
        }

        // ============================================================
        private static async Task EscrituraReal(
            AdministradorDeFirewall adm, AlmacenDeFirewallWindows almacen, string exe, List<string> creadas, string raiz)
        {
            Console.WriteLine("2. Regla por aplicacion contra el firewall real");

            int totalAntes = almacen.Enumerar().Count;
            int nexoAntes = adm.ListarDeNexo().Count;

            VistaPreviaFirewall v = adm.PrepararRegla(exe, AccionDeRegla.Bloquear);
            foreach (CambioDeFirewall c in v.Cambios) creadas.Add(c.Regla.Nombre);
            Check(almacen.Enumerar().Count == totalAntes, "planear no escribe en el firewall");

            ResultadoFirewall r = await adm.AplicarAsync(v, v.Token).ConfigureAwait(false);
            Check(r.Aplicados == 2 && r.Omitidos.Count == 0, "Windows acepta las 2 reglas (saliente y entrante)",
                  string.Join("; ", r.Omitidos));

            // Lectura con un almacen NUEVO: lo que Windows guardo, no lo que enviamos.
            var leidas = new AlmacenDeFirewallWindows().Enumerar().Where(x => creadas.Contains(x.Nombre)).ToList();
            Check(leidas.Count == 2, "las reglas persisten y se leen de vuelta");
            Check(leidas.All(x => x.Accion == AccionDeRegla.Bloquear && x.Habilitada), "guardadas como BLOQUEAR y habilitadas");
            Check(leidas.All(x => string.Equals(x.RutaApp, exe, StringComparison.OrdinalIgnoreCase)),
                  "con la ruta exacta del ejecutable");
            Check(leidas.Any(x => x.Direccion == DireccionDeRegla.Saliente) && leidas.Any(x => x.Direccion == DireccionDeRegla.Entrante),
                  "una saliente y una entrante");
            Check(leidas.All(x => x.Perfiles == PerfilesDeRed.Todos), "en los tres perfiles");
            Check(leidas.All(x => x.EsDeNexo), "marcadas con el grupo de Nexo");
            Check(adm.ListarDeNexo().Count == nexoAntes + 2, "ListarDeNexo las incluye");

            VistaPreviaFirewall dup = adm.PrepararRegla(exe, AccionDeRegla.Bloquear);
            Check(!dup.HayCambios, "pedirlas otra vez se detecta como duplicado contra el firewall real");

            // Quitar
            foreach (ReglaDeFirewall regla in leidas)
            {
                VistaPreviaFirewall q = adm.PrepararQuitar(regla.Nombre);
                ResultadoFirewall rq = await adm.AplicarAsync(q, q.Token).ConfigureAwait(false);
                Check(rq.Aplicados == 1, "quita '" + regla.Nombre + "'");
            }
            creadas.Clear();
            Check(almacen.Enumerar().Count == totalAntes, "el firewall vuelve exactamente al numero de reglas inicial");

            // Una regla de Windows no se puede quitar desde Nexo.
            ReglaDeFirewall? ajena = almacen.Enumerar().FirstOrDefault(x => !x.EsDeNexo);
            if (ajena is not null)
            {
                VistaPreviaFirewall qa = adm.PrepararQuitar(ajena.Nombre);
                Check(!qa.HayCambios && qa.Rechazos.Count == 1, "se niega a quitar una regla real de Windows ('" + Corto(ajena.Nombre) + "')");
            }

            // Un proceso protegido no se bloquea.
            string svchost = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe");
            VistaPreviaFirewall sv = adm.PrepararRegla(svchost, AccionDeRegla.Bloquear);
            Check(!sv.HayCambios && sv.Rechazos.Count == 1, "se niega a bloquear el svchost.exe real");

            Console.WriteLine();
            await Sigiloso(adm, almacen, creadas, raiz).ConfigureAwait(false);
        }

        private static async Task Sigiloso(
            AdministradorDeFirewall adm, AlmacenDeFirewallWindows almacen, List<string> creadas, string raiz)
        {
            Console.WriteLine("3. Modo sigiloso contra el firewall real");

            if (adm.SigilosoActivo() || almacen.Enumerar().Any(x => x.Nombre == AdministradorDeFirewall.NombrePingV4
                                                                     || x.Nombre == AdministradorDeFirewall.NombrePingV6))
            {
                Console.WriteLine("  [AVISO] El modo sigiloso ya esta (total o parcialmente) activo en este equipo;");
                Console.WriteLine("          no se prueba para no desactivarte una proteccion que ya tenias.");
                return;
            }

            int totalAntes = almacen.Enumerar().Count;

            VistaPreviaFirewall on = adm.PrepararSigiloso(true);
            Console.WriteLine(Sangrar(on.Describir()));
            foreach (CambioDeFirewall c in on.Cambios) creadas.Add(c.Regla.Nombre);

            ResultadoFirewall r = await adm.AplicarAsync(on, on.Token).ConfigureAwait(false);
            Check(r.Aplicados == 2 && r.Omitidos.Count == 0, "Windows acepta las 2 reglas de ping", string.Join("; ", r.Omitidos));
            Check(adm.SigilosoActivo(), "SigilosoActivo() lo detecta leyendo el firewall real");

            var ping4 = new AlmacenDeFirewallWindows().Enumerar().FirstOrDefault(x => x.Nombre == AdministradorDeFirewall.NombrePingV4);
            var ping6 = new AlmacenDeFirewallWindows().Enumerar().FirstOrDefault(x => x.Nombre == AdministradorDeFirewall.NombrePingV6);
            Check(ping4 is { Protocolo: 1, TiposIcmp: "8:*", Direccion: DireccionDeRegla.Entrante, Accion: AccionDeRegla.Bloquear },
                  "ICMPv4: protocolo 1, tipo 8, entrante, bloquear", ping4?.ToString());
            Check(ping6 is { Protocolo: 58, TiposIcmp: "128:*", Direccion: DireccionDeRegla.Entrante, Accion: AccionDeRegla.Bloquear },
                  "ICMPv6: protocolo 58, tipo 128, entrante, bloquear", ping6?.ToString());

            VistaPreviaFirewall off = adm.PrepararSigiloso(false);
            ResultadoFirewall roff = await adm.AplicarAsync(off, off.Token).ConfigureAwait(false);
            creadas.Clear();
            Check(roff.Aplicados == 2 && !adm.SigilosoActivo(), "desactivarlo retira las 2 reglas");
            Check(almacen.Enumerar().Count == totalAntes, "el firewall vuelve exactamente al numero de reglas inicial");

            // El vault debe tener las notas.
            int notas = Directory.Exists(Path.Combine(raiz, "vault"))
                ? Directory.EnumerateFiles(Path.Combine(raiz, "vault"), "*.md", SearchOption.AllDirectories)
                           .Count(f => Path.GetFileName(f).Contains("firewall", StringComparison.OrdinalIgnoreCase)
                                       || Path.GetFileName(f).Contains("sigiloso", StringComparison.OrdinalIgnoreCase))
                : 0;
            Check(notas >= 6, "el vault tiene las notas de los cambios (reglas y modo sigiloso)", "notas: " + notas);
            Console.WriteLine("      NOTA: no se probo el ping real. El trafico hacia la propia maquina va por loopback");
            Console.WriteLine("            y no pasa por el filtro; hace falta otro equipo de la red para verlo.");
        }

        /// <summary>
        /// Bloqueos reales (evento 5157) del registro de Seguridad. Solo lee. Sin administrador la fuente debe
        /// decir "no pude leer"; con administrador debe leer de verdad y saber si la auditoria esta activa.
        /// El resultado depende de la politica de auditoria del equipo, asi que se informa en vez de exigirlo.
        /// </summary>
        private static void LecturaDeBloqueos(bool admin)
        {
            Console.WriteLine("Bloqueos del firewall (registro de Seguridad, solo lectura)");

            ResultadoDeBloqueos r = new LectorDeBloqueos(new FuenteDeBloqueosWindows())
                .Leer(DateTimeOffset.UtcNow.AddDays(-7), maximo: 2000);

            if (!admin)
            {
                Check(r.Estado == EstadoDeFuente.SinPermisos && r.Grupos.Count == 0,
                      "sin administrador la fuente dice SinPermisos (no 'cero bloqueos')", "estado: " + r.Estado + " " + r.Motivo);
                Check(!r.PuedeAfirmarQueNoHuboBloqueos && r.ResultadoNoConcluyente,
                      "y el resultado es no concluyente");
                Check(r.AuditoriaActiva is null, "y no inventa si la auditoria esta activa (sin permisos: no se sabe)",
                      "auditoria: " + r.AuditoriaActiva);
                return;
            }

            Check(r.Estado == EstadoDeFuente.Ok, "como administrador se lee el registro de Seguridad", "estado: " + r.Estado + " " + r.Motivo);
            Check(r.AuditoriaActiva is not null, "como administrador se sabe si la auditoria de 'Filtering Platform Connection' esta activa");
            Console.WriteLine($"      INFO: auditoria de fallos: {(r.AuditoriaActiva switch { true => "activa", false => "apagada", _ => "?" })}; " +
                              $"{r.EventosLeidos} eventos en 7 dias, {r.Grupos.Count} grupos, {r.Descartados} sin interpretar.");
            // Si hay eventos reales, ninguno deberia haberse descartado: el analizador debe entender lo que Windows escribe.
            Check(r.Descartados == 0, "los eventos 5157 reales se interpretan todos (ninguno descartado)", "descartados: " + r.Descartados);
            if (r.AuditoriaActiva == false && r.EventosLeidos == 0)
                Console.WriteLine("      NOTA: con la auditoria apagada no hay eventos que probar; activala (auditpol, ver 'nexo-firewall bloqueos') y repite.");
        }

        private static string Corto(string s) => s.Length > 40 ? s[..40] + "..." : s;

        private static string Sangrar(string texto)
            => string.Join(Environment.NewLine, texto.TrimEnd().Split('\n').Select(l => "      " + l.TrimEnd('\r')));
    }
}
