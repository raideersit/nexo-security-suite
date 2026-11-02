using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Firewall;
using Nexo.Modules.Threats.Windows;
using Nexo.Reports;
using Nexo.Reports.Vault;

namespace Nexo.Firewall.Run
{
    /// <summary>
    /// Administra el Firewall de Windows por aplicacion, contra el equipo REAL.
    ///
    ///   estado                       perfiles, modo sigiloso y reglas de Nexo
    ///   listar                       solo las reglas que creo Nexo
    ///   bloquear  &lt;exe&gt; [--entrante|--saliente]
    ///   permitir  &lt;exe&gt; [--entrante|--saliente]
    ///   quitar    "&lt;nombre de la regla&gt;"
    ///   sigiloso  on|off
    ///
    /// Los comandos que cambian algo muestran primero el plan y piden escribir
    /// APLICAR. Sin esa confirmacion (o con la entrada redirigida) no se toca nada.
    /// Escribir en el firewall exige administrador; ver el plan no.
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            if (args.Length == 0 || args[0] is "--ayuda" or "-h") { Ayuda(); return args.Length == 0 ? 1 : 0; }

            string vaultRuta = Opcion(args, "--vault") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "Vault");

            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

            using var reportes = new ReportWriter(new VaultOptions { RutaVault = vaultRuta });
            await reportes.InicializarVaultAsync().ConfigureAwait(false);
            // Lista opcional de procesos que ademas NO se deben bloquear. Solo amplia la proteccion.
            string protegidosRuta = Opcion(args, "--protegidos") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "firewall-protegidos.txt");
            var adicionales = GuardiaDeReglas.LeerAdicionales(protegidosRuta, out var ignoradas);
            foreach (string i in ignoradas)
                Console.Error.WriteLine("Aviso: se ignora '" + i + "' en " + protegidosRuta + " (solo nombres de ejecutable).");
            var adm = new AdministradorDeFirewall(new AlmacenDeFirewallWindows(), reportes, admin,
                new GuardiaDeReglas(adicionales: adicionales));

            string comando = args[0].ToLowerInvariant();
            string? objetivo = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));

            switch (comando)
            {
                case "estado": return Estado(adm, admin);
                case "listar": return Listar(adm);
                case "bloqueos": return await Bloqueos(args, reportes, admin).ConfigureAwait(false);

                case "bloquear":
                case "permitir":
                    if (objetivo is null) return Uso("Falta la ruta del ejecutable.");
                    DireccionDeRegla? dir = args.Contains("--entrante") ? DireccionDeRegla.Entrante
                                          : args.Contains("--saliente") ? DireccionDeRegla.Saliente : null;
                    return await Confirmar(adm,
                        adm.PrepararRegla(objetivo, comando == "bloquear" ? AccionDeRegla.Bloquear : AccionDeRegla.Permitir, dir),
                        admin).ConfigureAwait(false);

                case "quitar":
                    if (objetivo is null) return Uso("Falta el nombre de la regla.");
                    return await Confirmar(adm, adm.PrepararQuitar(objetivo), admin).ConfigureAwait(false);

                case "sigiloso":
                    if (objetivo is not ("on" or "off")) return Uso("Usa: sigiloso on|off");
                    return await Confirmar(adm, adm.PrepararSigiloso(objetivo == "on"), admin).ConfigureAwait(false);

                default:
                    return Uso("Comando desconocido: " + args[0]);
            }
        }

        private static int Estado(AdministradorDeFirewall adm, bool admin)
        {
            Console.WriteLine("Administrador: " + (admin ? "si" : "no (puedes ver el plan, no aplicarlo)"));
            Console.WriteLine();
            foreach (PoliticaDePerfil p in adm.LeerPoliticas())
                Console.WriteLine($"  {p.Perfil,-8} firewall {(p.FirewallActivo ? "activo" : "DESACTIVADO")}   " +
                                  $"entrada: {p.EntradaPorDefecto}   salida: {p.SalidaPorDefecto}");
            Console.WriteLine();
            Console.WriteLine("Modo sigiloso: " + (adm.SigilosoActivo() ? "ACTIVO" : "desactivado"));
            Console.WriteLine("Reglas de Nexo: " + adm.ListarDeNexo().Count);
            return 0;
        }

        private static int Listar(AdministradorDeFirewall adm)
        {
            var reglas = adm.ListarDeNexo();
            if (reglas.Count == 0) { Console.WriteLine("Nexo no ha creado reglas."); return 0; }
            foreach (ReglaDeFirewall r in reglas)
                Console.WriteLine($"  {(r.Habilitada ? " " : "x")} {r.Nombre}");
            Console.WriteLine();
            Console.WriteLine(reglas.Count + " reglas (x = deshabilitada).");
            return 0;
        }

        /// <summary>
        /// Conexiones que el firewall bloqueo (evento 5157). SOLO LEE: no activa la auditoria ni cambia nada;
        /// escribe notas en el vault unicamente con --registrar. Codigo de salida 2 = no concluyente: no se pudo
        /// leer o la auditoria esta apagada, asi que "ningun bloqueo" no es una afirmacion que se pueda hacer.
        /// </summary>
        private static async Task<int> Bloqueos(string[] args, IReportWriter reportes, bool admin)
        {
            double horas = 24;
            if (Opcion(args, "--horas") is { } h && (!double.TryParse(h, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out horas) || horas <= 0 || horas > 24 * 365))
                return Uso("--horas debe ser un numero entre 0 y 8760.");
            int maximo = LectorDeBloqueos.MaximoPorDefecto;
            if (Opcion(args, "--max") is { } m && (!int.TryParse(m, out maximo) || maximo < 1 || maximo > 100_000))
                return Uso("--max debe ser un entero entre 1 y 100000.");

            DateTimeOffset desde = DateTimeOffset.UtcNow.AddHours(-horas);
            ResultadoDeBloqueos r = new LectorDeBloqueos(new FuenteDeBloqueosWindows()).Leer(desde, maximo);

            Console.WriteLine("Administrador: " + (admin ? "si" : "no (el registro de Seguridad exige administrador)"));
            Console.WriteLine("Auditoria de fallos de 'Filtering Platform Connection': " +
                (r.AuditoriaActiva switch { true => "activa", false => "APAGADA", _ => "no se pudo comprobar" }));
            Console.WriteLine($"Periodo: ultimas {horas.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)} h");
            Console.WriteLine();

            if (r.Estado != EstadoDeFuente.Ok)
            {
                Console.WriteLine("NO SE PUDO LEER el registro de Seguridad: " + r.Motivo);
                Console.WriteLine("Esto no significa que no haya habido bloqueos.");
                return 2;
            }

            foreach (BloqueoAgrupado g in r.Grupos.Take(30))
                Console.WriteLine($"  {g.Repeticiones,5}x  {(g.Direccion == DireccionDeRegla.Entrante ? "entrante" : "saliente")}  " +
                                  $"{g.Protocolo,-6} {g.IpRemota}:{g.PuertoRemoto}  {g.Aplicacion}");
            if (r.Grupos.Count > 30) Console.WriteLine($"  ... y {r.Grupos.Count - 30} grupos mas.");

            Console.WriteLine();
            Console.WriteLine($"{r.EventosLeidos} eventos leidos, {r.Grupos.Count} grupos distintos, {r.Descartados} sin interpretar.");
            if (r.Truncada) Console.WriteLine($"AVISO: hay mas eventos de los leidos (maximo {maximo}); esto es lo mas reciente, no todo. Sube --max o baja --horas.");
            if (r.Descartados > 0) Console.WriteLine("AVISO: eventos que no se pudieron interpretar no se cuentan como bloqueos.");

            if (r.PuedeAfirmarQueNoHuboBloqueos)
                Console.WriteLine("Sin bloqueos en el periodo (registro leido, auditoria activa).");
            else if (r.Grupos.Count == 0)
            {
                Console.WriteLine("RESULTADO NO CONCLUYENTE: no hay bloqueos que mostrar, pero eso no prueba que no los hubiera.");
                if (r.AuditoriaActiva != true)
                    Console.WriteLine("Windows no escribe estos eventos si la auditoria esta apagada. Para activarla (decision tuya, llena el registro):\n" +
                                      "  auditpol /set /subcategory:\"Filtering Platform Connection\" /failure:enable");
                return 2;
            }

            if (args.Contains("--registrar"))
            {
                int sin = await LectorDeBloqueos.RegistrarAsync(r, reportes).ConfigureAwait(false);
                Console.WriteLine($"Anotados en el vault: {Math.Min(r.Grupos.Count, 50)}" + (sin > 0 ? $" ({sin} grupos menos repetidos quedaron sin anotar)." : "."));
            }
            return 0;
        }

        private static async Task<int> Confirmar(AdministradorDeFirewall adm, VistaPreviaFirewall vista, bool admin)
        {
            Console.WriteLine(vista.Describir());

            if (!vista.HayCambios) { Console.WriteLine("No hay nada que aplicar."); return vista.Rechazos.Count > 0 ? 4 : 0; }

            if (!admin)
            {
                Console.WriteLine("Para aplicarlo hace falta una consola de administrador. No se ha tocado nada.");
                return 2;
            }

            Console.Write("Escribe APLICAR para continuar: ");
            string? respuesta = Console.IsInputRedirected ? null : Console.ReadLine();
            if (respuesta != "APLICAR")
            {
                Console.WriteLine();
                Console.WriteLine("Cancelado. No se ha tocado nada.");
                return 3;
            }

            ResultadoFirewall r = await adm.AplicarAsync(vista, vista.Token).ConfigureAwait(false);
            Console.WriteLine();
            Console.WriteLine($"Aplicados: {r.Aplicados}. Omitidos: {r.Omitidos.Count}.");
            foreach (string o in r.Omitidos) Console.WriteLine("  omitido: " + o);
            return r.Omitidos.Count == 0 ? 0 : 5;
        }

        private static int Uso(string mensaje)
        {
            Console.Error.WriteLine(mensaje);
            Ayuda();
            return 1;
        }

        private static string? Opcion(string[] args, string nombre)
        {
            int i = Array.IndexOf(args, nombre);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }

        private static void Ayuda()
        {
            Console.WriteLine("nexo-firewall <comando> [opciones]");
            Console.WriteLine();
            Console.WriteLine("  estado                              perfiles, modo sigiloso y reglas de Nexo");
            Console.WriteLine("  listar                              reglas creadas por Nexo");
            Console.WriteLine("  bloquear <exe> [--entrante|--saliente]   sin opcion: ambas direcciones");
            Console.WriteLine("  permitir <exe> [--entrante|--saliente]");
            Console.WriteLine("  quitar \"<nombre de la regla>\"        solo reglas de Nexo");
            Console.WriteLine("  sigiloso on|off                     bloquea el ping entrante (ICMPv4 e ICMPv6)");
            Console.WriteLine("  bloqueos [--horas N] [--max N] [--registrar]   conexiones que el firewall bloqueo (solo lee;");
            Console.WriteLine("                                      exige administrador y la auditoria de 'Filtering Platform Connection')");
            Console.WriteLine();
            Console.WriteLine("Los cambios muestran un plan y piden escribir APLICAR. Escribir en el");
            Console.WriteLine("firewall requiere una consola de administrador. Nunca bloquea procesos del");
            Console.WriteLine("sistema ni Windows Defender, y solo toca reglas del grupo 'Nexo Security Suite'.");
        }
    }
}
