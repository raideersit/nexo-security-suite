using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Inicio;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Modules.Cleanup.Platform;
using Nexo.Modules.Cleanup.Windows;
using Nexo.Reports;
using Nexo.Reports.Vault;

namespace Nexo.Cleanup.Run
{
    /// <summary>
    /// Ejecuta el limpiador contra el equipo REAL, con el catalogo de rutas
    /// verdadero. Tres modos, de menos a mas riesgo:
    ///
    ///   simulado   (por defecto) Recorre el flujo completo y lista lo que se
    ///              borraria. No toca el disco. Seguro en cualquier equipo.
    ///   papelera   Envia a la Papelera, reversible. Pide escribir BORRAR.
    ///   real       Borrado PERMANENTE. Se niega a ejecutarse si no es una VM.
    ///
    /// El rechazo del modo real no es un aviso: es codigo. La regla del proyecto
    /// ("nunca BorradorReal fuera de una VM") se hace cumplir aqui.
    /// </summary>
    public static class Program
    {
        private const string VariablePermiso = "NEXO_PERMITIR_BORRADO_REAL";

        public static async Task<int> Main(string[] args)
        {
            // Las rutas y los motivos ("—") no son ASCII. Sin esto la salida depende
            // de la pagina de codigos de la consola (850 imprime "?").
            Console.OutputEncoding = new UTF8Encoding(false);
            string modo = Opcion(args, "--modo") ?? "simulado";
            string? reglasArg = Opcion(args, "--reglas");
            string vaultRuta = Opcion(args, "--vault") ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "Vault");

            if (args.Contains("--ayuda") || args.Contains("-h")) { Ayuda(); return 0; }
            if (args.Length > 0 && args[0] == "arranque") return Arranque(args);
            if (args.Length > 0 && args[0] == "tareas") return Tareas(args);
            if (modo != "simulado" && modo != "papelera" && modo != "real")
            {
                Console.Error.WriteLine("Modo desconocido: " + modo + ". Usa simulado, papelera o real.");
                return 1;
            }

            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            (bool esVm, string equipo) = DetectorDeVm.Detectar();

            Console.WriteLine($"Modo: {modo}   Administrador: {(admin ? "si" : "no")}   Maquina virtual: {(esVm ? "si" : "no")} ({equipo})");

            // --- El modo real solo existe dentro de una VM ---
            if (modo == "real")
            {
                if (!esVm)
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine("RECHAZADO: el borrado permanente solo se ejecuta dentro de una maquina virtual.");
                    Console.Error.WriteLine("Este equipo no se reconoce como VM (" + equipo + "). No se ha tocado nada.");
                    return 2;
                }
                if (Environment.GetEnvironmentVariable(VariablePermiso) != "1")
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine($"RECHAZADO: define {VariablePermiso}=1 para confirmar que sabes lo que haces.");
                    return 2;
                }
            }

            IBorrador borrador = modo switch
            {
                "real" => new BorradorReal(),
                "papelera" => new BorradorPapelera(),
                _ => new BorradorSimulado()
            };

            var opciones = new VaultOptions { RutaVault = vaultRuta };   // redaccion por defecto: rutas relativas al perfil
            using var reportes = new ReportWriter(opciones);
            await reportes.InicializarVaultAsync().ConfigureAwait(false);

            var limpiador = new LimpiadorDeBasura(
                CatalogoDeRutas.Predeterminado(), ResolutorDeBases.DelSistema(),
                borrador, reportes, esAdministrador: admin);

            string[]? reglas = string.IsNullOrWhiteSpace(reglasArg)
                ? null
                : reglasArg.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            Console.WriteLine();
            Console.WriteLine("Calculando vista previa (no se borra nada)...");
            VistaPreviaLimpieza vista = await limpiador.PrepararVistaPreviaAsync(reglas).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(vista.Describir(maxEjemplos: 8));

            string lista = GuardarLista(vaultRuta, modo, vista);
            Console.WriteLine("Lista completa: " + lista);
            Console.WriteLine("(contiene rutas completas de tu equipo: no la compartas ni la subas a git)");

            if (vista.TotalArchivos == 0) return 0;

            if (modo != "simulado")
            {
                Console.WriteLine();
                Console.Write($"Se enviaran {vista.TotalArchivos} archivos a " +
                              (modo == "real" ? "BORRADO PERMANENTE" : "la Papelera") +
                              ". Escribe BORRAR para continuar: ");

                // Con la entrada redirigida ReadLine devuelve null: no hay nadie que confirme.
                string? respuesta = Console.IsInputRedirected ? null : Console.ReadLine();
                if (respuesta != "BORRAR")
                {
                    Console.WriteLine();
                    Console.WriteLine("Cancelado. No se ha tocado nada.");
                    return 3;
                }
            }

            ResultadoBorrado r = await limpiador.EjecutarAsync(vista, vista.Token).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(modo == "simulado"
                ? $"SIMULADO: se habrian eliminado {r.Eliminados} archivos ({Mb(r.BytesLiberados)}). No se toco el disco."
                : $"Eliminados: {r.Eliminados} ({Mb(r.BytesLiberados)}). Omitidos: {r.Omitidos.Count}.");
            foreach (string o in r.Omitidos.Take(10)) Console.WriteLine("  omitido: " + o);

            Console.WriteLine("Vault: " + vaultRuta);
            return 0;
        }

        /// <summary>
        /// Impacto de arranque que mide Windows (Diagnostics-Performance 100-103). SOLO LEE. Codigo de salida 2 =
        /// no concluyente: no se pudo leer, o no hay ningun arranque medido, asi que "nada lo retrasa" no se puede afirmar.
        /// </summary>
        private static int Arranque(string[] args)
        {
            int dias = 30;
            if (Opcion(args, "--dias") is { } d && (!int.TryParse(d, out dias) || dias < 1 || dias > 365))
            {
                Console.Error.WriteLine("--dias debe ser un entero entre 1 y 365.");
                return 1;
            }

            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            ResultadoDeArranque r = new AnalizadorDeArranque(new FuenteDeArranqueWindows()).Leer(DateTimeOffset.UtcNow.AddDays(-dias));

            Console.WriteLine("Administrador: " + (admin ? "si" : "no"));
            Console.WriteLine($"Periodo: ultimos {dias} dias   Registro: {FuenteDeArranqueWindows.Registro}");
            Console.WriteLine();

            if (r.Estado != EstadoDeLecturaDeArranque.Ok)
            {
                Console.WriteLine("NO SE PUDO LEER el registro: " + r.Motivo);
                Console.WriteLine("Esto no significa que el arranque este bien.");
                return 2;
            }

            if (r.Arranques.Count == 0)
                Console.WriteLine("Ningun arranque medido en el periodo. Windows solo los mide con el Servicio de directivas de diagnostico (DPS) en marcha.");
            else
            {
                Console.WriteLine($"Arranques medidos: {r.Arranques.Count}   mediana: {Seg(r.MedianaMs!.Value)}");
                foreach (ArranqueMedido a in r.Arranques.Take(5))
                    Console.WriteLine($"  {a.Cuando.ToLocalTime():yyyy-MM-dd HH:mm}  total {Seg(a.TotalMs),8}" +
                                      (a.PostArranqueMs is { } post ? $"   tras el inicio de sesion {Seg(post)}" : "") +
                                      (a.AppsDeInicio is { } n ? $"   apps de inicio: {n}" : "") +
                                      (a.EsDegradacion == true ? "   (Windows lo marco como lento)" : ""));
            }

            Console.WriteLine();
            if (r.Degradaciones.Count > 0)
            {
                Console.WriteLine("Lo que retraso el arranque (tardo mas de lo habitual):");
                foreach (DegradacionAgrupada g in r.Degradaciones.Take(20))
                    Console.WriteLine($"  {g.Veces,3}x  {Tipo(g.Tipo),-11} +{Seg(g.DegradacionMediaMs),-7} (max +{Seg(g.DegradacionMaximaMs)})  " +
                                      g.Nombre + (g.NombreAmigable is { } f ? "  (" + f + ")" : ""));
                if (r.Degradaciones.Count > 20) Console.WriteLine($"  ... y {r.Degradaciones.Count - 20} mas.");
            }

            var entradas = new RegistroInicioWindows().Enumerar();
            if (entradas.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Programas de inicio:");
                foreach (EntradaDeInicio e in entradas)
                {
                    DegradacionAgrupada? i = r.ImpactoDe(e);
                    string impacto = i is null ? "sin datos" : $"retraso {i.Veces}x, +{Seg(i.DegradacionMediaMs)} de media";
                    Console.WriteLine($"  {(e.Estado == EstadoDeInicio.Deshabilitada ? "x" : " ")} {e.Nombre,-30} {impacto}");
                }
                Console.WriteLine("  (\"sin datos\" no es \"no pesa\": Windows solo anota lo que tarda mas de lo habitual)");
            }

            Console.WriteLine();
            Console.WriteLine($"{r.EventosLeidos} eventos leidos, {r.Descartados} sin interpretar.");
            if (r.Truncada) Console.WriteLine("AVISO: hay mas eventos de los leidos; esto es lo mas reciente, no todo. Baja --dias.");
            if (r.Descartados > 0) Console.WriteLine("AVISO: eventos que no se pudieron interpretar no se cuentan.");

            if (r.PuedeAfirmarQueNadaLoRetraso)
                Console.WriteLine("Nada retraso el arranque en el periodo (segun lo que mide Windows).");
            else if (r.Arranques.Count == 0)
            {
                Console.WriteLine("RESULTADO NO CONCLUYENTE: sin arranques medidos no se puede decir nada del impacto.");
                return 2;
            }
            return 0;
        }

        /// <summary>
        /// Tareas programadas que se ejecutan al arrancar o al iniciar sesion. SOLO LEE. Codigo de salida 2 = lista
        /// incompleta (sin permisos para parte de la carpeta, tareas sin interpretar o truncada).
        /// </summary>
        private static int Tareas(string[] args)
        {
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            string carpeta = Opcion(args, "--carpeta") ?? LectorDeTareas.CarpetaDelSistema();
            InventarioDeTareas inv = LectorDeTareas.Leer(carpeta);

            Console.WriteLine("Administrador: " + (admin ? "si" : "no (la mayoria de las tareas solo las lee un administrador)"));
            Console.WriteLine("Carpeta: " + carpeta);
            Console.WriteLine();

            if (!inv.CarpetaDisponible)
            {
                Console.WriteLine("NO SE PUDO LEER: " + inv.Motivo);
                return 2;
            }

            // El impacto es opcional: si no se puede leer, se muestran las tareas sin el.
            ResultadoDeArranque arranque = new AnalizadorDeArranque(new FuenteDeArranqueWindows()).Leer(DateTimeOffset.UtcNow.AddDays(-30));

            foreach (TareaDeInicio t in inv.Tareas)
            {
                string cuando = string.Join(" + ", t.Disparadores.Select(d => d == DisparadorDeInicio.Arranque ? "al arrancar" : "al iniciar sesion"));
                var marcas = new System.Collections.Generic.List<string>();
                if (!t.Habilitada) marcas.Add("DESHABILITADA");
                if (t.Oculta) marcas.Add("oculta");
                if (t.MaximosPrivilegios) marcas.Add("maximos privilegios");
                if (t.Usuario == "S-1-5-18") marcas.Add("SYSTEM");
                if (t.Retraso is { } r && r > TimeSpan.Zero) marcas.Add("retraso " + r);
                Console.WriteLine($"  {t.Ruta}   [{cuando}]" + (marcas.Count > 0 ? "  (" + string.Join(", ", marcas) + ")" : ""));
                foreach (string c in t.Comandos)
                {
                    DegradacionAgrupada? i = arranque.ImpactoDeComando(c);
                    Console.WriteLine("      " + c + (i is null ? "" : $"   <- retraso el arranque {i.Veces}x, +{Seg(i.DegradacionMediaMs)} de media"));
                }
                if (t.TieneAccionCom) Console.WriteLine("      (accion COM: ejecuta codigo que no aparece como comando)");
            }

            Console.WriteLine();
            Console.WriteLine($"{inv.Tareas.Count} tareas de inicio en {inv.ArchivosLeidos} archivos leidos " +
                              $"({inv.Tareas.Count(t => t.EnCarpetaDeMicrosoft)} bajo \\Microsoft\\: es una carpeta, no una garantia).");
            foreach (string d in inv.Descartadas.Take(10)) Console.WriteLine("  sin interpretar: " + d);
            if (inv.Ilegibles.Count > 0)
                Console.WriteLine($"  {inv.Ilegibles.Count} archivos o carpetas sin permiso de lectura" + (admin ? "." : ": repite como administrador."));
            if (inv.Truncado) Console.WriteLine($"AVISO: se alcanzo el maximo de {LectorDeTareas.MaximoArchivos} archivos.");

            if (!inv.Completo)
            {
                Console.WriteLine("LISTA INCOMPLETA: puede haber tareas de inicio que no se ven aqui.");
                return 2;
            }
            return 0;
        }

        private static string Tipo(TipoDeDegradacion t) => t switch
        {
            TipoDeDegradacion.Aplicacion => "aplicacion",
            TipoDeDegradacion.Controlador => "controlador",
            _ => "servicio"
        };

        private static string Seg(long ms) => (ms / 1000.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + " s";

        private static string GuardarLista(string vaultRuta, string modo, VistaPreviaLimpieza vista)
        {
            Directory.CreateDirectory(vaultRuta);
            string ruta = Path.Combine(vaultRuta, $"lista-{modo}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");

            var sb = new StringBuilder();
            sb.Append("# ").Append(vista.TotalArchivos).Append(" archivos, ").Append(vista.TotalBytes).Append(" bytes\n");
            foreach (ElementoLimpiable e in vista.Elementos.OrderBy(e => e.Categoria).ThenBy(e => e.Ruta))
                sb.Append(e.Categoria).Append('\t').Append(e.Bytes).Append('\t').Append(e.Ruta).Append('\n');
            if (vista.RutasOmitidas.Count > 0)
            {
                sb.Append("\n# Omitido por el guardia\n");
                foreach (string o in vista.RutasOmitidas) sb.Append(o).Append('\n');
            }
            // Con BOM: Windows PowerShell 5.1 (Get-Content) y el Bloc de notas
            // antiguo leen como ANSI un UTF-8 sin BOM y rompen "—" y las tildes.
            File.WriteAllText(ruta, sb.ToString(), new UTF8Encoding(true));
            return ruta;
        }

        private static string? Opcion(string[] args, string nombre)
        {
            int i = Array.IndexOf(args, nombre);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }

        private static string Mb(long bytes) => (bytes / 1024.0 / 1024.0).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) + " MB";

        private static void Ayuda()
        {
            Console.WriteLine("nexo-cleanup [--modo simulado|papelera|real] [--reglas id1,id2] [--vault ruta]");
            Console.WriteLine("nexo-cleanup arranque [--dias N]   impacto de arranque medido por Windows (solo lee)");
            Console.WriteLine("nexo-cleanup tareas [--carpeta ruta]   tareas programadas al arrancar o iniciar sesion (solo lee)");
            Console.WriteLine();
            Console.WriteLine("  simulado  (defecto) lista lo que se borraria; no toca el disco");
            Console.WriteLine("  papelera  envia a la Papelera; pide escribir BORRAR");
            Console.WriteLine("  real      borrado permanente; SOLO dentro de una VM y con " + VariablePermiso + "=1");
        }
    }
}
