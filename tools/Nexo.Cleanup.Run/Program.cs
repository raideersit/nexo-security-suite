using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
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
            Console.WriteLine();
            Console.WriteLine("  simulado  (defecto) lista lo que se borraria; no toca el disco");
            Console.WriteLine("  papelera  envia a la Papelera; pide escribir BORRAR");
            Console.WriteLine("  real      borrado permanente; SOLO dentro de una VM y con " + VariablePermiso + "=1");
        }
    }
}
