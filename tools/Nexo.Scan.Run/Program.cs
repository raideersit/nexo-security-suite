using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Cuarentena;
using Nexo.Modules.Threats.Escaner;
using Nexo.Reports;
using Nexo.Reports.Vault;

namespace Nexo.Scan.Run
{
    /// <summary>
    /// Escaner bajo demanda y cuarentena contra un clamd REAL (ClamAV).
    ///
    ///   estado                          ¿hay un clamd escuchando?
    ///   escanear &lt;ruta...&gt; [--cuarentena]
    ///   cuarentena listar
    ///   cuarentena restaurar &lt;id&gt; [--destino ruta]
    ///   cuarentena purgar
    ///
    /// Escanear no modifica nada. Con --cuarentena se muestra un plan y se pide
    /// escribir CUARENTENA; sin eso (o con la entrada redirigida) no se toca nada.
    /// El contenido de los archivos solo se envia a un clamd LOCAL.
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            if (args.Length == 0 || args[0] is "--ayuda" or "-h") { Ayuda(); return args.Length == 0 ? 1 : 0; }

            string host = Opcion(args, "--host") ?? "127.0.0.1";
            int puerto = int.TryParse(Opcion(args, "--puerto"), NumberStyles.None, CultureInfo.InvariantCulture, out int p)
                ? p : ClamdClient.PuertoPorDefecto;
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string vaultRuta = Opcion(args, "--vault") ?? Path.Combine(local, "Nexo", "Vault");
            string carpetaQ = Opcion(args, "--carpeta-cuarentena") ?? Path.Combine(local, "Nexo", "Quarantine");

            ClamdClient motor;
            try { motor = new ClamdClient(host, puerto); }
            catch (ArgumentException ex) { Console.Error.WriteLine(ex.Message); return 1; }

            using var reportes = new ReportWriter(new VaultOptions { RutaVault = vaultRuta });
            await reportes.InicializarVaultAsync().ConfigureAwait(false);
            var almacen = new AlmacenDeCuarentena(carpetaQ, reportes);

            switch (args[0].ToLowerInvariant())
            {
                case "estado": return await Estado(motor, host, puerto).ConfigureAwait(false);

                case "escanear":
                    string[] rutas = args.Skip(1).Where((a, i) => !a.StartsWith("--", StringComparison.Ordinal)
                                                                  && !EsValorDeOpcion(args, i + 1)).ToArray();
                    if (rutas.Length == 0) return Uso("Indica que escanear.");
                    return await Escanear(motor, reportes, almacen, rutas, args.Contains("--cuarentena"), vaultRuta)
                        .ConfigureAwait(false);

                case "cuarentena":
                    return await Cuarentena(almacen, args).ConfigureAwait(false);

                default:
                    return Uso("Comando desconocido: " + args[0]);
            }
        }

        private static async Task<int> Estado(ClamdClient motor, string host, int puerto)
        {
            try
            {
                Console.WriteLine("clamd en " + host + ":" + puerto + ": " + await motor.VersionAsync().ConfigureAwait(false));
                return 0;
            }
            catch (MotorNoDisponibleException ex)
            {
                Console.Error.WriteLine("clamd NO disponible: " + ex.Message);
                Console.Error.WriteLine();
                Console.Error.WriteLine("Instala ClamAV y arranca el demonio con TCP en 127.0.0.1:3310 (clamd.conf:");
                Console.Error.WriteLine("TCPSocket 3310, TCPAddr 127.0.0.1) y actualiza las firmas con freshclam.");
                Console.Error.WriteLine("Mejor en una maquina virtual, no en tu equipo principal.");
                return 2;
            }
        }

        private static async Task<int> Escanear(
            ClamdClient motor, IReportWriter reportes, AlmacenDeCuarentena almacen,
            string[] rutas, bool pedirCuarentena, string vaultRuta)
        {
            var escaner = new EscanerBajoDemanda(motor, reportes,
                new OpcionesDeEscaneo { Excluir = new[] { almacen.Carpeta } });

            ResultadoDeEscaneo r;
            try
            {
                var progreso = new Progress<ProgresoDeEscaneo>(p =>
                {
                    if (p.Analizados % 200 == 0 && p.Analizados > 0) Console.Error.WriteLine($"  ... {p.Analizados} archivos");
                });
                r = await escaner.EscanearAsync(rutas.Select(Path.GetFullPath), progreso).ConfigureAwait(false);
            }
            catch (MotorNoDisponibleException ex)
            {
                Console.Error.WriteLine("No se escaneo nada: " + ex.Message);
                return 2;
            }

            Console.WriteLine($"Motor: {r.Motor} — {r.MotorVersion}");
            Console.WriteLine($"Analizados: {r.Analizados}   Detecciones: {r.Detecciones.Count}   " +
                              $"NO analizados: {r.Omitidos.Count}   Duracion: {r.Duracion.TotalSeconds:0.0} s");
            if (r.Incompleto) Console.WriteLine("ESCANEO INCOMPLETO: " + r.MotivoIncompleto);

            foreach (Deteccion d in r.Detecciones) Console.WriteLine($"  DETECTADO  {d.Firma}  {d.Ruta}");
            foreach (string o in r.Omitidos.Take(15)) Console.WriteLine("  no analizado: " + o);
            if (r.Omitidos.Count > 15) Console.WriteLine($"  ... y {r.Omitidos.Count - 15} mas");

            Console.WriteLine();
            Console.WriteLine(r.CompletamenteLimpio
                ? "Sin hallazgos, y se pudo analizar todo."
                : r.Detecciones.Count == 0
                    ? "Sin detecciones, PERO hay archivos que no se pudieron analizar: no se puede asegurar que este limpio."
                    : "Hay detecciones. Revisalas antes de actuar: un falso positivo existe.");
            Console.WriteLine("Vault: " + vaultRuta);

            if (r.Detecciones.Count == 0 || !pedirCuarentena) return r.Detecciones.Count > 0 ? 10 : (r.CompletamenteLimpio ? 0 : 11);

            VistaPreviaCuarentena vista = almacen.Preparar(r.Detecciones);
            Console.WriteLine();
            Console.WriteLine(vista.Describir());
            if (!vista.HayCambios) return 10;

            Console.Write("Escribe CUARENTENA para continuar: ");
            string? respuesta = Console.IsInputRedirected ? null : Console.ReadLine();
            if (respuesta != "CUARENTENA") { Console.WriteLine("\nCancelado. No se ha tocado nada."); return 3; }

            ResultadoCuarentena rq = await almacen.AplicarAsync(vista, vista.Token).ConfigureAwait(false);
            Console.WriteLine();
            Console.WriteLine($"En cuarentena: {rq.Movidos.Count}. Omitidos: {rq.Omitidos.Count}.");
            foreach (ElementoDeCuarentena e in rq.Movidos) Console.WriteLine($"  {e.Id}  {e.RutaOriginal}");
            foreach (string o in rq.Omitidos) Console.WriteLine("  omitido: " + o);
            if (rq.Movidos.Count > 0) Console.WriteLine("Para deshacerlo: nexo-scan cuarentena restaurar <id>");
            return rq.Omitidos.Count == 0 ? 10 : 5;
        }

        private static async Task<int> Cuarentena(AlmacenDeCuarentena almacen, string[] args)
        {
            string sub = args.Length > 1 ? args[1].ToLowerInvariant() : "";
            switch (sub)
            {
                case "listar":
                    var items = almacen.Listar();
                    if (items.Count == 0) { Console.WriteLine("La cuarentena esta vacia (" + almacen.Carpeta + ")."); return 0; }
                    foreach (ElementoDeCuarentena e in items)
                        Console.WriteLine($"  {e.Id}  {e.Fecha:yyyy-MM-dd HH:mm}  {e.Firma}  {e.RutaOriginal}");
                    return 0;

                case "restaurar":
                    string? id = args.Length > 2 ? args[2] : null;
                    if (id is null || id.StartsWith("--", StringComparison.Ordinal)) return Uso("Falta el id.");
                    ResultadoRestauracion r = await almacen.RestaurarAsync(id, Opcion(args, "--destino")).ConfigureAwait(false);
                    Console.WriteLine(r.Exito ? "Restaurado en " + r.Ruta : "No se restauro: " + r.Motivo);
                    return r.Exito ? 0 : 4;

                case "purgar":
                    VistaPreviaPurga vista = almacen.PrepararPurga();
                    Console.WriteLine(vista.Describir());
                    if (!vista.HayCambios) return 0;

                    Console.Write("Escribe PURGAR para eliminarlas definitivamente: ");
                    string? respuesta = Console.IsInputRedirected ? null : Console.ReadLine();
                    if (respuesta != "PURGAR") { Console.WriteLine(Environment.NewLine + "Cancelado. No se ha tocado nada."); return 3; }

                    ResultadoPurga rp = await almacen.AplicarPurgaAsync(vista, vista.Token).ConfigureAwait(false);
                    Console.WriteLine();
                    Console.WriteLine($"Purgadas: {rp.Purgados.Count}. Omitidas: {rp.Omitidos.Count}.");
                    foreach (string o in rp.Omitidos) Console.WriteLine("  omitida: " + o);
                    return rp.Omitidos.Count == 0 ? 0 : 5;

                default:
                    return Uso("Usa: cuarentena listar | cuarentena restaurar <id> [--destino ruta] | cuarentena purgar");
            }
        }

        private static bool EsValorDeOpcion(string[] args, int indice)
            => indice > 0 && indice < args.Length && args[indice - 1] is "--host" or "--puerto" or "--vault" or "--carpeta-cuarentena" or "--destino";

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
            Console.WriteLine("nexo-scan <comando> [opciones]");
            Console.WriteLine();
            Console.WriteLine("  estado                              ¿hay un clamd escuchando?");
            Console.WriteLine("  escanear <ruta...> [--cuarentena]   no modifica nada; con --cuarentena pide CUARENTENA");
            Console.WriteLine("  cuarentena listar");
            Console.WriteLine("  cuarentena restaurar <id> [--destino ruta]");
            Console.WriteLine("  cuarentena purgar                   elimina lo que supero los 30 dias; pide PURGAR");
            Console.WriteLine();
            Console.WriteLine("  --host 127.0.0.1 --puerto 3310     solo se aceptan direcciones locales");
            Console.WriteLine("  --carpeta-cuarentena <ruta>        por defecto %LOCALAPPDATA%\\Nexo\\Quarantine");
            Console.WriteLine();
            Console.WriteLine("Codigos de salida: 0 limpio; 10 con detecciones; 11 sin detecciones pero con archivos");
            Console.WriteLine("no analizados; 2 sin motor; 3 cancelado.");
        }
    }
}
