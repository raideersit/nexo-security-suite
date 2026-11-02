using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Inicio;
using Nexo.Modules.Cleanup.Windows;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Cleanup.Windows.Demo
{
    /// <summary>
    /// Arnes de las comprobaciones que solo tienen sentido en Windows.
    ///
    /// Todo lo que escribe lo hace sobre material sintetico y propio:
    ///   - una subclave temporal de HKCU (nunca la configuracion de inicio real),
    ///   - carpetas de inicio falsas dentro de %TEMP%,
    ///   - archivos de prueba que se envian a la Papelera (recuperables).
    /// Nada toca el perfil del usuario ni el catalogo real de rutas.
    /// </summary>
    public static class Program
    {
        private static int _fallos;

        private sealed class RegistroDeEventos : IReportWriter
        {
            public List<NexoEvent> Eventos { get; } = new List<NexoEvent>();

            public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
            {
                Eventos.Add(evento);
                return Task.FromResult(new NoteRef(evento.Id, "(memoria)", evento.Titulo, false));
            }

            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new System.Text.UTF8Encoding(false);
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            Console.WriteLine("Administrador: " + (admin ? "si" : "no"));
            Console.WriteLine();

            ProbarMedio();
            await ProbarInicio(admin).ConfigureAwait(false);
            ProbarArranque(admin);
            ProbarPapelera();
            await ProbarSalud().ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(_fallos == 0
                ? "TODAS LAS VERIFICACIONES PASARON"
                : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        // ============================================================
        //  1. TIPO DE DISCO
        // ============================================================
        private static void ProbarMedio()
        {
            Console.WriteLine("1. Tipo de disco (IOCTL_STORAGE_QUERY_PROPERTY)");
            var detector = new DetectorDeMedioWindows();

            foreach (DriveInfo d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
            {
                Console.WriteLine($"      {d.Name,-4} {detector.Detectar(d.Name)}");
            }

            string sistema = Path.GetPathRoot(Environment.SystemDirectory)!;
            MedioDeAlmacenamiento m = detector.Detectar(sistema);
            Console.WriteLine($"      (el volumen del sistema es {sistema}: {m}; contrastar a mano con Get-PhysicalDisk)");

            Check(detector.Detectar(@"\\servidor\recurso\x.txt") == MedioDeAlmacenamiento.Desconocido,
                  "una ruta de red se reporta como desconocida");
            Check(detector.Detectar("") == MedioDeAlmacenamiento.Desconocido,
                  "una ruta vacia se reporta como desconocida");
            Console.WriteLine();
        }

        // ============================================================
        //  2. INICIO — contra el registro de verdad, en una subclave propia
        // ============================================================
        private static async Task ProbarInicio(bool admin)
        {
            Console.WriteLine("2. Optimizacion de inicio (registro real, subclave temporal)");

            string sufijo = Guid.NewGuid().ToString("N")[..8];
            string subclave = @"Software\NexoTest-" + sufijo;
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-inicio-" + sufijo);
            string carpetaUsuario = Path.Combine(raiz, "usuario");
            string carpetaComun = Path.Combine(raiz, "comun");
            Directory.CreateDirectory(carpetaUsuario);
            Directory.CreateDirectory(carpetaComun);

            try
            {
                // Run falso: dos programas; uno ya viene deshabilitado.
                using (RegistryKey run = Registry.CurrentUser.CreateSubKey(subclave + @"\Run"))
                {
                    run.SetValue("AppA", @"cmd /c exit", RegistryValueKind.String);
                    run.SetValue("AppB", @"cmd /c exit", RegistryValueKind.String);
                    run.SetValue("SecurityHealthSim", @"cmd /c exit", RegistryValueKind.String);
                }
                using (RegistryKey ap = Registry.CurrentUser.CreateSubKey(subclave + @"\Explorer\StartupApproved\Run"))
                {
                    ap.SetValue("AppB", StartupApprovedCodec.Escribir(false, DateTimeOffset.Now), RegistryValueKind.Binary);
                }
                File.WriteAllText(Path.Combine(carpetaUsuario, "uno.lnk"), "x");
                File.WriteAllText(Path.Combine(carpetaUsuario, "desktop.ini"), "x");

                var registro = new RegistroInicioWindows(subclave, carpetaUsuario, carpetaComun);
                var eventos = new RegistroDeEventos();
                var optimizador = new OptimizadorDeInicio(registro, eventos, esAdministrador: admin);

                IReadOnlyList<EntradaDeInicio> entradas = optimizador.Listar();
                EntradaDeInicio Buscar(string n) => entradas.Single(e => e.Nombre == n);

                Check(entradas.Count(e => e.Origen == OrigenDeInicio.RunUsuario) == 3,
                      "lee las 3 entradas Run de usuario");
                Check(Buscar("AppA").Estado == EstadoDeInicio.Habilitada,
                      "una entrada sin indicador StartupApproved cuenta como habilitada");
                Check(Buscar("AppB").Estado == EstadoDeInicio.Deshabilitada,
                      "lee el estado deshabilitado desde StartupApproved");
                Check(Buscar("uno.lnk").Origen == OrigenDeInicio.CarpetaUsuario,
                      "lee la carpeta de inicio del usuario");
                Check(entradas.All(e => e.Nombre != "desktop.ini"), "ignora desktop.ini");

                // --- Deshabilitar: indicador si, borrado no ---
                ResultadoCambioInicio r = await optimizador.CambiarEstadoAsync(Buscar("AppA"), habilitar: false).ConfigureAwait(false);
                Check(r.Aplicado, "deshabilita AppA", r.Motivo);

                using (RegistryKey run = Registry.CurrentUser.OpenSubKey(subclave + @"\Run")!)
                    Check(run.GetValue("AppA") is string,
                          "NO borra la entrada Run original: solo cambia el indicador");

                byte[]? bytes = Registry.CurrentUser.OpenSubKey(subclave + @"\Explorer\StartupApproved\Run")?.GetValue("AppA") as byte[];
                Check(bytes is { Length: StartupApprovedCodec.Largo } && bytes[0] == 0x03,
                      "escribe 12 bytes con 0x03 en StartupApproved\\Run");
                Check(StartupApprovedCodec.FechaDeshabilitado(bytes) is { } f
                      && Math.Abs((DateTimeOffset.Now - f).TotalMinutes) < 2,
                      "registra la fecha de deshabilitado como FILETIME");

                // --- Volver a habilitar ---
                IReadOnlyList<EntradaDeInicio> recargadas = optimizador.Listar();
                r = await optimizador.CambiarEstadoAsync(recargadas.Single(e => e.Nombre == "AppA"), habilitar: true).ConfigureAwait(false);
                bytes = Registry.CurrentUser.OpenSubKey(subclave + @"\Explorer\StartupApproved\Run")?.GetValue("AppA") as byte[];
                Check(r.Aplicado && bytes is not null && bytes[0] == 0x02, "vuelve a habilitar AppA (0x02)", r.Motivo);

                // --- Carpeta de inicio ---
                r = await optimizador.CambiarEstadoAsync(Buscar("uno.lnk"), habilitar: false).ConfigureAwait(false);
                bytes = Registry.CurrentUser.OpenSubKey(subclave + @"\Explorer\StartupApproved\StartupFolder")?.GetValue("uno.lnk") as byte[];
                Check(r.Aplicado && bytes is not null && bytes[0] == 0x03 && File.Exists(Path.Combine(carpetaUsuario, "uno.lnk")),
                      "deshabilita un acceso de la carpeta de inicio sin borrar el archivo", r.Motivo);

                // --- Reglas ---
                r = await optimizador.CambiarEstadoAsync(Buscar("SecurityHealthSim"), habilitar: false).ConfigureAwait(false);
                Check(!r.Aplicado && r.Motivo!.Contains("protegida", StringComparison.Ordinal),
                      "se niega a deshabilitar una entrada de seguridad (SecurityHealth*)");

                r = await optimizador.CambiarEstadoAsync(Buscar("AppB"), habilitar: false).ConfigureAwait(false);
                Check(!r.Aplicado && r.Motivo!.Contains("ya estaba", StringComparison.Ordinal),
                      "no reescribe una entrada que ya estaba deshabilitada");

                int eventosAntes = eventos.Eventos.Count;
                Check(eventos.Eventos.Count(e => e.Tipo == TipoEvento.InicioModificado) == eventosAntes && eventosAntes == 3,
                      "emite un evento por cada cambio aplicado (y ninguno por los rechazos)",
                      "eventos: " + eventosAntes);

                // --- Permisos de HKLM, contra el registro de verdad ---
                var deMaquina = new EntradaDeInicio("AppMaquina", "x", OrigenDeInicio.RunMaquina, EstadoDeInicio.Habilitada);
                var sinAdmin = new OptimizadorDeInicio(registro, new RegistroDeEventos(), esAdministrador: false);
                r = await sinAdmin.CambiarEstadoAsync(deMaquina, habilitar: false).ConfigureAwait(false);
                Check(!r.Aplicado && r.Motivo!.Contains("administrador", StringComparison.Ordinal),
                      "sin ser administrador, rechaza una entrada de HKLM antes de tocar nada");

                // Forzando el optimizador a intentarlo: HKLM debe negarse solo si no somos admin.
                var forzado = new OptimizadorDeInicio(registro, new RegistroDeEventos(), esAdministrador: true);
                r = await forzado.CambiarEstadoAsync(deMaquina, habilitar: false).ConfigureAwait(false);
                if (admin)
                    Check(r.Aplicado, "como administrador, escribe en HKLM", r.Motivo);
                else
                    Check(!r.Aplicado && r.Motivo!.Contains("denego", StringComparison.Ordinal),
                          "sin permisos reales, Windows deniega HKLM y se traduce a un rechazo (no a un fallo)",
                          "resultado: " + (r.Aplicado ? "aplicado" : r.Motivo));
            }
            finally
            {
                TryBorrarClave(Registry.CurrentUser, subclave);
                TryBorrarClave(Registry.LocalMachine, subclave);
                try { Directory.Delete(raiz, recursive: true); } catch (IOException) { }
            }

            Check(Registry.CurrentUser.OpenSubKey(subclave) is null,
                  "limpia la subclave temporal de HKCU");
            Console.WriteLine();
        }

        private static void TryBorrarClave(RegistryKey hive, string ruta)
        {
            try { hive.DeleteSubKeyTree(ruta, throwOnMissingSubKey: false); }
            catch (Exception ex) when (ex is UnauthorizedAccessException || ex is System.Security.SecurityException) { }
        }

        // ============================================================
        //  2b. IMPACTO DE ARRANQUE — solo lectura, registro real
        // ============================================================
        private static void ProbarArranque(bool admin)
        {
            Console.WriteLine();
            Console.WriteLine("2b. Impacto de arranque (Diagnostics-Performance, solo lectura)");

            ResultadoDeArranque r = new AnalizadorDeArranque(new FuenteDeArranqueWindows()).Leer(DateTimeOffset.UtcNow.AddDays(-30));
            // No esta comprobado si este registro exige administrador: se informa en vez de exigirlo.
            Check(r.Estado != EstadoDeLecturaDeArranque.NoDisponible, "el registro de Diagnostics-Performance existe y se abre",
                  "estado: " + r.Estado + " " + r.Motivo);
            if (r.Estado == EstadoDeLecturaDeArranque.SinPermisos)
            {
                Check(!admin && r.Arranques.Count == 0 && !r.PuedeAfirmarQueNadaLoRetraso,
                      "sin permisos (y sin ser administrador) no se afirma nada", "admin: " + admin);
                return;
            }
            Console.WriteLine($"      INFO: administrador: {(admin ? "si" : "no")}; {r.Arranques.Count} arranques, mediana " +
                              $"{(r.MedianaMs is { } m ? m + " ms" : "-")}; {r.Degradaciones.Count} cosas que lo retrasaron; {r.Descartados} sin interpretar.");
            // El analizador debe entender lo que Windows escribe de verdad.
            Check(r.Descartados == 0, "los eventos 100-103 reales se interpretan todos (ninguno descartado)", "descartados: " + r.Descartados);

            // Tareas programadas reales: el XML que escribe el Programador de tareas debe entenderse entero.
            InventarioDeTareas inv = LectorDeTareas.Leer(LectorDeTareas.CarpetaDelSistema());
            Check(inv.CarpetaDisponible && inv.ArchivosLeidos > 0, "la carpeta de tareas del sistema se recorre", inv.Motivo);
            Check(inv.Descartadas.Count == 0, "las tareas reales se interpretan todas (ninguna descartada)",
                  string.Join(" | ", inv.Descartadas.Take(3)));
            Console.WriteLine($"      INFO: {inv.Tareas.Count} tareas de inicio en {inv.ArchivosLeidos} archivos; {inv.Ilegibles.Count} ilegibles" +
                              (admin ? "" : " (sin administrador es lo esperado)") + ".");
            if (admin) Check(inv.Ilegibles.Count == 0, "como administrador no queda nada ilegible", string.Join(" | ", inv.Ilegibles.Take(3)));
        }

        // ============================================================
        //  4. SALUD DE DISCO — solo lectura, datos reales
        // ============================================================
        private static async Task ProbarSalud()
        {
            Console.WriteLine();
            Console.WriteLine("4. Salud de disco por WMI (solo lectura, discos reales)");

            // Historial en un archivo temporal: se prueba la persistencia sin tocar el de verdad.
            string rutaHistorial = Path.Combine(Path.GetTempPath(), "nexo-historial-" + Guid.NewGuid().ToString("N")[..8] + ".json");
            var historial = new Nexo.Modules.Cleanup.Disco.HistorialDeSalud(rutaHistorial);

            var eventos = new RegistroDeEventos();
            var monitor = new Nexo.Modules.Cleanup.Disco.MonitorDeSalud(new FuenteSmartWmi(), eventos, historial);
            var resultado = await monitor.EvaluarAsync().ConfigureAwait(false);

            foreach (var (l, e) in resultado)
            {
                Console.WriteLine($"      {l.Modelo}  [{l.SerieRedactada}]");
                Console.WriteLine($"          prediccion de fallo : {(l.PrediccionDeFallo is null ? "no disponible" : l.PrediccionDeFallo.ToString())}");
                Console.WriteLine($"          atributos SMART     : {l.Atributos.Count}");
                Console.WriteLine($"          temperatura/desgaste/horas : {l.TemperaturaC?.ToString() ?? "-"} C / {l.DesgastePorcentaje?.ToString() ?? "-"} % / {l.HorasEncendido?.ToString() ?? "-"} h");
                Console.WriteLine($"          evaluacion          : {e.Severidad}" + (e.Alertas.Count > 0 ? " — " + string.Join("; ", e.Alertas) : ""));
                foreach (string lim in l.Limitaciones) Console.WriteLine("          limitacion: " + lim);
            }

            Check(resultado.Count > 0, "encuentra al menos un disco");
            Check(resultado.All(r => r.Lectura.PrediccionDeFallo is not null || r.Lectura.Limitaciones.Count > 0),
                  "todo disco sin bandera de prediccion explica por que (nada se omite en silencio)");
            Check(resultado.All(r => !r.Lectura.SerieRedactada.Any(char.IsLower) && r.Lectura.SerieRedactada.Length <= 8),
                  "el numero de serie sale redactado (4 ultimos caracteres)");
            Check(eventos.Eventos.Count == resultado.Count, "publica un evento por disco");

            int conAtributos = resultado.Count(r => r.Lectura.Atributos.Count > 0);
            int guardados = historial.Cargar().Count;
            Console.WriteLine($"      historial: {guardados} disco(s) guardado(s) de {resultado.Count} ({conAtributos} con atributos ATA)");
            Check(monitor.AdvertenciaDeHistorial is null && guardados == conAtributos,
                  "el historial guarda exactamente los discos con atributos, sin advertencias");
            try { File.Delete(rutaHistorial); } catch (IOException) { }
            Console.WriteLine();
        }

        // ============================================================
        //  3. PAPELERA Y ARCHIVOS BLOQUEADOS
        // ============================================================
        private static void ProbarPapelera()
        {
            Console.WriteLine("3. Papelera de reciclaje y archivos bloqueados");

            string sufijo = Guid.NewGuid().ToString("N")[..8];
            string carpeta = Path.Combine(Path.GetTempPath(), "nexo papelera " + sufijo);   // con espacio, a proposito
            Directory.CreateDirectory(carpeta);

            try
            {
                string a = Path.Combine(carpeta, "nexo-demo-" + sufijo + "-a.tmp");
                string b = Path.Combine(carpeta, "nexo-demo-" + sufijo + "-ñandú.tmp");   // caracteres no ASCII
                string bloqueado = Path.Combine(carpeta, "nexo-demo-" + sufijo + "-bloqueado.tmp");
                File.WriteAllText(a, "a");
                File.WriteAllText(b, "b");
                File.WriteAllText(bloqueado, "no me borres");

                var borrador = new BorradorPapelera();
                Check(borrador.EsReversible, "el borrador de Papelera se declara reversible");

                // --- Un archivo bloqueado por otro proceso ---
                using (var cerrojo = new FileStream(bloqueado, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    ResultadoBorrado r = borrador.Borrar(new[] { (a, 1L), (b, 1L), (bloqueado, 12L) });

                    Check(!File.Exists(a) && !File.Exists(b),
                          "envia a la Papelera un archivo normal y uno con caracteres no ASCII");
                    Check(File.Exists(bloqueado),
                          "NO elimina un archivo abierto por otro proceso");
                    Check(r.Eliminados == 2 && r.Omitidos.Count == 1,
                          "informa 2 eliminados y 1 omitido",
                          $"eliminados {r.Eliminados}, omitidos {r.Omitidos.Count}: " + string.Join(" | ", r.Omitidos));
                    foreach (string o in r.Omitidos) Console.WriteLine("      omitido: " + o);
                }

                // Una vez liberado el cerrojo, el mismo archivo si se puede enviar.
                ResultadoBorrado r2 = borrador.Borrar(new[] { (bloqueado, 12L) });
                Check(r2.Eliminados == 1 && !File.Exists(bloqueado),
                      "liberado el cerrojo, el archivo ya se envia a la Papelera");

                Console.WriteLine($"      (quedan 3 archivos 'nexo-demo-{sufijo}-*' en la Papelera; son sinteticos)");
            }
            finally
            {
                try { Directory.Delete(carpeta, recursive: true); } catch (IOException) { }
            }
            Console.WriteLine();
        }
    }
}
