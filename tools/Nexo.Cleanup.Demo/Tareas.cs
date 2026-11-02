using System;
using System.IO;
using System.Linq;
using System.Text;
using Nexo.Modules.Cleanup.Inicio;

namespace Nexo.Cleanup.Demo
{
    public static partial class Program
    {
        /// <summary>Una tarea con la forma que escribe el Programador de tareas. Los parametros permiten romperla.</summary>
        private static string Tarea(string disparadores = "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>",
                                    string acciones = "<Exec><Command>C:\\Program Files\\App\\app.exe</Command><Arguments>--bandeja</Arguments></Exec>",
                                    string ajustes = "<Enabled>true</Enabled>",
                                    string principal = "<UserId>S-1-5-21-1-2-3-1001</UserId><RunLevel>LeastPrivilege</RunLevel>",
                                    string raiz = "Task", string ns = "http://schemas.microsoft.com/windows/2004/02/mit/task")
            => "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
               $"<{raiz} version=\"1.2\" xmlns=\"{ns}\"><RegistrationInfo><Author>Empresa</Author><URI>\\falsa\\ruta</URI></RegistrationInfo>" +
               $"<Triggers>{disparadores}</Triggers><Principals><Principal id=\"Author\">{principal}</Principal></Principals>" +
               $"<Settings>{ajustes}</Settings><Actions Context=\"Author\">{acciones}</Actions></{raiz}>";

        private static void ProbarTareas()
        {
            Console.WriteLine();
            Console.WriteLine("5c. Tareas programadas de inicio (XML del Programador de tareas)");

            // --- Analizador ---
            bool ok = ParserDeTareaProgramada.TryParse(Tarea(), @"\App\Actualizar", out TareaDeInicio? t, out string? m);
            Check(ok && t is not null && t.Ruta == @"\App\Actualizar" && t.Disparadores.SequenceEqual(new[] { DisparadorDeInicio.InicioDeSesion })
                  && t.Comandos.Single() == "\"C:\\Program Files\\App\\app.exe\" --bandeja" && t.Habilitada && !t.Oculta
                  && t.Usuario == "S-1-5-21-1-2-3-1001" && !t.MaximosPrivilegios && t.Autor == "Empresa" && !t.EnCarpetaDeMicrosoft,
                  "una tarea al iniciar sesion se interpreta entera; la ruta sale del archivo, no del <URI> del XML", m);

            ok = ParserDeTareaProgramada.TryParse(Tarea(
                    disparadores: "<BootTrigger><Delay>PT2M</Delay></BootTrigger><LogonTrigger><Delay>PT30S</Delay></LogonTrigger><TimeTrigger/>",
                    acciones: "<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>",
                    ajustes: "<Hidden>true</Hidden>", principal: "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>"),
                @"\Microsoft\Windows\Algo", out t, out m);
            Check(ok && t!.Disparadores.Count == 2 && t.Retraso == TimeSpan.FromSeconds(30) && t.Comandos.Count == 0 && t.TieneAccionCom
                  && t.Oculta && t.MaximosPrivilegios && t.Usuario == "S-1-5-18" && t.EnCarpetaDeMicrosoft,
                  "arranque + sesion con retrasos (se queda el menor), accion COM, oculta, SYSTEM y maximos privilegios", m);

            ok = ParserDeTareaProgramada.TryParse(Tarea(disparadores: "<LogonTrigger/>", ajustes: ""), @"\X", out t, out _);
            Check(ok && t is { Habilitada: true }, "sin <Enabled> la tarea y el disparador estan habilitados (lo que dice el esquema)");

            ok = ParserDeTareaProgramada.TryParse(Tarea(ajustes: "<Enabled>false</Enabled>"), @"\X", out t, out _);
            Check(ok && t is { Habilitada: false }, "una tarea deshabilitada se lista como deshabilitada (no se oculta)");

            ok = ParserDeTareaProgramada.TryParse(Tarea(disparadores: "<LogonTrigger><Enabled>false</Enabled></LogonTrigger><TimeTrigger/>"), @"\X", out t, out m);
            Check(ok && t is null && m is null, "con el disparador de inicio apagado o solo por horario no es de inicio (se entendio, no se descarta)");

            // --- Hostil ---
            void Rechaza(string xml, string descripcion)
            {
                bool r = true; string? mo = null;
                try { r = ParserDeTareaProgramada.TryParse(xml, @"\X", out _, out mo); }
                catch (Exception e) { mo = "LANZO " + e.GetType().Name; }
                Check(!r && mo is not null && !mo.StartsWith("LANZO", StringComparison.Ordinal), descripcion, mo);
            }

            Rechaza(Tarea(acciones: "<Exec><Command>C:\\a.exe\n# Titulo falso</Command></Exec>"), "un comando con salto de linea rechaza la tarea entera");
            Rechaza(Tarea(acciones: "<Exec><Command>C:\\a.exe</Command><Arguments>x\u0085y</Arguments></Exec>"), "argumentos con caracteres de control (U+0085, valido en XML) tambien");
            Rechaza(Tarea(acciones: "<Exec><Command> </Command></Exec>"), "una accion Exec sin comando se rechaza");
            Rechaza(Tarea(ajustes: "<Enabled>quizas</Enabled>"), "un Enabled desconocido en la tarea no se toma por 'habilitada'");
            Rechaza(Tarea(disparadores: "<LogonTrigger><Enabled>2</Enabled></LogonTrigger>"), "ni en el disparador");
            Rechaza(Tarea(raiz: "Tarea"), "otro elemento raiz se rechaza");
            Rechaza(Tarea(ns: "urn:otro"), "el espacio de nombres equivocado se rechaza");
            Rechaza("<!DOCTYPE Task [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" + Tarea(acciones: "<Exec><Command>&x;</Command></Exec>").Replace("<?xml version=\"1.0\" encoding=\"UTF-16\"?>", ""),
                    "un DOCTYPE con entidad externa se rechaza");
            Rechaza(Tarea(acciones: string.Concat(Enumerable.Repeat("<Exec><Command>a.exe</Command></Exec>", 40))), "mas de 32 acciones se rechaza");
            Rechaza(Tarea(acciones: "<Exec><Command>" + new string('x', 300_000) + "</Command></Exec>"), "un documento enorme se rechaza sin procesarlo");
            Rechaza("<Task", "XML cortado");

            int lanzo = 0;
            var rnd = new Random(2004);
            string baseXml = Tarea();
            for (int i = 0; i < 2000; i++)
            {
                char[] cs = baseXml.ToCharArray();
                for (int k = 0, n = rnd.Next(1, 6); k < n; k++) cs[rnd.Next(cs.Length)] = (char)rnd.Next(1, 300);
                string s = new string(cs);
                if (rnd.Next(4) == 0) s = s[..rnd.Next(s.Length)];
                try { ParserDeTareaProgramada.TryParse(s, @"\X", out _, out _); } catch { lanzo++; }
            }
            Check(lanzo == 0, "2000 XML mutados al azar: ninguno lanza", "lanzaron: " + lanzo);

            // --- Lector de la carpeta, contra archivos reales en UTF-16 ---
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-tareas-demo");
            string fuera = Path.Combine(Path.GetTempPath(), "nexo-tareas-fuera");
            Limpiar(raiz); Limpiar(fuera);
            try
            {
                void Escribir(string rel, string xml)
                {
                    string ruta = Path.Combine(raiz, rel.Replace('\\', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(ruta)!);
                    File.WriteAllText(ruta, xml, new UnicodeEncoding(false, true));   // UTF-16 LE con BOM, como Windows
                }

                Escribir("Actualizador", Tarea());
                Escribir(@"Microsoft\Windows\Mantenimiento", Tarea(disparadores: "<BootTrigger/>",
                    acciones: "<ComHandler><ClassId>{1}</ClassId></ComHandler>"));
                Escribir(@"Microsoft\Windows\Solo de noche", Tarea(disparadores: "<CalendarTrigger/>"));
                Escribir(@"Raras\Rota", "<Task><roto");
                Escribir(@"Raras\Inyectada", Tarea(acciones: "<Exec><Command>a.exe\n# x</Command></Exec>"));

                // Un enlace de carpeta que apunta fuera no se sigue.
                Directory.CreateDirectory(fuera);
                File.WriteAllText(Path.Combine(fuera, "Escondida"), Tarea(), new UnicodeEncoding(false, true));
                bool hayEnlace = true;
                try { Directory.CreateSymbolicLink(Path.Combine(raiz, "Enlace"), fuera); } catch { hayEnlace = false; }

                // Sin permisos de lectura (no se puede simular siendo root ni en Windows con chmod).
                bool puedeQuitarPermisos = !OperatingSystem.IsWindows() && !Environment.IsPrivilegedProcess;
                if (puedeQuitarPermisos)
                {
                    Escribir(@"Privada\Secreta", Tarea());
                    Escribir("Ilegible", Tarea());
                    File.SetUnixFileMode(Path.Combine(raiz, "Ilegible"), UnixFileMode.None);
                    File.SetUnixFileMode(Path.Combine(raiz, "Privada"), UnixFileMode.None);
                }

                InventarioDeTareas inv = LectorDeTareas.Leer(raiz);
                Check(inv.CarpetaDisponible && inv.Tareas.Select(x => x.Ruta).SequenceEqual(new[] { @"\Actualizador", @"\Microsoft\Windows\Mantenimiento" }),
                      "lee UTF-16 de subcarpetas y lista solo las de inicio, con su ruta \\Carpeta\\Nombre",
                      string.Join(" | ", inv.Tareas.Select(x => x.Ruta)));
                Check(inv.Descartadas.Count == 2 && inv.Descartadas.Any(d => d.StartsWith(@"\Raras\Rota:", StringComparison.Ordinal))
                      && inv.Descartadas.Any(d => d.StartsWith(@"\Raras\Inyectada:", StringComparison.Ordinal)),
                      "las tareas rotas o con inyeccion se anotan como descartadas, con su ruta y el motivo",
                      string.Join(" | ", inv.Descartadas));
                if (hayEnlace)
                    Check(!inv.Tareas.Any(x => x.Ruta.Contains("Escondida")) && !inv.Descartadas.Any(d => d.Contains("Enlace")),
                          "un enlace de carpeta que apunta fuera no se sigue");
                else
                    Console.WriteLine("      NOTA: no se pudo crear el enlace simbolico; no se probo.");
                if (puedeQuitarPermisos)
                    Check(inv.Ilegibles.Contains(@"\Ilegible") && inv.Ilegibles.Contains(@"\Privada\") && !inv.Completo,
                          "un archivo y una carpeta sin permisos se anotan como ilegibles, el recorrido sigue, y la lista NO es completa",
                          string.Join(" | ", inv.Ilegibles));
                else
                    Console.WriteLine("      NOTA: como administrador/root no se puede simular falta de permisos; no se probo.");
                Check(!inv.Completo, "con descartadas la lista tampoco es completa");

                inv = LectorDeTareas.Leer(raiz, maximoArchivos: 2);
                Check(inv.Truncado && inv.ArchivosLeidos == 2 && !inv.Completo, "al llegar al maximo de archivos se marca truncado y no completo");

                inv = LectorDeTareas.Leer(Path.Combine(raiz, "no-existe"));
                Check(!inv.CarpetaDisponible && inv.Tareas.Count == 0 && !inv.Completo, "sin carpeta de tareas: no disponible, NO 'cero tareas'");

                string limpia = Path.Combine(raiz, "Microsoft");
                if (puedeQuitarPermisos) File.SetUnixFileMode(Path.Combine(raiz, "Privada"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                Directory.Delete(Path.Combine(raiz, "Raras"), true);
                inv = LectorDeTareas.Leer(limpia);
                Check(inv.Completo && inv.Tareas.Count == 1 && inv.ArchivosLeidos == 2, "recorrido sin problemas: completo");
            }
            finally
            {
                Limpiar(raiz); Limpiar(fuera);
            }

            // --- Cruce con el impacto de arranque ---
            var fuente = new FuenteDeArranqueFalsa();
            fuente.Xml.AddRange(new[] { Arranque100(), Lenta(nombre: "app.exe") });
            ResultadoDeArranque res = new AnalizadorDeArranque(fuente).Leer(A0.AddDays(-7));
            ParserDeTareaProgramada.TryParse(Tarea(), @"\App", out t, out _);
            Check(res.ImpactoDeComando(t!.Comandos[0]) is { Veces: 1 }, "el comando de una tarea se cruza con el impacto de arranque como una entrada de Run");
        }

        private static void Limpiar(string ruta)
        {
            if (!Directory.Exists(ruta)) return;
            // Devuelve los permisos antes de borrar (una prueba que falla a medias puede dejarlos quitados).
            if (!OperatingSystem.IsWindows())
                foreach (string e in Directory.EnumerateFileSystemEntries(ruta, "*", new EnumerationOptions
                             { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }).Prepend(ruta))
                    try { File.SetUnixFileMode(e, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); } catch { }
            Directory.Delete(ruta, true);
        }
    }
}
