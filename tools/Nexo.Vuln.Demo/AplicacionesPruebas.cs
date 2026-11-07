using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        /// <summary>Salida REAL de «winget upgrade» (v1.29.380, Windows en espanol) del equipo principal, copiada tal cual.</summary>
        private const string WingetReal = """
Nombre                                                       Id                                        Versión         Disponible      Origen
---------------------------------------------------------------------------------------------------------------------------------------------
Epic Games Launcher                                          EpicGames.EpicGamesLauncher               1.3.161.0       1.3.210.0       winget
Epic Online Services                                         EpicGames.EpicOnlineServices              4.1.0           4.3.1           winget
Git                                                          Git.Git                                   2.54.0          2.56.0.4        winget
GitHub CLI                                                   GitHub.cli                                2.101.0         2.103.3         winget
Java 8 Update 401 (64-bit)                                   Oracle.JavaRuntimeEnvironment             8.0.4010.10     8.0.5110.33     winget
Microsoft .NET SDK 8.0.425 (x64)                             Microsoft.DotNet.SDK.8                    8.0.425         8.0.427         winget
Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.30501 Microsoft.VCRedist.2013.x64               12.0.30501.0    12.0.40664.0    winget
Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.30501 Microsoft.VCRedist.2013.x86               12.0.30501.0    12.0.40664.0    winget
Microsoft Windows Desktop Runtime 10.0.1 (x64)               Microsoft.DotNet.DesktopRuntime.10        10.0.1          10.0.14         winget
Node.js                                                      OpenJS.NodeJS.LTS                         24.15.0         26.13.0         winget
NVIDIA Software del sistema PhysX 9.23.1019                  Nvidia.PhysX                              9.23.1019       9.26.0703       winget
Obsidian                                                     Obsidian.Obsidian                         1.13.7          1.15.0          winget
Python Install Manager                                       Python.PythonInstallManager               26.3.240.0      26.4.240.0      winget
Rockstar Games Launcher                                      RockstarGames.Launcher                    1.0.108.2970    1.0.110.3150    winget
Rustup: the Rust toolchain installer                         Rustlang.Rustup                           1.29.0          1.29.3          winget
Terminal Windows                                             Microsoft.WindowsTerminal                 1.24.12741.0    1.25.2733.0     winget
Ubisoft Connect                                              Ubisoft.Connect                           < 175.1.0.13416 175.1.0.13416   winget
Visual Studio Build Tools 2022                               Microsoft.VisualStudio.2022.BuildTools    17.14.37        17.14.44        winget
Visual Studio Community 2026 Insiders                        Microsoft.VisualStudio.Community.Insiders 18.11.12224.323 18.12.12328.396 winget
WinRAR 7.01 (64-bit)                                         RARLab.WinRAR                             7.01.0          7.23.0          winget
WizTree v4.28                                                AntibodySoftware.WizTree                  4.28            4.33            winget
21 actualizaciones disponibles.
""";

        private static SalidaDeWinget Winget(string texto) => new(EstadoDeWinget.Correcta, texto, 0);

        public static void ProbarWingetReal()
        {
            Console.WriteLine("12. Salida real de winget (español)");
            ResultadoDeParseo p = ParserDeActualizacionesWinget.Parsear(WingetReal);
            Check(p.Reconocido && p.Aplicaciones.Count == 21 && p.Avisos.Count == 0, "la salida real se lee entera: 21 aplicaciones y ningun aviso", p.Aplicaciones.Count + " / " + string.Join(";", p.Avisos));
            AplicacionDesactualizada e = p.Aplicaciones[0];
            Check(e == new AplicacionDesactualizada("Epic Games Launcher", "EpicGames.EpicGamesLauncher", "1.3.161.0", "1.3.210.0", "winget"), "la primera fila se corta bien por columnas (nombre con espacios incluido)", e.ToString());
            Check(p.Aplicaciones.Single(a => a.Id == "Ubisoft.Connect").VersionInstalada == "< 175.1.0.13416", "«< 175.1.0.13416» (version con prefijo) se conserva tal cual");
            AplicacionDesactualizada vc = p.Aplicaciones.First(a => a.Id == "Microsoft.VCRedist.2013.x64");
            Check(vc.Nombre == "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.30501", "un nombre que llena toda su columna (sin espacio de separacion extra) no se come el Id", vc.Nombre);
            Check(p.Aplicaciones.Select(a => a.Id).Distinct().Count() == 21 && p.Aplicaciones.All(a => a.Origen == "winget"), "21 Id distintos, todos de winget");
            Check(p.Aplicaciones.Any(a => a.Nombre.Contains("sistema")), "los nombres en espanol con acentos y minusculas se leen («NVIDIA Software del sistema PhysX»)");

            ResultadoDeAplicaciones r = AnalizadorDeAplicaciones.Analizar(Winget(WingetReal));
            Check(r.Analisis.Completo && r.Aplicaciones.Count == 21, "el analisis es completo");
            Check(r.Analisis.Hallazgos.Count(h => h.Id == "APP-RIESGO-DESACTUALIZADA") == 2
                  && r.Analisis.Hallazgos.Where(h => h.Id == "APP-RIESGO-DESACTUALIZADA").Select(h => h.Sujeto).OrderBy(x => x).SequenceEqual(new[] { "Java 8 Update 401 (64-bit)", "WinRAR 7.01 (64-bit)" }),
                  "marca como riesgo Media solo Java y WinRAR (las otras 19 no estan en la lista corta)");
            HallazgoDeSistema resumen = r.Analisis.Hallazgos.Single(h => h.Id == "APPS-DESACTUALIZADAS");
            Check(resumen.Severidad == Severidad.Baja && resumen.Titulo.StartsWith("19 "), "las otras 19 van en un solo hallazgo Bajo", resumen.Titulo);
            Check(resumen.Detalle.Contains("no significa que la tuya sea vulnerable"), "y el texto aclara que una version nueva no significa «vulnerable»");
            Check(r.Analisis.Hallazgos.Single(h => h.Sujeto == "Java 8 Update 401 (64-bit)").Recomendacion.Contains("winget upgrade --id Oracle.JavaRuntimeEnvironment"), "la recomendacion lleva el comando exacto con el Id");
            Check(r.Analisis.Maxima == Severidad.Media, "la maxima es Media");
        }

        public static void ProbarVariantesDeWinget()
        {
            Console.WriteLine("13. Variantes: ruido, otros idiomas, tablas rotas");
            Check(ParserDeActualizacionesWinget.Parsear(WingetReal.Replace("\n", "\r\n")).Aplicaciones.Count == 21, "con saltos de linea CRLF se lee igual");
            string ruido = "   -   \\   |   /   -\r\n  \r\n" + WingetReal;
            Check(ParserDeActualizacionesWinget.Parsear(ruido) is { Reconocido: true } r1 && r1.Aplicaciones.Count == 21, "el «spinner» de winget antes de la tabla se ignora");
            Check(ParserDeActualizacionesWinget.Parsear("\n\n" + WingetReal + "\n\n").Aplicaciones.Count == 21, "lineas en blanco alrededor no importan");

            // Solo español: el mismo contenido con el encabezado en ingles NO se interpreta.
            string ingles = WingetReal.Replace("Nombre ", "Name   ").Replace("Versión", "Version").Replace("Disponible", "Available ").Replace("Origen", "Source").Replace("actualizaciones disponibles", "upgrades available");
            ResultadoDeParseo en = ParserDeActualizacionesWinget.Parsear(ingles);
            Check(!en.Reconocido && en.Aplicaciones.Count == 0 && en.Avisos.Single().Contains("español"), "con el encabezado en ingles: NO reconocido, 0 aplicaciones y el aviso dice que es solo espanol");
            ResultadoDeAplicaciones enA = AnalizadorDeAplicaciones.Analizar(Winget(ingles));
            Check(!enA.Analisis.Completo && enA.Analisis.Hallazgos.Count == 0, "y el analisis queda «no evaluado», nunca «sin actualizaciones»");

            // Mensajes de «nada que actualizar».
            ResultadoDeParseo ninguna = ParserDeActualizacionesWinget.Parsear("No se encontraron actualizaciones disponibles.\r\n");
            Check(ninguna.Reconocido && ninguna.SinActualizaciones && ninguna.Avisos.Count == 0, "«No se encontraron actualizaciones...» = reconocido y sin actualizaciones");
            Check(ParserDeActualizacionesWinget.Parsear("No se encontró ningún origen que coincida.").Reconocido == false, "otro «No se encontro...» que NO habla de actualizaciones no se toma por «sin actualizaciones»");
            Check(!ParserDeActualizacionesWinget.Parsear("Error al abrir el origen. No se pudo conectar.").Reconocido, "un error de winget no se toma por «sin actualizaciones»");
            ResultadoDeAplicaciones sinNada = AnalizadorDeAplicaciones.Analizar(Winget("No se encontraron actualizaciones disponibles."));
            Check(sinNada.Analisis.Completo && sinNada.Analisis.Hallazgos.Count == 0, "«sin actualizaciones» reconocido: completo y sin hallazgos");

            foreach (string vacio in new[] { "", "   ", "\n\n" }) Check(!ParserDeActualizacionesWinget.Parsear(vacio).Reconocido, "salida vacia («" + vacio.Replace("\n", "\\n") + "») no se reconoce");
            Check(!ParserDeActualizacionesWinget.Parsear(null).Reconocido, "una salida null no se reconoce");
            Check(!ParserDeActualizacionesWinget.Parsear(WingetReal.Replace("---------------------------------------------------------------------------------------------------------------------------------------------\n", "")).Reconocido, "sin la linea de guiones bajo el encabezado no se reconoce");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Check(!ParserDeActualizacionesWinget.Parsear(new string('x', ParserDeActualizacionesWinget.MaximoDeCaracteres + 1)).Reconocido && sw.ElapsedMilliseconds < 1000, "una salida mas grande que el tope se rechaza sin procesarla");

            // Filas rotas: no se adivinan.
            string truncada = WingetReal.Replace("Microsoft.VisualStudio.2022.BuildTools    ", "Microsoft.VisualStudio.2022.Build…       ");
            ResultadoDeParseo tr = ParserDeActualizacionesWinget.Parsear(truncada);
            Check(tr.Aplicaciones.Count == 20 && tr.Avisos.Single().StartsWith("1 fila"), "una fila con el Id truncado («…») no se adivina: 20 leidas y 1 aviso", tr.Aplicaciones.Count + " / " + string.Join(";", tr.Avisos));
            Check(!AnalizadorDeAplicaciones.Analizar(Winget(truncada)).Analisis.Completo, "y por eso el analisis no es completo");
            string corta = WingetReal.Replace("Obsidian                                                     Obsidian.Obsidian                         1.13.7          1.15.0          winget", "Obsidian    Obsidian.Obsidian");
            ResultadoDeParseo co = ParserDeActualizacionesWinget.Parsear(corta);
            Check(co.Aplicaciones.Count == 20 && co.Avisos.Count == 1, "una fila mas corta que la columna Origen es ilegible (no revienta)", string.Join(";", co.Avisos));

            // El recuento final debe cuadrar.
            ResultadoDeParseo mal = ParserDeActualizacionesWinget.Parsear(WingetReal.Replace("21 actualizaciones disponibles.", "22 actualizaciones disponibles."));
            Check(mal.Avisos.Single().Contains("no cuadra"), "si el recuento dice 22 y hay 21 filas, avisa que no cuadra");
            ResultadoDeParseo sinRecuento = ParserDeActualizacionesWinget.Parsear(WingetReal.Replace("21 actualizaciones disponibles.", ""));
            Check(sinRecuento.Avisos.Single().Contains("recuento"), "si falta el recuento final (salida cortada), avisa: no se puede comprobar que este completa");
            ResultadoDeParseo extra = ParserDeActualizacionesWinget.Parsear(WingetReal + "\nLas siguientes actualizaciones no se pudieron comparar:\nNombre   Id   Versión\n");
            Check(extra.Avisos.Count == 1 && extra.Avisos[0].Contains("más información"), "texto adicional despues del recuento (otra tabla, avisos) no se ignora en silencio: se avisa");
            Check(!AnalizadorDeAplicaciones.Analizar(Winget(WingetReal + "\nalgo mas")).Analisis.Completo, "y hace la revision incompleta");

            int lanzo = 0;
            for (int i = 0; i < WingetReal.Length; i += 7) { try { ParserDeActualizacionesWinget.Parsear(WingetReal.Substring(0, i)); } catch (Exception) { lanzo++; } }
            Check(lanzo == 0, "cortar la salida real en cada 7 posiciones (" + WingetReal.Length / 7 + " cortes) nunca lanza una excepcion", lanzo + " lanzaron");

            // Estados de winget.
            foreach (EstadoDeWinget est in new[] { EstadoDeWinget.NoInstalado, EstadoDeWinget.TiempoAgotado, EstadoDeWinget.Error })
            {
                ResultadoDeAplicaciones x = AnalizadorDeAplicaciones.Analizar(new SalidaDeWinget(est, "", -1));
                Check(!x.Analisis.Completo && x.Analisis.Hallazgos.Count == 0 && x.Aplicaciones.Count == 0, "winget " + est + ": no evaluado y sin hallazgos inventados");
            }
            bool lanzoNull = false;
            try { AnalizadorDeAplicaciones.Analizar(null!); } catch (ArgumentNullException) { lanzoNull = true; }
            Check(lanzoNull, "una salida null se rechaza");
        }

        public static void ProbarReglasDeAplicaciones()
        {
            Console.WriteLine("14. Reglas y evento de aplicaciones");
            // Columnas: Nombre 16, Id 24, Version 8, Disponible 11, Origen. El Id mas largo de las pruebas (19) cabe holgado.
            string Una(string id, string nombre) => $"Nombre          Id                      Versión Disponible Origen\n----------------------------------------------------------\n{nombre,-16}{id,-24}1.0     2.0        winget\n1 actualizaciones disponibles.\n";

            Check(AnalizadorDeAplicaciones.Analizar(Winget(Una("google.chrome", "Chrome"))).Analisis.Hallazgos.Single().Id == "APP-RIESGO-DESACTUALIZADA", "el Id de la lista de riesgo se reconoce sin distinguir mayusculas (google.chrome)");
            Check(AnalizadorDeAplicaciones.Analizar(Winget(Una("Git.Git", "Git"))).Analisis.Hallazgos.Single().Id == "APPS-DESACTUALIZADAS", "un programa fuera de la lista (Git) solo da el hallazgo Bajo");
            Check(AnalizadorDeAplicaciones.Analizar(Winget(Una("Mozilla.Firefox.ESR", "Firefox"))).Analisis.Hallazgos.Single().Id == "APP-RIESGO-DESACTUALIZADA", "una variante con el mismo prefijo (Mozilla.Firefox.ESR) cuenta");
            Check(AnalizadorDeAplicaciones.Analizar(Winget(Una("NoMozilla.Firefox", "X"))).Analisis.Hallazgos.Single().Id == "APPS-DESACTUALIZADAS", "pero un Id que solo CONTIENE el nombre no (se compara el prefijo)");

            ResultadoDeAplicaciones real = AnalizadorDeAplicaciones.Analizar(Winget(WingetReal));
            NexoEvent ev = EventosDeVulnerabilidades.RevisionDeAplicaciones(real);
            Check(ev.Severidad == Severidad.Media && ev.Modulo == ModuloOrigen.Amenazas && ev.Tipo == TipoEvento.VulnerabilidadDetectada, "con Java y WinRAR atrasados: evento Media, modulo Amenazas");
            Check(ev.Titulo == "Revisión de aplicaciones desactualizadas: 3 hallazgo(s)", "el titulo cuenta los hallazgos", ev.Titulo);
            Check(ev.Cuerpo!.Contains("| Epic Games Launcher | EpicGames.EpicGamesLauncher | 1.3.161.0 | 1.3.210.0 |"), "el cuerpo lleva la tabla de aplicaciones");
            Check(ev.Cuerpo.Contains("no es una revisión de todo el software instalado") && ev.Cuerpo.Contains("no significa que la instalada sea vulnerable"), "y declara su alcance: no revisa todo el software ni dice «vulnerable»");

            // Incompleta: Media y «incompleta».
            NexoEvent inc = EventosDeVulnerabilidades.RevisionDeAplicaciones(AnalizadorDeAplicaciones.Analizar(new SalidaDeWinget(EstadoDeWinget.NoInstalado, "", -1)));
            Check(inc.Severidad == Severidad.Media && inc.Titulo.EndsWith("incompleta") && inc.Cuerpo!.Contains("NO significa que esté bien"), "winget no instalado: Media, «incompleta», no significa que este bien");
            NexoEvent limpio = EventosDeVulnerabilidades.RevisionDeAplicaciones(AnalizadorDeAplicaciones.Analizar(Winget("No se encontraron actualizaciones disponibles.")));
            Check(limpio.Severidad == Severidad.Info && limpio.Titulo.EndsWith("sin hallazgos"), "leida entera y sin nada que actualizar: Info, «sin hallazgos»");

            // Mucha lista: se recorta y no rompe la tabla.
            var filas = Enumerable.Range(0, 150).Select(i => new AplicacionDesactualizada("App|" + i, "Id." + i, "1.0", "2.0", "winget")).ToList();
            var grande = new ResultadoDeAplicaciones(new ResultadoDeAnalisis(Array.Empty<HallazgoDeSistema>(), Array.Empty<string>()), filas);
            NexoEvent eg = EventosDeVulnerabilidades.RevisionDeAplicaciones(grande);
            Check(eg.Cuerpo!.Contains("y 50 más") && eg.Cuerpo.Split('\n').Count(l => l.StartsWith("| App/")) == 100, "150 aplicaciones: la tabla muestra 100 y dice «y 50 mas»");
            Check(eg.Cuerpo.Split('\n').Where(l => l.StartsWith("| App/")).All(l => l.Count(c => c == '|') == 5), "un nombre con «|» no rompe la tabla (5 barras por fila)");
        }
    }
}
