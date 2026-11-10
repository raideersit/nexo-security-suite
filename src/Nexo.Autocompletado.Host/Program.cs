using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Autocompletado;

namespace Nexo.Autocompletado.Host
{
    /// <summary>
    /// nexo-autocompletar.exe
    ///   chrome-extension://ID/ [--parent-window=N]   lo lanza el navegador: reenvía mensajes a la ventana de Nexo (no imprime nada más)
    ///   --instalar                                    registra el host para Brave, Chrome y Edge (solo tu usuario, sin administrador)
    ///   --desinstalar                                 lo quita (solo las claves que apuntan al manifiesto de Nexo)
    ///   --estado                                      qué ve cada navegador
    /// Para pruebas: --raiz-de-pruebas Software\X (todo el registro va bajo esa clave) y --manifiesto RUTA.
    /// </summary>
    internal static class Program
    {
        private static async Task<int> Main(string[] args)
        {
            if (args.Length > 0 && args[0].StartsWith("chrome-extension://", StringComparison.Ordinal))
            {
                // Modo navegador: stdout es SOLO el protocolo. Los avisos van a stderr (el navegador los anota en su registro).
                if (!InstaladorDeHostNativo.EsOrigenDeExtension(args[0]))
                {
                    Console.Error.WriteLine("nexo-autocompletar: origen no válido");
                    return 3;
                }
                using Stream entrada = Console.OpenStandardInput();
                using Stream salida = Console.OpenStandardOutput();
                return await new RelevoNativo(CanalDeAutocompletado.NombreDePipeActual()).EjecutarAsync(entrada, salida).ConfigureAwait(false);
            }

            string? raiz = Opcion(args, "--raiz-de-pruebas");
            string manifiesto = Opcion(args, "--manifiesto") ?? RutaDelManifiesto();
            var registro = new RegistroDeWindows(raiz);

            if (args.Contains("--instalar"))
            {
                string? programa = Environment.ProcessPath;
                if (programa is null) { Console.WriteLine("No se sabe dónde está este programa: no se instala."); return 1; }
                IReadOnlyList<string> problemas = InstaladorDeHostNativo.Instalar(registro, manifiesto, programa, new[] { InstaladorDeHostNativo.IdDeLaExtension });
                Console.WriteLine("Manifiesto: " + manifiesto);
                Console.WriteLine("Programa:   " + programa);
                foreach (string p in problemas) Console.WriteLine("PROBLEMA: " + p);
                Mostrar(registro);
                return problemas.Count == 0 ? 0 : 1;
            }
            if (args.Contains("--desinstalar"))
            {
                foreach (string l in InstaladorDeHostNativo.Desinstalar(registro, manifiesto)) Console.WriteLine(l);
                return 0;
            }
            if (args.Contains("--estado"))
            {
                return Mostrar(registro) ? 0 : 1;
            }

            Console.WriteLine("nexo-autocompletar: el puente entre la extensión de Nexo en el navegador y la bóveda.");
            Console.WriteLine("  --instalar     lo registra para Brave, Chrome y Edge (solo tu usuario)");
            Console.WriteLine("  --desinstalar  lo quita");
            Console.WriteLine("  --estado       qué ve cada navegador");
            return args.Length == 0 ? 0 : 1;
        }

        private static bool Mostrar(IRegistroDeUsuario registro)
        {
            bool todo = true;
            foreach (EstadoDelHost e in InstaladorDeHostNativo.Revisar(registro))
            {
                Console.WriteLine(e.Navegador.Nombre + ": " + e.Detalle);
                todo &= e.Situacion == SituacionDelHost.Listo;
            }
            return todo;
        }

        internal static string RutaDelManifiesto()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nexo", "autocompletado",
                            InstaladorDeHostNativo.NombreDelHost + ".json");

        private static string? Opcion(string[] args, string nombre)
        {
            int i = Array.IndexOf(args, nombre);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
    }
}
