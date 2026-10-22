using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        /// <summary>
        /// El diario USN de verdad. Sin administrador solo comprueba que se NIEGA con claridad y no finge
        /// vigilar; como administrador ademas crea un archivo y espera verlo llegar por el diario.
        /// </summary>
        private static async Task ProbarUsnReal(string raiz)
        {
            Console.WriteLine("8. Diario USN real (" + (EsAdmin ? "como administrador" : "SIN administrador: solo se comprueba la negativa") + ")");

            string unidad = Path.GetPathRoot(raiz)![0].ToString();
            string carpeta = Path.Combine(raiz, "usn");
            Directory.CreateDirectory(carpeta);

            var recibidos = new ConcurrentQueue<CambioDeArchivo>();
            var perdidos = new ConcurrentQueue<string>();
            using var fuente = new FuenteUsn(new[] { unidad[0] }, new[] { carpeta });
            fuente.Iniciar(recibidos.Enqueue, perdidos.Enqueue);

            if (!EsAdmin)
            {
                Check(fuente.NoVigiladas.Count == 1 && fuente.NoVigiladas[0].Contains("administrador"),
                      "sin administrador la fuente lo DICE (no vigilada: hace falta administrador) en vez de fingir",
                      string.Join("; ", fuente.NoVigiladas));
                await Task.Delay(300).ConfigureAwait(false);
                string f = Path.Combine(carpeta, "x.exe");
                File.WriteAllText(f, "x");
                await Task.Delay(1500).ConfigureAwait(false);
                Check(recibidos.IsEmpty, "y, sin vigilar, no emite cambios inventados");
                Console.WriteLine("  [NOTA]  Camino elevado (lectura real del diario y resolucion de rutas) SIN PROBAR en esta ejecucion.");
            }
            else
            {
                Check(fuente.NoVigiladas.Count == 0, "como administrador el volumen se abre y el diario esta activo", string.Join("; ", fuente.NoVigiladas));
                await Task.Delay(500).ConfigureAwait(false);

                string f = Path.Combine(carpeta, "desde-el-diario.exe");
                File.WriteAllBytes(f, Encoding.ASCII.GetBytes("contenido"));
                bool visto = false;
                for (int i = 0; i < 100 && !visto; i++)
                {
                    visto = recibidos.Any(c => string.Equals(c.Ruta, f, StringComparison.OrdinalIgnoreCase));
                    if (!visto) await Task.Delay(100).ConfigureAwait(false);
                }
                Check(visto, "un archivo creado dentro de la carpeta llega por el diario USN, con su ruta completa",
                      string.Join(", ", recibidos.Select(c => c.Ruta)));

                string fuera = Path.Combine(raiz, "fuera-del-prefijo.exe");
                File.WriteAllText(fuera, "x");
                await Task.Delay(1500).ConfigureAwait(false);
                Check(!recibidos.Any(c => string.Equals(c.Ruta, fuera, StringComparison.OrdinalIgnoreCase)),
                      "lo que cambia fuera de las carpetas pedidas no se emite");
            }

            Console.WriteLine();
        }
    }
}
