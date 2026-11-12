using System;
using System.IO;
using Nexo.Modules.Threats.Ransomware;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        /// <summary>El gancho que protege la carpeta de copias: cuándo se llama, y que su fallo nunca tumba la copia ni se calla.</summary>
        private static void ProbarProteccionDeCopia()
        {
            Console.WriteLine("29b. Copia versionada: gancho que protege la carpeta de copias");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-prot-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "docs");
            try
            {
                Directory.CreateDirectory(docs);
                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno");

                // 1. Se llama UNA vez, con la carpeta de Nexo ya creada y todavía VACÍA (así lo de dentro hereda los permisos).
                string copia1 = Path.Combine(raiz, "c1");
                int llamadas = 0; string? recibida = null; bool existiaRaiz = false, existiaContenido = true;
                var cfg1 = new ConfiguracionDeCopia(new[] { docs }, copia1, 3, ProtegerCarpeta: ruta =>
                {
                    llamadas++; recibida = ruta;
                    existiaRaiz = Directory.Exists(ruta);
                    existiaContenido = Directory.Exists(Path.Combine(ruta, "contenido")) || Directory.Exists(Path.Combine(ruta, "instantaneas"));
                    return null;
                });
                ResultadoDeCopia r1 = CopiaVersionada.Copiar(cfg1, T0);
                Check(r1.Correcto && llamadas == 1, "el gancho se llama una vez por copia", $"llamadas={llamadas} error={r1.Error}");
                Check(recibida == Path.Combine(Path.GetFullPath(copia1), CopiaVersionada.CarpetaDeCopias), "recibe la carpeta de Nexo dentro del destino, no el destino entero", recibida);
                Check(existiaRaiz && !existiaContenido, "se llama con la carpeta creada y ANTES de crear «contenido» e «instantaneas»");
                Check(r1.AvisoDeProteccion is null, "si el gancho dice null (protegida), no hay aviso");

                // 2. Si no pudo proteger: la copia se hace igual y el motivo llega, no se calla.
                var cfg2 = new ConfiguracionDeCopia(new[] { docs }, Path.Combine(raiz, "c2"), 3, ProtegerCarpeta: _ => "El destino usa exFAT, que no admite permisos");
                ResultadoDeCopia r2 = CopiaVersionada.Copiar(cfg2, T0);
                Check(r2.Correcto && r2.Instantanea!.Entradas.Count == 1, "el gancho no pudo proteger: la copia se hace igual");
                Check(r2.AvisoDeProteccion == "El destino usa exFAT, que no admite permisos", "y el motivo llega tal cual en el resultado", r2.AvisoDeProteccion);

                // 3. Si el gancho LANZA, tampoco tumba la copia, y se dice.
                var cfg3 = new ConfiguracionDeCopia(new[] { docs }, Path.Combine(raiz, "c3"), 3, ProtegerCarpeta: _ => throw new UnauthorizedAccessException("sin permiso"));
                ResultadoDeCopia r3 = CopiaVersionada.Copiar(cfg3, T0);
                Check(r3.Correcto && r3.AvisoDeProteccion is { } a3 && a3.Contains("No se pudo proteger") && a3.Contains("sin permiso"), "un gancho que lanza: copia hecha y aviso con el motivo", r3.AvisoDeProteccion);

                // 4. Sin gancho (como antes): sin aviso, y la copia es idéntica.
                ResultadoDeCopia r4 = CopiaVersionada.Copiar(new ConfiguracionDeCopia(new[] { docs }, Path.Combine(raiz, "c4"), 3), T0);
                Check(r4.Correcto && r4.AvisoDeProteccion is null, "sin gancho: igual que antes y sin aviso");

                // 5. Una segunda copia en el mismo destino vuelve a llamar al gancho (por si cambió algo entre copias) y sigue bien.
                llamadas = 0;
                ResultadoDeCopia r5 = CopiaVersionada.Copiar(cfg1, T0.AddMinutes(1));
                Check(r5.Correcto && llamadas == 1 && existiaRaiz, "la segunda copia en el mismo destino vuelve a llamarlo");
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }
    }
}
