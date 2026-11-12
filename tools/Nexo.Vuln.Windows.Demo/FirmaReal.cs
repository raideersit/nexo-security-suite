using System;
using System.IO;
using Nexo.Native.Trust;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        /// <summary>Verificación de firmas contra Windows REAL (sin administrador, sin red): firma incrustada, por catálogo, ausente y alterada.</summary>
        public static void ProbarFirmaReal()
        {
            Console.WriteLine("15. Firma digital de archivos sobre Windows REAL");
            string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            foreach (string f in new[] { "kernel32.dll", "cmd.exe", "notepad.exe", "ntdll.dll" })
            {
                string ruta = Path.Combine(sys, f);
                var (r, c) = FirmaDeArchivo.Verificar(ruta);
                Check(r == ResultadoDeFirma.Valida, "«" + f + "» de System32 es válida (firma incrustada o por catálogo)", r + " 0x" + c.ToString("X"));
            }

            string tmp = Path.Combine(Path.GetTempPath(), "nexo-firma-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmp);
            try
            {
                string texto = Path.Combine(tmp, "nada.exe");
                File.WriteAllText(texto, "esto no es un ejecutable");
                Check(FirmaDeArchivo.Verificar(texto).Resultado != ResultadoDeFirma.Valida, "un archivo cualquiera NO sale válido");

                // Una copia de un binario firmado, alterada: nunca válida.
                string alterada = Path.Combine(tmp, "cmd-alterado.exe");
                File.Copy(Path.Combine(sys, "cmd.exe"), alterada);
                using (var fs = new FileStream(alterada, FileMode.Append)) fs.WriteByte(0);
                var (ra, _) = FirmaDeArchivo.Verificar(alterada);
                Check(ra is ResultadoDeFirma.Invalida or ResultadoDeFirma.Ausente, "un cmd.exe alterado (1 byte añadido) NO sale válido", ra.ToString());

                // La copia sin alterar sí conserva la firma incrustada (cmd.exe la lleva incrustada en esta versión de Windows; si no, el catálogo la cubre por hash).
                string copia = Path.Combine(tmp, "cmd-copia.exe");
                File.Copy(Path.Combine(sys, "cmd.exe"), copia);
                Check(FirmaDeArchivo.Verificar(copia).Resultado == ResultadoDeFirma.Valida, "la copia sin alterar sigue válida (la firma viaja con el contenido)");
            }
            finally { try { Directory.Delete(tmp, true); } catch { /* temporal */ } }

            Check(FirmaDeArchivo.Verificar(Path.Combine(sys, "no-existe.exe")).Resultado == ResultadoDeFirma.NoSePudo, "un archivo que no existe es «no se pudo», no «sin firma»");
            Check(FirmaDeArchivo.Verificar(null).Resultado == ResultadoDeFirma.NoSePudo && FirmaDeArchivo.Verificar("").Resultado == ResultadoDeFirma.NoSePudo, "ruta null o vacía: «no se pudo»");
        }
    }
}
