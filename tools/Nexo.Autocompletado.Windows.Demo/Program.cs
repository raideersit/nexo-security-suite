using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;
using Nexo.Autocompletado.Host;
using Nexo.Modules.Identity.Autocompletado;

namespace Nexo.Autocompletado.Windows.Demo
{
    internal static class Program
    {
        private static int _fallos;
        private static readonly string[] ClavesDeNavegador = InstaladorDeHostNativo.Navegadores.Select(n => n.Subclave).ToArray();

        private static async Task<int> Main()
        {
            string exe = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Nexo.Autocompletado.Host", "bin", "Debug",
                                                       "net8.0-windows", "nexo-autocompletar.exe"));
            if (!File.Exists(exe)) { Console.WriteLine("No está " + exe + ": compila antes src/Nexo.Autocompletado.Host."); return 1; }
            Console.WriteLine("Host: " + exe);

            // Lo que había ANTES en las claves de los navegadores: al final tiene que ser exactamente lo mismo.
            string?[] antes = ClavesDeNavegador.Select(LeerHkcu).ToArray();
            string raiz = @"Software\NexoPruebas-" + Guid.NewGuid().ToString("N")[..8];
            string dir = Path.Combine(Path.GetTempPath(), "nexo-autocompletado-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(dir);
            try
            {
                ProbarRegistroReal(raiz, dir, exe);
                ProbarExeComoInstalador(raiz, dir, exe);
                await ProbarExeComoNavegador(exe).ConfigureAwait(false);
            }
            finally
            {
                Registry.CurrentUser.DeleteSubKeyTree(raiz, throwOnMissingSubKey: false);
                try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }

            Console.WriteLine("Limpieza");
            Check(Registry.CurrentUser.OpenSubKey(raiz) is null, "la clave de pruebas ya no existe");
            Check(ClavesDeNavegador.Select(LeerHkcu).SequenceEqual(antes), "las claves que leen Brave/Chrome y Edge quedaron como estaban (" +
                  string.Join(", ", antes.Select(a => a ?? "no existían")) + ")");

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool c, string d, string? detalle = null)
        {
            if (!c) _fallos++;
            Console.WriteLine($"  [{(c ? "OK" : "FALLO")}]    {d}");
            if (!c && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static string? LeerHkcu(string subclave)
        {
            using RegistryKey? k = Registry.CurrentUser.OpenSubKey(subclave);
            return k?.GetValue("") as string;
        }

        private static void ProbarRegistroReal(string raiz, string dir, string exe)
        {
            Console.WriteLine("1. Registro real de Windows (bajo " + raiz + ")");
            var reg = new RegistroDeWindows(raiz);
            string man = Path.Combine(dir, "lib", InstaladorDeHostNativo.NombreDelHost + ".json");
            IReadOnlyList<string> p = InstaladorDeHostNativo.Instalar(reg, man, exe, new[] { InstaladorDeHostNativo.IdDeLaExtension });
            Check(p.Count == 0, "instalar sin problemas", string.Join("; ", p));
            Check(ClavesDeNavegador.All(c => LeerHkcu(raiz + "\\" + c) == man), "leído con la API de Windows: las dos claves tienen como valor por omisión la ruta del manifiesto");
            using (RegistryKey? k = Registry.CurrentUser.OpenSubKey(raiz + "\\" + ClavesDeNavegador[0]))
                Check(k?.GetValueKind("") == RegistryValueKind.String && k.GetValueNames().SequenceEqual(new[] { "" }),
                    "el valor es REG_SZ (lo que espera Chromium) y no hay otros valores");
            Check(InstaladorDeHostNativo.Revisar(reg).All(e => e.Situacion == SituacionDelHost.Listo), "revisar: «listo» con el exe real");
            Check(reg.LeerValor(@"Software\NoExiste\Nada") is null && !reg.BorrarClave(@"Software\NoExiste\Nada"), "una clave que no existe: null, y borrarla da false sin error");
            IReadOnlyList<string> d = InstaladorDeHostNativo.Desinstalar(reg, man);
            Check(ClavesDeNavegador.All(c => Registry.CurrentUser.OpenSubKey(raiz + "\\" + c) is null) && !File.Exists(man),
                "desinstalar: las claves desaparecen del registro y el manifiesto se borra", string.Join("; ", d));
            bool raro = false;
            try { _ = new RegistroDeWindows(@"Sistema\X"); } catch (ArgumentException) { raro = true; }
            Check(raro, "una raíz de pruebas fuera de Software\\: rechazada");
        }

        private static (int codigo, string salida) Ejecutar(string exe, params string[] args)
        {
            var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, StandardOutputEncoding = Encoding.UTF8 };
            foreach (string a in args) psi.ArgumentList.Add(a);
            using Process pr = Process.Start(psi)!;
            string o = pr.StandardOutput.ReadToEnd() + pr.StandardError.ReadToEnd();
            pr.WaitForExit();
            return (pr.ExitCode, o);
        }

        private static void ProbarExeComoInstalador(string raiz, string dir, string exe)
        {
            Console.WriteLine("2. nexo-autocompletar --instalar / --estado / --desinstalar (con la raíz de pruebas)");
            string man = Path.Combine(dir, "exe", "m.json");
            (int c, string o) = Ejecutar(exe, "--estado", "--raiz-de-pruebas", raiz, "--manifiesto", man);
            Check(c == 1 && o.Contains("no registrado"), "--estado sin instalar: código 1 y «no registrado»", c + " / " + o);
            (c, o) = Ejecutar(exe, "--instalar", "--raiz-de-pruebas", raiz, "--manifiesto", man);
            Check(c == 0 && o.Contains("Brave y Chrome: listo") && o.Contains("Edge: listo"), "--instalar: código 0 y los dos «listo»", c + " / " + o);
            JsonElement m = JsonDocument.Parse(File.ReadAllBytes(man)).RootElement;
            Check(string.Equals(m.GetProperty("path").GetString(), exe, StringComparison.OrdinalIgnoreCase), "el manifiesto apunta a este mismo exe (Environment.ProcessPath)", m.GetProperty("path").GetString());
            (c, o) = Ejecutar(exe, "--estado", "--raiz-de-pruebas", raiz, "--manifiesto", man);
            Check(c == 0, "--estado instalado: código 0", o);
            (c, o) = Ejecutar(exe, "--desinstalar", "--raiz-de-pruebas", raiz, "--manifiesto", man);
            Check(c == 0 && o.Split('\n').Count(l => l.Contains("quitado")) == 2 && !File.Exists(man), "--desinstalar: quita los dos y el manifiesto", o);
            (c, o) = Ejecutar(exe);
            Check(c == 0 && o.Contains("--instalar"), "sin argumentos: ayuda en español");
            (c, o) = Ejecutar(exe, "--algo-raro");
            Check(c == 1, "argumento desconocido: código 1 (no instala nada)");
        }

        private static byte[] Trama(string json)
        {
            byte[] j = Encoding.UTF8.GetBytes(json), b = new byte[j.Length + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)j.Length);
            j.CopyTo(b, 4);
            return b;
        }

        /// <summary>Lanza el exe como Chromium (origen + --parent-window), le escribe <paramref name="entrada"/> y cierra stdin. Devuelve código, stdout crudo y stderr.</summary>
        private static async Task<(int codigo, byte[] salida, string error)> ComoNavegador(string exe, byte[] entrada, string origen)
        {
            var psi = new ProcessStartInfo(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add(origen);
            psi.ArgumentList.Add("--parent-window=0");
            using Process pr = Process.Start(psi)!;
            var ms = new MemoryStream();
            Task copia = pr.StandardOutput.BaseStream.CopyToAsync(ms);
            Task<string> err = pr.StandardError.ReadToEndAsync();
            try
            {
                await pr.StandardInput.BaseStream.WriteAsync(entrada).ConfigureAwait(false);
                await pr.StandardInput.BaseStream.FlushAsync().ConfigureAwait(false);
            }
            catch (IOException) { /* el host ya cerró (p. ej. origen no válido) */ }
            pr.StandardInput.Close();
            if (!pr.WaitForExit(30_000)) { pr.Kill(); return (-1, ms.ToArray(), "colgado"); }
            await copia.ConfigureAwait(false);
            return (pr.ExitCode, ms.ToArray(), await err.ConfigureAwait(false));
        }

        private static List<JsonElement> Respuestas(byte[] b)
        {
            var l = new List<JsonElement>();
            int i = 0;
            while (i + 4 <= b.Length)
            {
                int n = (int)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i));
                if (n <= 0 || i + 4 + n > b.Length) { l.Add(JsonDocument.Parse("{\"estado\":\"TRAMA ROTA\"}").RootElement.Clone()); return l; }
                l.Add(JsonDocument.Parse(b.AsMemory(i + 4, n)).RootElement.Clone());
                i += 4 + n;
            }
            if (i != b.Length) l.Add(JsonDocument.Parse("{\"estado\":\"BYTES SOBRANTES\"}").RootElement.Clone());
            return l;
        }

        private static async Task ProbarExeComoNavegador(string exe)
        {
            Console.WriteLine("3. El exe lanzado como lo lanza el navegador (stdin/stdout binarios, pipe real con el nombre de tu usuario)");
            string origen = InstaladorDeHostNativo.OrigenDe(InstaladorDeHostNativo.IdDeLaExtension);

            // Sin ventana de Nexo.
            var sw = Stopwatch.StartNew();
            (int c, byte[] o, string e) = await ComoNavegador(exe, Trama("{\"tipo\":\"estado\",\"navegador\":\"brave\"}"), origen).ConfigureAwait(false);
            List<JsonElement> r = Respuestas(o);
            Check(c == 0 && r.Count == 1 && r[0].GetProperty("estado").GetString() == "sin_nexo" && e.Length == 0,
                "sin la ventana de Nexo: el exe contesta «sin_nexo», sale con 0 y no escribe en stderr", c + " / " + Encoding.UTF8.GetString(o) + " / " + e);
            Console.WriteLine("           (" + sw.ElapsedMilliseconds + " ms, incluye los 2 s de espera de conexión)");

            // Con un «Nexo» de pruebas escuchando en el pipe real del usuario: hace eco y cuenta.
            int vistas = 0;
            ServidorDeAutocompletado srv = new ServidorDeAutocompletado(CanalDeAutocompletado.NombreDePipeActual(), (p, ct) =>
            {
                vistas++;
                using JsonDocument d = JsonDocument.Parse(p);
                return Task.FromResult(JsonSerializer.SerializeToUtf8Bytes(new { estado = "ok", eco = d.RootElement.GetProperty("tipo").GetString(), n = vistas, texto = "ñandú «sí»" }));
            });
            try { srv.Iniciar(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Check(false, "no se pudo abrir el pipe real (¿hay otro Nexo con autocompletado abierto?)", ex.Message);
                return;
            }
            await using (srv.ConfigureAwait(false))
            {
                sw.Restart();
                byte[] tres = Trama("{\"tipo\":\"uno\"}").Concat(Trama("{\"tipo\":\"dos\"}")).Concat(Trama("{\"tipo\":\"tres\"}")).ToArray();
                (c, o, e) = await ComoNavegador(exe, tres, origen).ConfigureAwait(false);
                r = Respuestas(o);
                Check(c == 0 && r.Select(x => x.GetProperty("eco").GetString()).SequenceEqual(new[] { "uno", "dos", "tres" }) && e.Length == 0,
                    "tres mensajes en un mismo proceso (como connectNative): tres respuestas en orden, código 0, stderr vacío", c + " / " + Encoding.UTF8.GetString(o) + " / " + e);
                Check(r.Count == 3 && r.All(x => x.GetProperty("estado").GetString() == "ok"), "stdout es SOLO tramas del protocolo (ni un byte de más)");
                Check(r.Count == 3 && r[0].GetProperty("texto").GetString() == "ñandú «sí»", "UTF-8 sin estropear (sin modo texto ni \\r\\n)");
                Console.WriteLine("           (" + sw.ElapsedMilliseconds + " ms para lanzar el exe y hacer tres idas y vueltas)");

                int antes = vistas;
                (c, o, _) = await ComoNavegador(exe, Trama("{\"tipo\":\"uno\"}"), "chrome-extension://noesunid/").ConfigureAwait(false);
                Check(c == 3 && o.Length == 0 && vistas == antes, "origen mal formado: el exe sale con 3, no contesta y no llega nada a Nexo");
                (c, o, _) = await ComoNavegador(exe, BitConverter.GetBytes(MensajeNativo.MaxEntrada + 1), origen).ConfigureAwait(false);
                Check(c == 2 && o.Length == 0 && vistas == antes, "trama de más de 64 KB: el exe sale con 2 sin reenviar nada");
                (c, o, _) = await ComoNavegador(exe, Array.Empty<byte>(), origen).ConfigureAwait(false);
                Check(c == 0 && o.Length == 0, "el navegador cierra sin mandar nada: sale con 0");
            }
        }
    }
}
