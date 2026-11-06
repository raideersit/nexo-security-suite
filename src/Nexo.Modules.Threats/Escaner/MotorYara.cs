using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Threats.Escaner
{
    /// <summary>Como se lanza <c>yara64.exe</c>. Todo es configurable; los limites tienen valores prudentes.</summary>
    public sealed record OpcionesDeYara(
        string Ejecutable,
        string Reglas,
        string CarpetaTemporal)
    {
        /// <summary>Tiempo maximo por analisis. YARA recibe <c>-a</c> con este valor y, ademas, se mata el proceso.</summary>
        public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tamano maximo de lo que se vuelca a la copia temporal. Mas grande NO es «limpio»: es un error
        /// (el esc&aacute;ner lo cuenta como no analizado).
        /// </summary>
        public long MaximoDeBytes { get; init; } = 100L * 1024 * 1024;

        /// <summary>
        /// Argumentos que van ANTES de los de YARA, para lanzarlo a traves de un envoltorio. Las pruebas lo usan para
        /// ejecutar un yara falso; en produccion queda vacio.
        /// </summary>
        public IReadOnlyList<string> ArgumentosPrevios { get; init; } = Array.Empty<string>();

        /// <summary>Las copias temporales mas viejas que esto (restos de una caida) se borran al arrancar.</summary>
        public TimeSpan EdadMaximaDeRestos { get; init; } = TimeSpan.FromHours(1);
    }

    /// <summary>
    /// Motor de firmas YARA a traves de su ejecutable de linea de comandos (<c>yara64.exe</c>, BSD-3: no hay problema de
    /// licencia al ejecutarlo).
    ///
    /// <c>yara64.exe</c> en Windows solo lee archivos por RUTA (no acepta stdin: «-» y «CON» fallan, comprobado con
    /// la 4.6.0), y <see cref="IMotorDeFirmas"/> entrega un <see cref="Stream"/>. Por eso el contenido se vuelca a una
    /// copia temporal y se borra en cuanto YARA termina:
    ///  - nombre aleatorio, en una carpeta que solo deben poder leer SYSTEM y Administradores (la de ProgramData\Nexo);
    ///  - tope de tamano (<see cref="OpcionesDeYara.MaximoDeBytes"/>);
    ///  - se borra siempre (finally), tambien si se cancela o falla, y al arrancar se barren los restos de una caida.
    ///
    /// Regla del proyecto, como en <see cref="ClamdClient"/>: ante la duda, JAMAS «limpio». YARA sale con 0 tanto si
    /// encuentra algo como si no, asi que la deteccion se lee de la salida estandar, y una salida que no se entiende es
    /// un error, no un «limpio».
    /// </summary>
    public sealed class MotorYara : IMotorDeFirmas
    {
        private const string Prefijo = "nexo-yara-";

        private readonly OpcionesDeYara _o;

        public MotorYara(OpcionesDeYara opciones)
        {
            if (opciones is null) throw new ArgumentNullException(nameof(opciones));
            if (!Path.IsPathRooted(opciones.Ejecutable)) throw new ArgumentException("La ruta de yara debe ser absoluta.", nameof(opciones));
            if (!Path.IsPathRooted(opciones.Reglas)) throw new ArgumentException("La ruta de las reglas debe ser absoluta.", nameof(opciones));
            if (!Path.IsPathRooted(opciones.CarpetaTemporal)) throw new ArgumentException("La carpeta temporal debe ser una ruta absoluta.", nameof(opciones));
            if (opciones.Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(opciones));
            if (opciones.MaximoDeBytes < 1) throw new ArgumentOutOfRangeException(nameof(opciones));
            _o = opciones;
            BarrerRestos();
        }

        public string Nombre => "YARA";

        public async Task<string> VersionAsync(CancellationToken ct = default)
        {
            if (!File.Exists(_o.Ejecutable)) throw new MotorNoDisponibleException("No existe el ejecutable de YARA: " + _o.Ejecutable);
            if (!File.Exists(_o.Reglas)) throw new MotorNoDisponibleException("No existe el archivo de reglas: " + _o.Reglas);

            SalidaDeProceso s;
            try { s = await EjecutarAsync(new[] { "--version" }, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is IOException)
            {
                throw new MotorNoDisponibleException("No se pudo ejecutar YARA: " + ex.Message, ex);
            }
            if (s.AgotoElTiempo || s.Codigo != 0 || s.Texto.Trim().Length == 0)
                throw new MotorNoDisponibleException("YARA no respondio a --version" + (s.Errores.Length > 0 ? ": " + Recortar(s.Errores) : "."));
            return "YARA " + s.Texto.Trim() + " (reglas: " + Path.GetFileName(_o.Reglas) + ")";
        }

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            if (contenido is null) throw new ArgumentNullException(nameof(contenido));

            string copia = Path.Combine(_o.CarpetaTemporal, Prefijo + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() + ".bin");
            try
            {
                Directory.CreateDirectory(_o.CarpetaTemporal);

                // 1) Volcar el contenido, con tope. Pasarse del tope es un error, no «limpio».
                try
                {
                    using var fs = new FileStream(copia, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
                    byte[] buf = new byte[64 * 1024];
                    long total = 0;
                    int n;
                    while ((n = await contenido.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false)) > 0)
                    {
                        total += n;
                        if (total > _o.MaximoDeBytes)
                            return ResultadoDeMotor.Fallo("el archivo supera el limite de " + _o.MaximoDeBytes / (1024 * 1024) + " MB para YARA");
                        await fs.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    return ResultadoDeMotor.Fallo("no se pudo preparar la copia temporal para YARA (" + ex.GetType().Name + ")");
                }

                // 2) Ejecutar YARA sobre la copia. -N: no seguir enlaces; -w: sin advertencias; -a: tiempo maximo.
                int segundos = Math.Max(1, (int)Math.Ceiling(_o.Timeout.TotalSeconds));
                SalidaDeProceso s;
                try
                {
                    s = await EjecutarAsync(new[] { "-N", "-w", "-a", segundos.ToString(System.Globalization.CultureInfo.InvariantCulture), _o.Reglas, copia },
                                            _o.Timeout + TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is IOException)
                {
                    return ResultadoDeMotor.Fallo("no se pudo ejecutar YARA (" + ex.GetType().Name + ")");
                }

                if (s.AgotoElTiempo) return ResultadoDeMotor.Fallo("tiempo de espera agotado esperando a YARA");
                return Interpretar(s.Codigo, s.Texto, s.Errores, copia);
            }
            finally
            {
                BorrarCopia(copia);
            }
        }

        /// <summary>
        /// Traduce lo que dijo YARA. Con la salida por omision cada deteccion es una linea «Regla ruta». Codigo 0 y sin
        /// lineas = limpio; cualquier otro codigo, o una linea que no es «Regla + la ruta de la copia», es un error.
        /// </summary>
        public static ResultadoDeMotor Interpretar(int codigo, string salida, string error, string rutaAnalizada)
        {
            if (codigo != 0)
                return ResultadoDeMotor.Fallo("YARA termino con codigo " + codigo + (error.Trim().Length > 0 ? ": " + Recortar(error.Trim()) : ""));

            var reglas = new List<string>();
            foreach (string linea in salida.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0))
            {
                if (!linea.EndsWith(rutaAnalizada, StringComparison.Ordinal))
                    return ResultadoDeMotor.Fallo("salida no reconocida de YARA: " + Recortar(linea));
                string regla = linea[..^rutaAnalizada.Length].Trim();
                if (regla.Length == 0 || regla.Any(char.IsWhiteSpace))
                    return ResultadoDeMotor.Fallo("salida no reconocida de YARA: " + Recortar(linea));
                reglas.Add(regla);
            }

            if (error.Trim().Length > 0)
                return ResultadoDeMotor.Fallo("YARA dejo mensajes de error aunque salio con 0: " + Recortar(error.Trim()));

            return reglas.Count == 0
                ? ResultadoDeMotor.Limpio()
                : ResultadoDeMotor.Infectado("YARA." + string.Join(",", reglas.Distinct().Take(5)));
        }

        private readonly record struct SalidaDeProceso(int Codigo, string Texto, string Errores, bool AgotoElTiempo);

        private async Task<SalidaDeProceso> EjecutarAsync(IEnumerable<string> argumentos, TimeSpan tiempo, CancellationToken ct)
        {
            var psi = new ProcessStartInfo(_o.Ejecutable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = false,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            foreach (string a in _o.ArgumentosPrevios) psi.ArgumentList.Add(a);
            foreach (string a in argumentos) psi.ArgumentList.Add(a);

            using var proceso = new Process { StartInfo = psi };
            proceso.Start();

            // Las dos salidas se leen a la vez: si no, un proceso con mucha salida se bloquea.
            Task<string> salida = LimitadoAsync(proceso.StandardOutput);
            Task<string> error = LimitadoAsync(proceso.StandardError);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(tiempo);
            try
            {
                await proceso.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Matar(proceso);
                if (ct.IsCancellationRequested) throw;
                return new SalidaDeProceso(-1, "", "", AgotoElTiempo: true);
            }

            return new SalidaDeProceso(proceso.ExitCode, await salida.ConfigureAwait(false), await error.ConfigureAwait(false), false);
        }

        /// <summary>Lee hasta 64 KB y descarta el resto: la salida legitima mide decenas de bytes.</summary>
        private static async Task<string> LimitadoAsync(StreamReader lector)
        {
            var sb = new StringBuilder();
            char[] b = new char[4096];
            int n;
            while ((n = await lector.ReadAsync(b.AsMemory()).ConfigureAwait(false)) > 0)
                if (sb.Length < 64 * 1024) sb.Append(b, 0, Math.Min(n, 64 * 1024 - sb.Length));
            return sb.ToString();
        }

        private static void Matar(Process p)
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception) { }
        }

        private static void BorrarCopia(string ruta)
        {
            try { if (File.Exists(ruta)) File.Delete(ruta); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { /* el barrido de arranque lo recoge */ }
        }

        /// <summary>Borra las copias que quedaron de una ejecucion que cayo en medio de un analisis.</summary>
        private void BarrerRestos()
        {
            try
            {
                if (!Directory.Exists(_o.CarpetaTemporal)) return;
                DateTime limite = DateTime.UtcNow - _o.EdadMaximaDeRestos;
                foreach (string f in Directory.EnumerateFiles(_o.CarpetaTemporal, Prefijo + "*.bin"))
                    if (File.GetLastWriteTimeUtc(f) < limite) BorrarCopia(f);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
        }

        private static string Recortar(string s) => s.Length > 200 ? s[..200] + "..." : s;
    }
}
