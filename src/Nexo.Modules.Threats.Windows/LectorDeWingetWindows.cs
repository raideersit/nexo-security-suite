using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Ejecuta <c>winget upgrade</c> (solo CONSULTA: jamas instala ni actualiza nada) y devuelve su salida para
    /// <see cref="ParserDeActualizacionesWinget"/>. Usa <c>--accept-source-agreements --disable-interactivity</c> para que no se
    /// quede esperando una respuesta, entrada vacia, tope de tiempo y de tamano. winget necesita sesion de usuario: lanzado
    /// desde el servicio como SYSTEM normalmente no funciona; este lector esta pensado para la ventana o la linea de comandos.
    /// </summary>
    public static class LectorDeWingetWindows
    {
        public static readonly TimeSpan EsperaPorOmision = TimeSpan.FromSeconds(120);
        private const int MaximoDeCaracteres = 2 * 1024 * 1024;

        public static async Task<SalidaDeWinget> LeerAsync(TimeSpan? espera = null, CancellationToken ct = default)
        {
            TimeSpan limite = espera ?? EsperaPorOmision;
            var psi = new ProcessStartInfo("winget")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("upgrade");
            psi.ArgumentList.Add("--accept-source-agreements");
            psi.ArgumentList.Add("--disable-interactivity");

            Process? p;
            try { p = Process.Start(psi); }
            catch (Win32Exception) { return new SalidaDeWinget(EstadoDeWinget.NoInstalado, "", -1); }
            if (p is null) return new SalidaDeWinget(EstadoDeWinget.NoInstalado, "", -1);

            using (p)
            {
                try
                {
                    p.StandardInput.Close(); // nada que responder: si pregunta algo, termina en vez de colgarse
                    Task<string> salida = LeerAcotadoAsync(p.StandardOutput);
                    Task<string> errores = LeerAcotadoAsync(p.StandardError);

                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(limite);
                    try { await p.WaitForExitAsync(cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        TryMatar(p);
                        return new SalidaDeWinget(EstadoDeWinget.TiempoAgotado, "", -1);
                    }
                    catch (OperationCanceledException) { TryMatar(p); throw; }

                    string texto = await salida.ConfigureAwait(false);
                    _ = await errores.ConfigureAwait(false);
                    return new SalidaDeWinget(EstadoDeWinget.Correcta, texto, p.ExitCode);
                }
                catch (Exception e) when (e is InvalidOperationException or System.IO.IOException)
                {
                    TryMatar(p);
                    return new SalidaDeWinget(EstadoDeWinget.Error, "", -1);
                }
            }
        }

        private static async Task<string> LeerAcotadoAsync(System.IO.StreamReader r)
        {
            var sb = new StringBuilder();
            char[] buf = new char[8192];
            int n;
            while ((n = await r.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false)) > 0)
            {
                if (sb.Length + n > MaximoDeCaracteres) { sb.Append('\n').Append("[salida recortada]"); break; }
                sb.Append(buf, 0, n);
            }
            return sb.ToString();
        }

        private static void TryMatar(Process p)
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (Exception e) when (e is InvalidOperationException or Win32Exception) { }
        }
    }
}
