using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vpn;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Conecta y desconecta tuneles con el WireGuard oficial (<c>wireguard /installtunnelservice</c> y <c>/uninstalltunnelservice</c>,
    /// segun su documentacion). Corre en el servicio de Nexo (SYSTEM), solo despues de la vista previa, el token y la aprobacion.
    /// Defensas:
    ///  - El archivo se guarda en una carpeta cuyo acceso es SOLO de SYSTEM y administradores (sin herencia): la documentacion no dice si el
    ///    servicio del tunel relee el archivo en cada arranque, asi que no puede quedar donde un proceso normal del usuario lo cambie.
    ///  - wireguard.exe se ejecuta sin shell, con argumentos separados (nada que inyectar), y solo desde Archivos de programa.
    ///  - El nombre del tunel se vuelve a validar aqui (no se confia en quien llama).
    ///  - Tras instalar se comprueba que el servicio exista; un codigo de salida distinto de 0 es un fallo, con el codigo.
    /// </summary>
    public sealed class EjecutorDeWireGuardWindows : IEjecutorDeWireGuard
    {
        private readonly string _exe;
        private readonly TimeSpan _espera;

        public EjecutorDeWireGuardWindows(string? carpeta = null, TimeSpan? espera = null)
        {
            Carpeta = carpeta ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nexo", "vpn");
            _exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe");
            _espera = espera ?? TimeSpan.FromSeconds(60);
        }

        public string Carpeta { get; }

        private string RutaDe(string tunel) => Path.Combine(Carpeta, tunel + ".conf");

        public bool EsDeNexo(string tunel) => ParserDeWireGuard.ValidarNombre(tunel) is null && File.Exists(RutaDe(tunel));

        public async Task<ResultadoDeVpn> ConectarAsync(string tunel, string conf, CancellationToken ct)
        {
            if (ParserDeWireGuard.ValidarNombre(tunel) is string e) return new ResultadoDeVpn(false, "el nombre del túnel no es válido (" + e + ")");
            if (!File.Exists(_exe)) return new ResultadoDeVpn(false, "no se encuentra WireGuard en «" + _exe + "»");
            string ruta = RutaDe(tunel);
            try
            {
                CrearCarpetaProtegida();
                string tmp = ruta + ".tmp";
                File.WriteAllText(tmp, conf, new UTF8Encoding(false));
                File.Move(tmp, ruta, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                // Sin ser SYSTEM o administrador no se pueden fijar estos permisos: mejor no instalar que dejar el archivo desprotegido.
                return new ResultadoDeVpn(false, "no se pudo guardar el archivo en la carpeta protegida (" + ex.GetType().Name + "). No se instaló nada.");
            }

            (int? codigo, string? fallo) = await EjecutarAsync(ct, "/installtunnelservice", ruta).ConfigureAwait(false);
            if (codigo != 0)
            {
                TryBorrar(ruta);
                return new ResultadoDeVpn(false, "WireGuard no pudo instalar el túnel (" + (fallo ?? "código " + codigo) + "). Se borró la copia del archivo.");
            }
            // Comprobar que el servicio existe de verdad (y esperar un poco a que arranque).
            EstadoDeTunel? estado = await EsperarServicioAsync(tunel, debeExistir: true, ct).ConfigureAwait(false);
            if (estado is null) return new ResultadoDeVpn(false, "WireGuard terminó sin error, pero el servicio del túnel no aparece. Revisa WireGuard.");
            return new ResultadoDeVpn(true, estado == EstadoDeTunel.Activo
                ? "Túnel «" + tunel + "» instalado y en marcha. Que el servidor responda no se comprueba aquí."
                : "Túnel «" + tunel + "» instalado, pero Windows lo marca como " + estado + ".");
        }

        public async Task<ResultadoDeVpn> DesconectarAsync(string tunel, CancellationToken ct)
        {
            if (ParserDeWireGuard.ValidarNombre(tunel) is string e) return new ResultadoDeVpn(false, "el nombre del túnel no es válido (" + e + ")");
            if (!File.Exists(_exe)) return new ResultadoDeVpn(false, "no se encuentra WireGuard en «" + _exe + "»");
            (int? codigo, string? fallo) = await EjecutarAsync(ct, "/uninstalltunnelservice", tunel).ConfigureAwait(false);
            if (codigo != 0) return new ResultadoDeVpn(false, "WireGuard no pudo quitar el túnel (" + (fallo ?? "código " + codigo) + ").");
            EstadoDeTunel? queda = await EsperarServicioAsync(tunel, debeExistir: false, ct).ConfigureAwait(false);
            bool borrado = TryBorrar(RutaDe(tunel));
            if (queda is not null) return new ResultadoDeVpn(false, "WireGuard terminó sin error, pero el servicio del túnel sigue ahí (" + queda + ").");
            return new ResultadoDeVpn(true, "Túnel «" + tunel + "» desconectado y quitado." + (borrado ? "" : " No se pudo borrar la copia del archivo en «" + Carpeta + "»: bórrala a mano."));
        }

        /// <summary>Crea (o corrige) la carpeta con acceso solo para SYSTEM y administradores, sin heredar permisos de la carpeta de arriba.</summary>
        private void CrearCarpetaProtegida()
        {
            var seguridad = new DirectorySecurity();
            seguridad.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var sistema = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            foreach (SecurityIdentifier sid in new[] { sistema, admins })
                seguridad.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            seguridad.SetOwner(admins);
            var dir = new DirectoryInfo(Carpeta);
            if (!dir.Exists) dir.Create(seguridad);
            else dir.SetAccessControl(seguridad);
        }

        private async Task<(int? Codigo, string? Fallo)> EjecutarAsync(CancellationToken ct, params string[] argumentos)
        {
            var psi = new ProcessStartInfo(_exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string a in argumentos) psi.ArgumentList.Add(a);
            try
            {
                using Process p = Process.Start(psi) ?? throw new InvalidOperationException("no se pudo iniciar");
                using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limite.CancelAfter(_espera);
                Task<string> err = p.StandardError.ReadToEndAsync(limite.Token);
                _ = p.StandardOutput.ReadToEndAsync(limite.Token);
                try { await p.WaitForExitAsync(limite.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                    return (null, "WireGuard no terminó en " + (int)_espera.TotalSeconds + " s");
                }
                string e = (await err.ConfigureAwait(false)).Trim();
                return (p.ExitCode, p.ExitCode == 0 ? null : "código " + p.ExitCode + (e.Length > 0 ? ": " + (e.Length > 200 ? e.Substring(0, 200) + "…" : e) : ""));
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
            {
                return (null, "no se pudo ejecutar WireGuard (" + ex.GetType().Name + ")");
            }
        }

        private static async Task<EstadoDeTunel?> EsperarServicioAsync(string tunel, bool debeExistir, CancellationToken ct)
        {
            string nombre = LectorDeWireGuardWindows.PrefijoDeServicio + tunel;
            EstadoDeTunel? ultimo = null;
            for (int i = 0; i < 20; i++)
            {
                ultimo = LeerServicio(nombre);
                if (debeExistir ? ultimo == EstadoDeTunel.Activo : ultimo is null) return ultimo;
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            return ultimo;
        }

        private static EstadoDeTunel? LeerServicio(string nombre)
        {
            ServiceController[] todos = ServiceController.GetServices();
            try
            {
                ServiceController? s = todos.FirstOrDefault(x => string.Equals(x.ServiceName, nombre, StringComparison.OrdinalIgnoreCase));
                if (s is null) return null;
                return s.Status switch
                {
                    ServiceControllerStatus.Running => EstadoDeTunel.Activo,
                    ServiceControllerStatus.Stopped => EstadoDeTunel.Detenido,
                    _ => EstadoDeTunel.Cambiando
                };
            }
            catch (Exception e) when (e is Win32Exception or InvalidOperationException) { return EstadoDeTunel.Desconocido; }
            finally { foreach (ServiceController x in todos) x.Dispose(); }
        }

        private static bool TryBorrar(string ruta)
        {
            try { if (File.Exists(ruta)) File.Delete(ruta); return true; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
        }
    }
}
