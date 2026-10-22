using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Vault;

namespace Nexo.Service
{
    /// <summary>
    /// Arranca el vault y el pipe IPC y deja constancia en una nota. Todo I/O con
    /// CancellationToken: al parar, el SCM da 5 s y despues mata el proceso.
    /// </summary>
    public sealed class NexoWorker : BackgroundService
    {
        private readonly IConfiguration _config;
        private readonly IHostApplicationLifetime _vida;

        public NexoWorker(IConfiguration config, IHostApplicationLifetime vida)
        {
            _config = config;
            _vida = vida;
        }

        public static string RutaDeVaultPorDefecto()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nexo", "Vault");

        protected override async Task ExecuteAsync(CancellationToken parada)
        {
            string version = typeof(NexoWorker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                             ?? "0.0.0";
            int plus = version.IndexOf('+');
            if (plus > 0) version = version[..plus];

            string vaultCfg = _config["Nexo:Vault"] ?? "";
            string vault = string.IsNullOrWhiteSpace(vaultCfg) ? RutaDeVaultPorDefecto() : vaultCfg;
            string pipe = _config["Nexo:PipeName"] ?? "NexoIpc";

            using var reportes = new ReportWriter(new VaultOptions { RutaVault = vault });
            await reportes.InicializarVaultAsync(parada).ConfigureAwait(false);

            var inicio = Stopwatch.StartNew();
            ServidorDePipe? servidor = null;
            string? aviso = null;
            try
            {
                servidor = new ServidorDePipe(pipe, new ManejadorDelServicio(version));
                servidor.Iniciar();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // No se aborta: el servicio puede seguir sin IPC, pero NO se finge que lo tiene.
                aviso = "El pipe '" + pipe + "' no se pudo abrir (" + ex.GetType().Name + "). Otro proceso lo tiene o falta permiso.";
                servidor = null;
            }

            await reportes.EscribirAsync(Eventos.Sistema.ServicioIniciado(version, servidor is not null, aviso), parada)
                          .ConfigureAwait(false);

            try { await Task.Delay(Timeout.Infinite, parada).ConfigureAwait(false); }
            catch (OperationCanceledException) { }

            int atendidas = servidor?.Atendidas ?? 0;
            if (servidor is not null) await servidor.DisposeAsync().ConfigureAwait(false);

            // CancellationToken.None: la parada ya esta pedida y esta nota debe escribirse igualmente.
            await reportes.EscribirAsync(Eventos.Sistema.ServicioDetenido(inicio.Elapsed, atendidas), CancellationToken.None)
                          .ConfigureAwait(false);
        }
    }
}
