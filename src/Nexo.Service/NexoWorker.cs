using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Threats.Cuarentena;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Firewall;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Modules.Threats.Windows;
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
        private readonly IServiceProvider _servicios;

        public NexoWorker(IConfiguration config, IServiceProvider servicios)
        {
            _config = config;
            _servicios = servicios;
        }

        public static string RutaDeVaultPorDefecto()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nexo", "Vault");

        private IReadOnlyList<IModuloDelServicio> CrearModulos(IReportWriter reportes, string vault)
        {
            // El almacen se puede sustituir por DI (las pruebas usan uno en memoria y no tocan el firewall real).
            IAlmacenDeFirewall almacen = _servicios.GetService<IAlmacenDeFirewall>() ?? new AlmacenDeFirewallWindows();
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

            // Nombres extra que no se bloquean: solo AMPLIAN la proteccion (ver GuardiaDeReglas).
            string protegidos = _config["Nexo:Protegidos"] is { Length: > 0 } cfg
                ? cfg
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nexo", "firewall-protegidos.txt");
            var guardia = new GuardiaDeReglas(adicionales: GuardiaDeReglas.LeerAdicionales(protegidos, out _));

            // Motor de firmas: clamd por TCP local (o uno inyectado por DI en las pruebas).
            IMotorDeFirmas motor = _servicios.GetService<IMotorDeFirmas>() ?? new ClamdClient(
                _config["Nexo:ClamdHost"] is { Length: > 0 } h ? h : "127.0.0.1",
                int.TryParse(_config["Nexo:ClamdPuerto"], out int puerto) ? puerto : ClamdClient.PuertoPorDefecto);

            // La carpeta de cuarentena guarda las claves junto a los archivos: solo SYSTEM y
            // Administradores deben poder escribir ahi (lo fija nexo-service.ps1 sobre la carpeta Nexo de ProgramData).
            string carpetaQ = _config["Nexo:Cuarentena"] is { Length: > 0 } q
                ? q
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Nexo", "Quarantine");
            var almacenQ = new AlmacenDeCuarentena(carpetaQ, reportes);
            var escaneo = new ModuloEscaneo(motor, reportes, excluir: new[] { almacenQ.Carpeta });

            var modulos = new List<IModuloDelServicio>
            {
                new ModuloFirewall(new AdministradorDeFirewall(almacen, reportes, admin, guardia)),
                escaneo
            };

            // Tiempo real: APAGADO por omision (hay que activarlo en appsettings.json). Sin metodos para
            // encenderlo ni apagarlo por el pipe: un proceso malicioso los usaria para quitar la proteccion.
            ModuloTiempoReal? tiempoReal = null;
            if (bool.TryParse(_config["Nexo:TiempoReal:Activo"], out bool activo) && activo)
            {
                IReadOnlyList<string> raices = _config["Nexo:TiempoReal:Raices"] is { Length: > 0 } r
                    ? r.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    : ModuloTiempoReal.RaicesPorDefecto();

                // Nunca se analiza a si mismo: ni la cuarentena ni el vault.
                var opciones = new OpcionesDeTiempoReal { Excluir = new[] { almacenQ.Carpeta, vault } };

                // Fuente: "watcher" (FileSystemWatcher; por omision, sin administrador, puede perder eventos)
                // o "usn" (diario NTFS; necesita administrador/SYSTEM, no pierde eventos).
                bool usn = string.Equals(_config["Nexo:TiempoReal:Fuente"], "usn", StringComparison.OrdinalIgnoreCase);
                IFuenteDeCambios fuente = _servicios.GetService<IFuenteDeCambios>()
                    ?? (usn
                        ? new FuenteUsn(raices.Select(r => r.Length > 1 && r[1] == ':' ? r[0] : 'C'), raices)
                        : new FuenteFileSystemWatcher(raices));
                tiempoReal = new ModuloTiempoReal(new VigilanteEnTiempoReal(motor, reportes, opciones), fuente, raices, motor.Nombre);
                tiempoReal.Iniciar();
                modulos.Add(tiempoReal);
            }

            if (tiempoReal is null) modulos.Add(new ModuloTiempoRealApagado());

            modulos.Add(new ModuloCuarentena(almacenQ, tiempoReal is null
                ? escaneo
                : new ResultadosCombinados(escaneo, tiempoReal)));
            return modulos;
        }

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
            IReadOnlyList<IModuloDelServicio> modulos = Array.Empty<IModuloDelServicio>();
            string? aviso = null;
            try
            {
                modulos = CrearModulos(reportes, vault);
                servidor = new ServidorDePipe(pipe, new ManejadorDelServicio(version, modulos));
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
            // Los modulos con trabajos en curso (p. ej. un escaneo) los cancelan al cerrarse.
            foreach (IModuloDelServicio m in modulos)
                if (m is IAsyncDisposable d) await d.DisposeAsync().ConfigureAwait(false);

            // CancellationToken.None: la parada ya esta pedida y esta nota debe escribirse igualmente.
            await reportes.EscribirAsync(Eventos.Sistema.ServicioDetenido(inicio.Elapsed, atendidas), CancellationToken.None)
                          .ConfigureAwait(false);
        }
    }
}
