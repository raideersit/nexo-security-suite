using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Nexo.Modules.Cleanup.Inicio;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Entradas de inicio reales: registro (Run) y carpetas de inicio, con su
    /// estado en <c>Explorer\StartupApproved</c>.
    ///
    /// Escribir en HKLM o en la carpeta comun requiere administrador; sin el,
    /// Windows lanza UnauthorizedAccessException y el optimizador lo traduce a un
    /// rechazo limpio en vez de fallar.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class RegistroInicioWindows : IRegistroInicio
    {
        public const string BaseReal = @"Software\Microsoft\Windows\CurrentVersion";

        private readonly string _base;
        private readonly string _carpetaUsuario;
        private readonly string _carpetaComun;

        /// <param name="subclaveBase">
        /// Subclave que contiene Run y Explorer\StartupApproved. El valor real es
        /// <see cref="BaseReal"/>; las pruebas pasan una subclave propia de HKCU para
        /// ejercitar el codigo de verdad sin tocar la configuracion de inicio del
        /// equipo.
        /// </param>
        public RegistroInicioWindows(
            string subclaveBase = BaseReal,
            string? carpetaUsuario = null,
            string? carpetaComun = null)
        {
            _base = subclaveBase;
            _carpetaUsuario = carpetaUsuario ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\Startup");
            _carpetaComun = carpetaComun ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\StartUp");
        }

        public IReadOnlyList<EntradaDeInicio> Enumerar()
        {
            var lista = new List<EntradaDeInicio>();

            AgregarRun(lista, Registry.CurrentUser, OrigenDeInicio.RunUsuario);
            AgregarRun(lista, Registry.LocalMachine, OrigenDeInicio.RunMaquina);
            AgregarRun(lista, Registry.LocalMachine, OrigenDeInicio.RunMaquina32);
            AgregarCarpeta(lista, _carpetaUsuario, OrigenDeInicio.CarpetaUsuario);
            AgregarCarpeta(lista, _carpetaComun, OrigenDeInicio.CarpetaComun);

            return lista;
        }

        public void EscribirEstado(EntradaDeInicio entrada, byte[] datos)
        {
            RegistryKey hive = HiveDe(entrada.Origen);

            // CreateSubKey con escritura: si la clave StartupApproved aun no existe
            // (equipo recien instalado) hay que crearla. En HKLM sin administrador
            // esto lanza UnauthorizedAccessException, que es lo esperado.
            using RegistryKey clave = hive.CreateSubKey(RutaAprobada(entrada.Origen), writable: true)
                ?? throw new UnauthorizedAccessException("No se pudo abrir la clave StartupApproved.");

            clave.SetValue(entrada.Nombre, datos, RegistryValueKind.Binary);
        }

        // ------------------------------------------------------------------
        private void AgregarRun(List<EntradaDeInicio> lista, RegistryKey hive, OrigenDeInicio origen)
        {
            using RegistryKey? run = hive.OpenSubKey(RutaRun(origen), writable: false);
            if (run is null) return;

            using RegistryKey? aprobadas = hive.OpenSubKey(RutaAprobada(origen), writable: false);

            foreach (string nombre in run.GetValueNames())
            {
                if (nombre.Length == 0) continue;   // valor "(predeterminado)"
                string? comando = run.GetValue(nombre) as string;
                lista.Add(new EntradaDeInicio(nombre, comando, origen, EstadoDe(aprobadas, nombre)));
            }
        }

        private void AgregarCarpeta(List<EntradaDeInicio> lista, string carpeta, OrigenDeInicio origen)
        {
            if (!Directory.Exists(carpeta)) return;

            using RegistryKey? aprobadas = HiveDe(origen).OpenSubKey(RutaAprobada(origen), writable: false);

            foreach (string archivo in Directory.EnumerateFiles(carpeta))
            {
                string nombre = Path.GetFileName(archivo);
                if (string.Equals(nombre, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                lista.Add(new EntradaDeInicio(nombre, archivo, origen, EstadoDe(aprobadas, nombre)));
            }
        }

        private static EstadoDeInicio EstadoDe(RegistryKey? aprobadas, string nombre)
            => StartupApprovedCodec.Leer(aprobadas?.GetValue(nombre) as byte[]);

        private static RegistryKey HiveDe(OrigenDeInicio origen)
            => origen == OrigenDeInicio.RunUsuario || origen == OrigenDeInicio.CarpetaUsuario
                ? Registry.CurrentUser
                : Registry.LocalMachine;

        private string RutaRun(OrigenDeInicio origen) => origen switch
        {
            OrigenDeInicio.RunMaquina32 => _base.Replace(@"Software\", @"Software\Wow6432Node\", StringComparison.OrdinalIgnoreCase)
                                           + @"\Run",
            _ => _base + @"\Run"
        };

        private string RutaAprobada(OrigenDeInicio origen) => origen switch
        {
            OrigenDeInicio.RunUsuario or OrigenDeInicio.RunMaquina => _base + @"\Explorer\StartupApproved\Run",
            OrigenDeInicio.RunMaquina32 => _base + @"\Explorer\StartupApproved\Run32",
            _ => _base + @"\Explorer\StartupApproved\StartupFolder"
        };
    }
}
