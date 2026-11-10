using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Ransomware;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee, SOLO LECTURA, la configuracion del acceso controlado a carpetas de Defender (WMI <c>root\Microsoft\Windows\Defender</c>, clases
    /// <c>MSFT_MpPreference</c> y <c>MSFT_MpComputerStatus</c>, las mismas que usan <c>Get-MpPreference</c> y <c>Get-MpComputerStatus</c>) y los
    /// eventos 1123/1124/1127/1128/5007 del registro de Defender. Funciona sin administrador; lo unico que Windows no da sin el es la lista de
    /// programas con permiso (se marca como no leida). No cambia nada: activar la proteccion se hace en Seguridad de Windows.
    /// </summary>
    public static class LectorDeCarpetasProtegidasWindows
    {
        public const int MaximoPorConsulta = 2000;
        internal const string EspacioDefender = @"root\Microsoft\Windows\Defender";

        public static LecturaDeCarpetasProtegidas Leer(TimeSpan periodo, DateTimeOffset ahora)
        {
            var noLeido = new List<string>();
            (int? modo, IReadOnlyList<string>? extra, IReadOnlyList<string>? permitidas, bool? tiempoReal, string? motor) = LeerConfiguracion();

            string desde = (ahora - periodo).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            var eventos = new List<EventoDeWindows>();
            int descartados = 0;
            void Consultar(string ids, string queSeRevisa)
            {
                try
                {
                    var q = new EventLogQuery(AnalizadorDeCarpetasProtegidas.RegistroDefender, PathType.LogName,
                        "*[System[(" + ids + ") and TimeCreated[@SystemTime>='" + desde + "']]]") { ReverseDirection = true };
                    using var lector = new EventLogReader(q);
                    int n = 0;
                    EventRecord? r;
                    while ((r = lector.ReadEvent()) is not null)
                    {
                        using (r)
                        {
                            if (++n > MaximoPorConsulta)
                            {
                                noLeido.Add("Hay más de " + MaximoPorConsulta + " eventos de " + queSeRevisa + ": solo se revisaron los más recientes.");
                                return;
                            }
                            if (ParserDeEventoDeWindows.TryParse(r.ToXml(), out EventoDeWindows? e, out _) && e is not null) eventos.Add(e);
                            else descartados++;
                        }
                    }
                }
                catch (Exception e) when (e is UnauthorizedAccessException or EventLogException)
                {
                    noLeido.Add("No se pudo leer el registro de Defender (" + e.GetType().Name + "): no se revisaron " + queSeRevisa + ".");
                }
            }

            Consultar(string.Join(" or ", new[] { 1123, 1124, 1127, 1128 }.Select(i => "EventID=" + i)), "bloqueos de las carpetas protegidas");
            // El 5007 es de CUALQUIER ajuste de Defender (cientos al mes); se filtra luego por la ruta del acceso controlado a carpetas.
            Consultar("EventID=5007", "cambios de configuración de Defender");

            return new LecturaDeCarpetasProtegidas(modo, extra, permitidas, tiempoReal, motor, eventos, noLeido, descartados, periodo);
        }

        /// <summary>Solo lo necesario para decidir un cambio (sin leer eventos).</summary>
        public static EstadoDeDefenderCfa LeerEstado()
        {
            (int? modo, _, _, bool? tiempoReal, string? motor) = LeerConfiguracion();
            return new EstadoDeDefenderCfa(modo, tiempoReal, motor);
        }

        private static (int? Modo, IReadOnlyList<string>? Extra, IReadOnlyList<string>? Permitidas, bool? TiempoReal, string? Motor) LeerConfiguracion()
        {
            int? modo = null;
            IReadOnlyList<string>? extra = null, permitidas = null;
            bool? tiempoReal = null;
            string? motor = null;

            try
            {
                using var buscador = new ManagementObjectSearcher(EspacioDefender,
                    "SELECT EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders, ControlledFolderAccessAllowedApplications FROM MSFT_MpPreference");
                foreach (ManagementBaseObject o in buscador.Get())
                {
                    using (o)
                    {
                        modo = o["EnableControlledFolderAccess"] switch { byte b => b, int i => i, uint u => (int)u, _ => null };
                        extra = AnalizadorDeCarpetasProtegidas.ListaLegible(o["ControlledFolderAccessProtectedFolders"] as string[] ?? (o["ControlledFolderAccessProtectedFolders"] is null ? Array.Empty<string>() : null));
                        permitidas = AnalizadorDeCarpetasProtegidas.ListaLegible(o["ControlledFolderAccessAllowedApplications"] as string[] ?? (o["ControlledFolderAccessAllowedApplications"] is null ? Array.Empty<string>() : null));
                    }
                    break;
                }
            }
            catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
            {
                // El modo queda en null: el analizador lo declara «no se pudo leer».
            }

            try
            {
                using var buscador = new ManagementObjectSearcher(EspacioDefender, "SELECT AMRunningMode, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus");
                foreach (ManagementBaseObject o in buscador.Get())
                {
                    using (o)
                    {
                        motor = o["AMRunningMode"] as string;
                        tiempoReal = o["RealTimeProtectionEnabled"] as bool?;
                    }
                    break;
                }
            }
            catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
            {
            }

            return (modo, extra, permitidas, tiempoReal, motor);
        }
    }

    public sealed class LectorDeEstadoDeCfaWindows : ILectorDeEstadoDeCfa
    {
        public EstadoDeDefenderCfa Leer() => LectorDeCarpetasProtegidasWindows.LeerEstado();
    }

    /// <summary>
    /// Cambia <c>EnableControlledFolderAccess</c> con el metodo estatico <c>MSFT_MpPreference.Set</c> (el mismo que usa <c>Set-MpPreference</c>).
    /// Exige administrador: corre en el servicio como SYSTEM, solo tras plan + token + aprobacion. Solo recibe un valor del enum: no hay forma
    /// de pasarle otra cosa. Que Windows acepte la llamada no prueba nada: <see cref="PlanificadorDeCarpetasProtegidas.Aplicar"/> vuelve a leer.
    /// </summary>
    public sealed class EjecutorDeCfaWindows : IEjecutorDeCfa
    {
        public string? Fijar(ModoDeCarpetasProtegidas modo)
        {
            if (!Enum.IsDefined(typeof(ModoDeCarpetasProtegidas), modo)) return "valor no válido";
            try
            {
                using var clase = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
                using ManagementBaseObject entrada = clase.GetMethodParameters("Set");
                entrada["EnableControlledFolderAccess"] = (byte)modo;
                using ManagementBaseObject? salida = clase.InvokeMethod("Set", entrada, null);
                object? rv = salida?["ReturnValue"];
                uint codigo = rv is null ? 0u : Convert.ToUInt32(rv, CultureInfo.InvariantCulture);
                return codigo == 0 ? null : "código " + codigo;
            }
            catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
            {
                return e is UnauthorizedAccessException ? "hace falta ser administrador" : e.GetType().Name + (e is ManagementException me ? " " + me.ErrorCode : "");
            }
        }
    }
}
