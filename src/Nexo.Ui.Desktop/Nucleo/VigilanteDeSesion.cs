#if WINDOWS
using System;
using Microsoft.Win32;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// Avisa cuando el equipo deja de estar a la vista del usuario: sesion de Windows bloqueada, cierre de sesion, desconexion
    /// (escritorio remoto o cambio rapido de usuario) o suspension. La ventana bloquea la boveda de contraseñas en esos casos.
    /// Solo ESCUCHA eventos del sistema (<see cref="SystemEvents"/>, API administrada, sin P/Invoke propio): no lee ni cambia nada.
    /// </summary>
    public sealed class VigilanteDeSesionWindows : IDisposable
    {
        private bool _activo;

        /// <summary>Se lanza en un hilo del sistema: quien escuche debe pasar al hilo de la interfaz.</summary>
        public event Action<string>? SesionAmenazada;

        public VigilanteDeSesionWindows()
        {
            SystemEvents.SessionSwitch += AlCambiarLaSesion;
            SystemEvents.PowerModeChanged += AlCambiarLaEnergia;
            _activo = true;
        }

        /// <summary>El texto del aviso para un cambio de sesion que deja el equipo fuera de la vista del usuario; null si no es uno de ellos.</summary>
        public static string? MotivoDeSesion(SessionSwitchReason r) => r switch
        {
            SessionSwitchReason.SessionLock => "La bóveda se bloqueó porque se bloqueó la sesión de Windows.",
            SessionSwitchReason.SessionLogoff => "La bóveda se bloqueó porque se cerró la sesión de Windows.",
            SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect => "La bóveda se bloqueó porque la sesión se desconectó.",
            _ => null
        };

        /// <summary>El texto del aviso para un cambio de energia; solo la suspension bloquea.</summary>
        public static string? MotivoDeEnergia(PowerModes m) => m == PowerModes.Suspend ? "La bóveda se bloqueó porque el equipo se suspendió." : null;

        private void AlCambiarLaSesion(object? sender, SessionSwitchEventArgs e)
        {
            string? motivo = MotivoDeSesion(e.Reason);
            if (motivo is not null) SesionAmenazada?.Invoke(motivo);
        }

        private void AlCambiarLaEnergia(object? sender, PowerModeChangedEventArgs e)
        {
            string? motivo = MotivoDeEnergia(e.Mode);
            if (motivo is not null) SesionAmenazada?.Invoke(motivo);
        }

        public void Dispose()
        {
            if (!_activo) return;
            _activo = false;
            SystemEvents.SessionSwitch -= AlCambiarLaSesion;
            SystemEvents.PowerModeChanged -= AlCambiarLaEnergia;
        }
    }
}
#endif
