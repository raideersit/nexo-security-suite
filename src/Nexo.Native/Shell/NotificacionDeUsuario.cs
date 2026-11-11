using System;
using System.Runtime.InteropServices;

namespace Nexo.Native.Shell
{
    /// <summary>
    /// SHQueryUserNotificationState: lo que Windows sabe sobre si la persona esta ocupada con algo a pantalla completa. Es la misma señal
    /// que usan las aplicaciones para decidir si pueden mostrar un aviso. Solo lectura, sin administrador. No lanza.
    /// </summary>
    public static class NotificacionDeUsuario
    {
        /// <summary>Los valores de QUERY_USER_NOTIFICATION_STATE.</summary>
        public enum Estado { Desconocido = 0, Ausente = 1, PantallaCompleta = 2, JuegoD3D = 3, Presentacion = 4, AceptaAvisos = 5, NoMolestar = 6, AppDeLaTienda = 7 }

        [DllImport("shell32.dll")]
        private static extern int SHQueryUserNotificationState(out int estado);

        public static Estado Leer()
        {
            try
            {
                if (SHQueryUserNotificationState(out int e) != 0) return Estado.Desconocido;
                return Traducir(e);
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return Estado.Desconocido; }
        }

        public static Estado Traducir(int valor) => valor is >= 1 and <= 7 ? (Estado)valor : Estado.Desconocido;
    }
}
