using Nexo.Modules.Cleanup.Perfiles;
using Nexo.Native.Power;
using Nexo.Native.Shell;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Lee de Windows las señales de actividad (energia y pantalla completa) para <see cref="ReglasDePerfil"/>. Solo lectura, sin
    /// administrador. El Wi-Fi abierto lo aporta quien llama (viene de la revision de Wi-Fi), no se lee aqui.
    /// </summary>
    public static class LectorDeActividadWindows
    {
        public static SenalesDeActividad Leer(bool? wifiAbierto = null)
        {
            LecturaDeEnergia e = EstadoDeEnergia.Leer();
            FuenteDeEnergia fuente = !e.Correcta ? FuenteDeEnergia.Desconocida : e.Corriente switch
            {
                LineaDeCorriente.Conectada => FuenteDeEnergia.Corriente,
                LineaDeCorriente.Desconectada => FuenteDeEnergia.Bateria,
                _ => FuenteDeEnergia.Desconocida
            };
            return new SenalesDeActividad(fuente, e.BateriaPorCiento, e.AhorroActivo, Pantalla(NotificacionDeUsuario.Leer()), wifiAbierto);
        }

        public static EstadoDePantalla Pantalla(NotificacionDeUsuario.Estado s) => s switch
        {
            NotificacionDeUsuario.Estado.Ausente => EstadoDePantalla.Ausente,
            NotificacionDeUsuario.Estado.PantallaCompleta or NotificacionDeUsuario.Estado.AppDeLaTienda => EstadoDePantalla.PantallaCompleta,
            NotificacionDeUsuario.Estado.JuegoD3D => EstadoDePantalla.JuegoD3D,
            NotificacionDeUsuario.Estado.Presentacion => EstadoDePantalla.Presentacion,
            NotificacionDeUsuario.Estado.AceptaAvisos => EstadoDePantalla.Libre,
            NotificacionDeUsuario.Estado.NoMolestar => EstadoDePantalla.NoMolestar,
            _ => EstadoDePantalla.Desconocido
        };
    }
}
