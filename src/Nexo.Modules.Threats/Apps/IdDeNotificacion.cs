using System.Text;

namespace Nexo.Modules.Threats.Apps
{
    /// <summary>
    /// Id ESTABLE de una notificacion a partir de una clave («app:paquete», «equipo:fila», «resumen»).
    /// No sirve string.GetHashCode(): en .NET cambia en cada proceso, y Nexo avisa desde procesos distintos (la app abierta, el trabajo periodico).
    /// Con ids distintos, Android no reemplaza el aviso anterior de la misma app y se ven dos (pasó en las pruebas del S20 FE, 2026-11-17).
    /// FNV-1a de 32 bits sobre UTF-8: el mismo valor en cualquier proceso, version de .NET y equipo.
    /// </summary>
    public static class IdDeNotificacion
    {
        public static int De(string clave)
        {
            unchecked
            {
                uint h = 2166136261;
                foreach (var b in Encoding.UTF8.GetBytes(clave))
                {
                    h ^= b;
                    h *= 16777619;
                }
                return (int)h;
            }
        }
    }
}
