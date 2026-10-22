using System;

namespace Nexo.Modules.Threats
{
    /// <summary>
    /// En nombre de quien se toca el sistema de archivos. El servicio corre como SYSTEM, que puede
    /// leer y borrar casi todo; si hiciera con SYSTEM lo que le pide un usuario, ese usuario
    /// obtendria permisos que no tiene (leer lo que no puede leer, borrar lo que no puede borrar:
    /// el «delegado confundido»). La regla es: el servicio nunca hace con SYSTEM lo que quien lo
    /// pide no podria hacer por si mismo. Cada operacion se ejecuta con la identidad del llamador.
    ///
    /// Solo para operaciones SINCRONAS y breves (abrir, enumerar, borrar): la suplantacion va
    /// ligada al hilo y no sobrevive a un <c>await</c>. Los datos ya abiertos se pueden leer despues:
    /// el acceso se comprueba al ABRIR.
    /// </summary>
    public interface IAccesoAArchivos
    {
        T Ejecutar<T>(Func<T> operacion);
    }

    /// <summary>Sin suplantacion: la herramienta de consola ya corre como el usuario que la lanza.</summary>
    public sealed class AccesoDirecto : IAccesoAArchivos
    {
        public static readonly AccesoDirecto Instancia = new AccesoDirecto();
        private AccesoDirecto() { }

        public T Ejecutar<T>(Func<T> operacion) => operacion();
    }

    public static class AccesoAArchivosExtensiones
    {
        public static void Ejecutar(this IAccesoAArchivos acceso, Action operacion)
            => acceso.Ejecutar<object?>(() => { operacion(); return null; });
    }
}
