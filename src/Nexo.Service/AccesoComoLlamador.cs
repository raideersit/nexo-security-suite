using System;
using Nexo.Ipc;
using Nexo.Modules.Threats;

namespace Nexo.Service
{
    /// <summary>
    /// Hace las operaciones de archivos con la identidad de quien llamo por el pipe, no como SYSTEM.
    /// Falla CERRADO: si no hay identidad utilizable (el cliente conecto con nivel «Identification», o
    /// no se pudo identificar), la operacion se rechaza con un error claro; nunca se hace como SYSTEM
    /// «por si acaso». Es lo que impide que un usuario use al servicio para leer o borrar lo que a el no le
    /// dejan.
    /// </summary>
    public sealed class AccesoComoLlamador : IAccesoAArchivos, IDisposable
    {
        public const int SinIdentidad = -32030;

        private readonly ContextoDeLlamada _contexto;
        private readonly bool _propietario;

        public AccesoComoLlamador(ContextoDeLlamada contexto, bool propietario = false)
        {
            _contexto = contexto;
            _propietario = propietario;
        }

        /// <summary>El acceso de la peticion en curso. Lanza <see cref="ErrorDeComando"/> si no se puede actuar como el llamador.</summary>
        public static AccesoComoLlamador Requerir()
        {
            ContextoDeLlamada? c = ContextoDeLlamada.Actual;
            if (c is null || !c.PuedeActuarComoElLlamador)
                throw new ErrorDeComando(SinIdentidad,
                    "el servicio no puede actuar con tu identidad (conecta con nivel de suplantacion); " +
                    "no se hace como SYSTEM para no darte mas permisos de los que tienes");
            return new AccesoComoLlamador(c);
        }

        /// <summary>Copia que sobrevive a la peticion (para un trabajo en segundo plano). Hay que liberarla.</summary>
        public AccesoComoLlamador Duplicar() => new AccesoComoLlamador(_contexto.Duplicar(), propietario: true);

        public T Ejecutar<T>(Func<T> operacion) => _contexto.Ejecutar(operacion);

        public void Dispose()
        {
            if (_propietario) _contexto.Dispose();
        }
    }
}
