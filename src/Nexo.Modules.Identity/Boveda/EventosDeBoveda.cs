using Nexo.Reports.Model;

namespace Nexo.Modules.Identity.Boveda
{
    /// <summary>
    /// Los eventos de la boveda. Las notas del vault de reportes son TEXTO PLANO que cualquiera con acceso a la carpeta lee,
    /// asi que aqui NO entra nunca un sitio, un usuario, una contrasena ni una ruta: solo hechos (creada, desbloqueada,
    /// intento fallido) y un conteo.
    /// </summary>
    public static class EventosDeBoveda
    {
        public static NexoEvent Creada() => new(ModuloOrigen.Identidad, TipoEvento.BovedaCreada, "Bóveda de contraseñas creada")
        {
            Severidad = Severidad.Info,
            Accion = Accion.Registrada
        };

        public static NexoEvent Desbloqueada(int entradas)
        {
            var e = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.BovedaDesbloqueada, "Bóveda de contraseñas desbloqueada")
            {
                Severidad = Severidad.Info,
                Accion = Accion.Registrada
            };
            e.Campos["entradas"] = entradas;
            return e;
        }

        public static NexoEvent FalloDeDesbloqueo() => new(ModuloOrigen.Identidad, TipoEvento.BovedaFalloDeDesbloqueo, "Intento fallido de abrir la bóveda")
        {
            Severidad = Severidad.Media,
            Accion = Accion.Registrada
        };
    }
}
