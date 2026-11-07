using System;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// El portapapeles del sistema, detras de una interfaz para poder probar el borrado automatico sin pantalla. Una contraseña copiada
    /// no debe quedarse ahi: el modelo la borra a los 30 s, pero SOLO si el portapapeles sigue teniendo lo que puso Nexo (si el usuario
    /// copio otra cosa mientras tanto, no se toca).
    /// </summary>
    public interface IPortapapeles
    {
        /// <summary>true si se pudo poner el texto. Nunca lanza.</summary>
        Task<bool> PonerAsync(string texto);

        /// <summary>El texto actual, o null si no hay texto o no se pudo leer.</summary>
        Task<string?> LeerAsync();

        Task BorrarAsync();
    }

    /// <summary>Sin portapapeles (pruebas sin pantalla, o una plataforma que no lo ofrece): dice que no pudo y no finge.</summary>
    public sealed class PortapapelesNoDisponible : IPortapapeles
    {
        public Task<bool> PonerAsync(string texto) => Task.FromResult(false);
        public Task<string?> LeerAsync() => Task.FromResult<string?>(null);
        public Task BorrarAsync() => Task.CompletedTask;
    }

    public enum FaseDeBoveda
    {
        /// <summary>No existe el archivo: se puede crear una.</summary>
        SinBoveda,

        /// <summary>Existe y esta cerrada: hay que escribir la contraseña maestra.</summary>
        Bloqueada,
        Abierta
    }
}
