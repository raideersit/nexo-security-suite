using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    /// <summary>
    /// El portapapeles real, a traves de la ventana. Nunca lanza: si el sistema lo rechaza (otro programa lo tiene abierto, sesion remota...)
    /// devuelve «no se pudo» y el modelo lo dice; jamas finge haber copiado ni haber borrado.
    /// </summary>
    public sealed class PortapapelesDeAvalonia : IPortapapeles
    {
        private TopLevel? _ventana;

        /// <summary>La ventana la llama al crearse: el portapapeles de Avalonia cuelga de ella.</summary>
        public void Enlazar(TopLevel ventana) => _ventana = ventana;

        private IClipboard? Portapapeles => _ventana?.Clipboard;

        public async Task<bool> PonerAsync(string texto)
        {
            try
            {
                IClipboard? c = Portapapeles;
                if (c is null) return false;
                await c.SetTextAsync(texto);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return false;
            }
        }

        public async Task<string?> LeerAsync()
        {
            try
            {
                IClipboard? c = Portapapeles;
                return c is null ? null : await c.GetTextAsync();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return null;
            }
        }

        public async Task BorrarAsync()
        {
            try
            {
                IClipboard? c = Portapapeles;
                if (c is not null) await c.ClearAsync();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Si no se pudo borrar, no se afirma lo contrario: el modelo ya dijo «borrado» solo si LeerAsync coincidia, y aqui no hay mas que hacer.
            }
        }
    }
}
