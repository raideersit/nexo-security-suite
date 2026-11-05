using System;
using System.ComponentModel;
using System.Diagnostics;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Tray
{
    // Sin WinForms: Nexo.Ui.Desktop compila este archivo (en Windows) para pedir la aprobacion a traves de nexo-tray.exe.

    /// <summary>Lanza este mismo ejecutable elevado (aviso de UAC) para que aplique un plan ya aprobado.</summary>
    internal sealed class LanzadorElevado : ILanzadorElevado
    {
        private readonly string _pipe;
        private readonly string? _exe;

        /// <param name="exe">El ejecutable a elevar. Por omision, este mismo (solo las pruebas indican otro).</param>
        public LanzadorElevado(string pipe, string? exe = null)
        {
            _pipe = pipe;
            _exe = exe;
        }

        public string? UltimoMotivo { get; private set; }

        public bool Lanzar(TipoDeAccion tipo, string token)
        {
            UltimoMotivo = null;

            // El token se valida (64 hex) antes de ir a una linea de comandos: nada que inyectar.
            if (!AccionesDelServicio.EsTokenValido(token)) { UltimoMotivo = "token no valido"; return false; }

            try
            {
                string? exe = _exe ?? Environment.ProcessPath;
                if (exe is null) { UltimoMotivo = "no se pudo localizar el ejecutable"; return false; }

                // No se eleva un ejecutable que un proceso normal del usuario podria haber sustituido: el aviso de UAC
                // diria "Nexo" y ejecutaria con permisos de administrador lo que otro hubiera puesto ahi.
                if (!UbicacionSegura.EsSegura(exe, out string motivo))
                {
                    UltimoMotivo = "la bandeja esta en una ubicacion que el usuario puede modificar (" + motivo +
                                   "); instalala en una carpeta como Program Files para poder aprobar desde ella";
                    return false;
                }
                Process.Start(new ProcessStartInfo(exe, "--aplicar " + tipo + " " + token + " --pipe \"" + _pipe.Replace("\"", "") + "\"")
                {
                    UseShellExecute = true,
                    Verb = "runas"            // aviso de UAC en el escritorio seguro: lo que un proceso normal no puede pulsar
                });
                return true;
            }
            catch (Win32Exception)
            {
                UltimoMotivo = "el aviso de UAC se cancelo";     // 1223
                return false;
            }
        }
    }
}
