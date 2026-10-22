using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Tray
{
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

    internal static class Auxiliar
    {
        /// <summary>--aplicar &lt;tipo&gt; &lt;token&gt;: aplica un plan y muestra el resultado. Corre elevado.</summary>
        public static int Aplicar(string[] args, int i, string pipe)
        {
            if (i + 2 >= args.Length || !Enum.TryParse(args[i + 1], ignoreCase: true, out TipoDeAccion tipo)
                || !AccionesDelServicio.EsTokenValido(args[i + 2]))
            {
                MessageBox.Show("Argumentos no validos.", "Nexo", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 2;
            }

            ResultadoDeAplicar r;
            try
            {
                r = AccionesDelServicio.AplicarAsync(pipe, tipo, args[i + 2], TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException)
            {
                r = new ResultadoDeAplicar(false, false, "No se pudo hablar con el servicio.");
            }

            MessageBox.Show(
                r.Exito ? r.Mensaje : (r.NecesitaElevacion ? "El servicio sigue pidiendo aprobacion: " : "No se aplico: ") + r.Mensaje,
                "Nexo", MessageBoxButtons.OK, r.Exito ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            return r.Exito ? 0 : 1;
        }

        /// <summary>--una-vez --salida archivo: una consulta, el resultado en JSON y fuera. Sirve para comprobar el cableado sin pantalla.</summary>
        public static int UnaVez(string[] args, string pipe)
        {
            int i = Array.IndexOf(args, "--salida");
            string? salida = i >= 0 && i + 1 < args.Length ? args[i + 1] : null;

            InstantaneaDelServicio inst = ConsultorDelServicio.ConsultarAsync(pipe, TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
            var modelo = new ModeloDeBandeja();
            modelo.Actualizar(inst);

            string json = JsonSerializer.Serialize(new
            {
                conectado = inst.Conectado,
                estado = modelo.Estado.ToString(),
                texto = modelo.Texto,
                detecciones = inst.Detecciones.Count,
                error = inst.Error
            });
            if (salida is not null) File.WriteAllText(salida, json, new UTF8Encoding(false));
            return inst.Conectado ? 0 : 1;
        }
    }
}
