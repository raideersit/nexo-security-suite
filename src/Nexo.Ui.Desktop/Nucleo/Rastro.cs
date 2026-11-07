using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
#if WINDOWS
using System.Linq;
#endif

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>
    /// Avisa al servicio de lo que hizo la ventana (una revision de seguridad, un bloqueo de la boveda...) para que lo deje en el vault
    /// de reportes. La ventana NO escribe en el vault (es del servicio): solo envia una clave de un catalogo fijo y unos numeros.
    /// Es de mejor esfuerzo y no bloquea: si el servicio no esta, simplemente no queda rastro (la ventana no lo presenta como registrado).
    /// Nunca lleva nombres de cuentas, redes, programas, sitios, usuarios ni contraseñas.
    /// </summary>
    public interface IRastroDeVentana
    {
        void Avisar(string tipo, IReadOnlyDictionary<string, object?>? campos = null);
    }

    /// <summary>Sin servicio (o sin Windows): no deja rastro.</summary>
    public sealed class RastroNulo : IRastroDeVentana
    {
        public static readonly RastroNulo Instancia = new();
        public void Avisar(string tipo, IReadOnlyDictionary<string, object?>? campos = null) { }
    }

#if WINDOWS
    /// <summary>Envia el aviso por el pipe del servicio (<c>ventana.registrar</c>), en segundo plano y tragandose cualquier fallo.</summary>
    public sealed class RastroPorPipe : IRastroDeVentana
    {
        private readonly string _pipe;
        private readonly TimeSpan _espera;

        public RastroPorPipe(string pipe, TimeSpan? espera = null)
        {
            _pipe = pipe;
            _espera = espera ?? TimeSpan.FromSeconds(3);
        }

        public void Avisar(string tipo, IReadOnlyDictionary<string, object?>? campos = null)
        {
            var parametros = new Dictionary<string, object?>(StringComparer.Ordinal) { ["tipo"] = tipo };
            if (campos is not null) foreach (KeyValuePair<string, object?> kv in campos) parametros[kv.Key] = kv.Value;
            _ = Task.Run(async () =>
            {
                try { await LlamadaPorPipe.LlamarAsync(_pipe, _espera, "ventana.registrar", parametros, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception) { /* mejor esfuerzo: un fallo del rastro nunca afecta a lo que el usuario esta haciendo */ }
            });
        }
    }
#endif
}
