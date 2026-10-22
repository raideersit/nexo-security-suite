using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;

namespace Nexo.Service
{
    /// <summary>
    /// Metodos que el servicio expone por el pipe. Hoy son solo de LECTURA (ping, estado):
    /// ninguna accion que borre archivos, cambie reglas del firewall o toque el sistema se
    /// expone hasta que lleve su vista previa y su token de confirmacion, validados AQUI.
    /// El servicio corre con privilegios y la ACL del pipe solo limita quien llama; no
    /// convierte en fiable a quien llama (Salida 0, §2, regla de oro).
    /// </summary>
    public sealed class ManejadorDelServicio : IManejadorDeComandos
    {
        private readonly string _version;
        private readonly DateTimeOffset _inicio;
        private readonly Func<DateTimeOffset> _reloj;

        public ManejadorDelServicio(string version, Func<DateTimeOffset>? reloj = null)
        {
            _version = version;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _inicio = _reloj();
        }

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
        {
            switch (metodo)
            {
                case "ping":
                    return Task.FromResult<object?>(new { pong = true, version = _version });

                case "estado":
                    return Task.FromResult<object?>(new
                    {
                        version = _version,
                        activo_segundos = (long)(_reloj() - _inicio).TotalSeconds,
                        // Los modulos se registran aqui cuando existan como INexoModule.
                        modulos = Array.Empty<string>(),
                        metodos = new[] { "ping", "estado" }
                    });

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }
    }
}
