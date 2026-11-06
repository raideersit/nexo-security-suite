using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Cleanup.Disco;

namespace Nexo.Service
{
    /// <summary>
    /// La salud de los discos (S.M.A.R.T.) por el pipe. Solo lectura de los discos:
    /// - «disco.estado» devuelve lo ultimo que se leyo, sin volver a leer (WMI tarda y cada lectura deja notas en el vault);
    /// - «disco.leer» pide una lectura nueva en segundo plano, como mucho cada <see cref="VigiaDeSalud.MinimoEntreLecturas"/>.
    /// El servicio lee al arrancar y cada intervalo (Nexo:Disco:IntervaloHoras). Como SYSTEM puede leer los atributos ATA,
    /// que sin administrador no se ven.
    /// </summary>
    public sealed class ModuloSaludDisco : IModuloDelServicio, IAsyncDisposable
    {
        private readonly VigiaDeSalud _vigia;

        public ModuloSaludDisco(VigiaDeSalud vigia) => _vigia = vigia;

        public IReadOnlyList<string> Metodos { get; } = new[] { "disco.estado", "disco.leer" };

        public void Iniciar() => _vigia.Iniciar();

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
        {
            switch (metodo)
            {
                case "disco.estado":
                    return Task.FromResult<object?>(VigiaDeSalud.ParaJson(_vigia.Estado()));

                case "disco.leer":
                {
                    bool iniciada = _vigia.PedirLectura(out string motivo);
                    return Task.FromResult<object?>(new { iniciada, motivo });
                }

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        public ValueTask DisposeAsync()
        {
            _vigia.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Lo que contesta el servicio con la salud del disco apagada en appsettings.json: lo dice, no calla.</summary>
    public sealed class ModuloSaludDiscoApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "disco.estado", "disco.leer" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo switch
            {
                "disco.estado" => Task.FromResult<object?>(new
                {
                    estado = "apagado",
                    leyendo = false,
                    discos = Array.Empty<object>(),
                    error = "La salud del disco está apagada en appsettings.json (Nexo:Disco:Activo)."
                }),
                "disco.leer" => Task.FromResult<object?>(new { iniciada = false, motivo = "la salud del disco está apagada en appsettings.json" }),
                _ => throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido")
            };
    }
}
