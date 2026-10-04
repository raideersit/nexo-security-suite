using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;

namespace Nexo.Modules.Cleanup.Inicio
{
    /// <summary>
    /// Acceso al almacen de entradas de inicio. Se abstrae porque la
    /// implementacion real toca el registro de Windows y las pruebas necesitan un
    /// almacen en memoria que pueda fallar a voluntad.
    /// </summary>
    public interface IRegistroInicio
    {
        IReadOnlyList<EntradaDeInicio> Enumerar();

        /// <summary>
        /// Escribe el indicador StartupApproved de la entrada. Nunca borra la
        /// entrada original.
        /// </summary>
        /// <exception cref="UnauthorizedAccessException">Sin permisos para escribir ahi.</exception>
        void EscribirEstado(EntradaDeInicio entrada, byte[] datos);
    }

    /// <summary>
    /// Habilita y deshabilita programas de inicio.
    ///
    /// La decision que gobierna esta clase: DESHABILITAR, NUNCA BORRAR. Borrar la
    /// entrada Run seria irreversible e invisible; cambiar el indicador es
    /// reversible y el usuario lo ve reflejado en el Administrador de tareas.
    /// Por eso no hay vista previa con token (eso es para lo que borra), pero si
    /// una lista de proteccion y un evento en el vault por cada cambio.
    /// </summary>
    public sealed class OptimizadorDeInicio
    {
        /// <summary>
        /// Entradas que no se deshabilitan: la regla del proyecto es que Nexo
        /// complementa a Windows Defender, nunca lo desactiva.
        /// </summary>
        public static readonly IReadOnlyList<string> ProtegidasPorDefecto = new[]
        {
            "SecurityHealth*",
            "WindowsDefender*",
            "Windows Defender*",
            "Nexo*"
        };

        private readonly IRegistroInicio _registro;
        private readonly IReportWriter _reportes;
        private readonly bool _esAdministrador;
        private readonly IReadOnlyList<string> _protegidas;

        public OptimizadorDeInicio(
            IRegistroInicio registro,
            IReportWriter reportes,
            bool esAdministrador,
            IEnumerable<string>? protegidas = null)
        {
            _registro = registro;
            _reportes = reportes;
            _esAdministrador = esAdministrador;
            _protegidas = (protegidas ?? ProtegidasPorDefecto).ToList();
        }

        public IReadOnlyList<EntradaDeInicio> Listar() => _registro.Enumerar();

        public bool EstaProtegida(EntradaDeInicio entrada)
            => _protegidas.Any(p => Coincide(entrada.Nombre, p));

        public async Task<ResultadoCambioInicio> CambiarEstadoAsync(
            EntradaDeInicio entrada,
            bool habilitar,
            CancellationToken ct = default)
        {
            if (entrada is null) throw new ArgumentNullException(nameof(entrada));

            // Habilitar nunca es peligroso; deshabilitar algo protegido si.
            if (!habilitar && EstaProtegida(entrada))
                return ResultadoCambioInicio.No("entrada protegida (seguridad del sistema o de Nexo)");

            if (entrada.RequiereAdmin && !_esAdministrador)
                return ResultadoCambioInicio.No("requiere permisos de administrador");

            if (entrada.Estado == EstadoDeInicio.Desconocida)
                return ResultadoCambioInicio.No("el indicador tiene un valor desconocido; no se modifica a ciegas");

            EstadoDeInicio deseado = habilitar ? EstadoDeInicio.Habilitada : EstadoDeInicio.Deshabilitada;
            if (entrada.Estado == deseado)
                return ResultadoCambioInicio.No("ya estaba " + (habilitar ? "habilitada" : "deshabilitada"));

            try
            {
                _registro.EscribirEstado(entrada, StartupApprovedCodec.Escribir(habilitar, DateTimeOffset.Now));
            }
            catch (UnauthorizedAccessException)
            {
                return ResultadoCambioInicio.No("Windows denego el acceso al registro");
            }
            catch (Exception ex) when (ex is SecurityException || ex is IOException)
            {
                return ResultadoCambioInicio.No(ex.GetType().Name);
            }

            await _reportes.EscribirAsync(
                Nexo.Reports.Model.Eventos.Limpieza.InicioModificado(entrada.Nombre, entrada.Origen.ToString(), habilitar),
                ct).ConfigureAwait(false);

            return ResultadoCambioInicio.Ok();
        }

        /// <summary>Coincidencia glob simple: '*' solo al final, suficiente para los nombres de la lista.</summary>
        private static bool Coincide(string nombre, string patron)
            => patron.EndsWith('*')
                ? nombre.StartsWith(patron[..^1], StringComparison.OrdinalIgnoreCase)
                : string.Equals(nombre, patron, StringComparison.OrdinalIgnoreCase);
    }
}
