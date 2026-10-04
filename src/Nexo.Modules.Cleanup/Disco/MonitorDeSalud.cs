using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>
    /// Lee los discos, evalua cada uno y publica un evento por disco.
    ///
    /// Solo lee. Nada de este modulo escribe en un disco, y por eso no necesita
    /// vista previa ni token.
    /// </summary>
    public sealed class MonitorDeSalud
    {
        private readonly IFuenteSmart _fuente;
        private readonly IReportWriter _reportes;

        public MonitorDeSalud(IFuenteSmart fuente, IReportWriter reportes)
        {
            _fuente = fuente;
            _reportes = reportes;
        }

        /// <param name="anteriores">
        /// Ultima lectura conocida de cada disco, por modelo+serie, para detectar
        /// crecimiento. Guardarla entre ejecuciones es responsabilidad de quien llama.
        /// </param>
        public async Task<IReadOnlyList<(LecturaDeDisco Lectura, EvaluacionDeSalud Evaluacion)>> EvaluarAsync(
            IReadOnlyDictionary<string, LecturaDeDisco>? anteriores = null,
            CancellationToken ct = default)
        {
            var resultado = new List<(LecturaDeDisco, EvaluacionDeSalud)>();

            foreach (LecturaDeDisco lectura in _fuente.Leer())
            {
                ct.ThrowIfCancellationRequested();

                LecturaDeDisco? previa = null;
                anteriores?.TryGetValue(Clave(lectura), out previa);

                EvaluacionDeSalud evaluacion = EvaluadorDeSalud.Evaluar(lectura, previa);

                NexoEvent ev = Eventos.Limpieza.SaludDisco(
                    lectura.Modelo,
                    lectura.SerieRedactada,
                    lectura.PrediccionDeFallo == true,
                    lectura.TemperaturaC,
                    lectura.DesgastePorcentaje,
                    lectura.HorasEncendido,
                    evaluacion.Alertas,
                    evaluacion.Severidad,
                    sinDatos: !lectura.TieneDatos);

                if (lectura.Limitaciones.Count > 0)
                    ev.Con("limitaciones", new List<string>(lectura.Limitaciones).ToArray());

                await _reportes.EscribirAsync(ev, ct).ConfigureAwait(false);
                resultado.Add((lectura, evaluacion));
            }

            return resultado;
        }

        public static string Clave(LecturaDeDisco l) => l.Modelo + "|" + l.SerieRedactada;
    }
}
