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
        private readonly HistorialDeSalud? _historial;

        /// <param name="historial">
        /// Si se pasa, el monitor carga de ahi las lecturas anteriores y guarda las
        /// nuevas al terminar. Sin el, el crecimiento solo se detecta si quien llama
        /// pasa <c>anteriores</c>.
        /// </param>
        public MonitorDeSalud(IFuenteSmart fuente, IReportWriter reportes, HistorialDeSalud? historial = null)
        {
            _fuente = fuente;
            _reportes = reportes;
            _historial = historial;
        }

        /// <summary>
        /// Problema con el historial en la ultima evaluacion (no se pudo leer o
        /// guardar), o null. La de lectura ademas va en el evento de cada disco.
        /// </summary>
        public string? AdvertenciaDeHistorial { get; private set; }

        /// <param name="anteriores">
        /// Ultima lectura conocida de cada disco, por modelo+serie, para detectar
        /// crecimiento. Si es null y hay historial, se cargan del historial.
        /// </param>
        public async Task<IReadOnlyList<(LecturaDeDisco Lectura, EvaluacionDeSalud Evaluacion)>> EvaluarAsync(
            IReadOnlyDictionary<string, LecturaDeDisco>? anteriores = null,
            CancellationToken ct = default)
        {
            var resultado = new List<(LecturaDeDisco, EvaluacionDeSalud)>();

            AdvertenciaDeHistorial = null;
            if (anteriores is null && _historial is not null)
            {
                anteriores = _historial.Cargar();
                AdvertenciaDeHistorial = _historial.Advertencia;
            }
            string? avisoDeCarga = AdvertenciaDeHistorial;

            IReadOnlyList<LecturaDeDisco> lecturas = _fuente.Leer();
            foreach (LecturaDeDisco lectura in lecturas)
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

                var limitaciones = new List<string>(lectura.Limitaciones);
                if (avisoDeCarga is not null) limitaciones.Add(avisoDeCarga);
                if (limitaciones.Count > 0)
                    ev.Con("limitaciones", limitaciones.ToArray());

                await _reportes.EscribirAsync(ev, ct).ConfigureAwait(false);
                resultado.Add((lectura, evaluacion));
            }

            if (_historial is not null)
            {
                _historial.Guardar(lecturas);
                AdvertenciaDeHistorial ??= _historial.Advertencia;
            }

            return resultado;
        }

        public static string Clave(LecturaDeDisco l) => l.Modelo + "|" + l.SerieRedactada;
    }
}
