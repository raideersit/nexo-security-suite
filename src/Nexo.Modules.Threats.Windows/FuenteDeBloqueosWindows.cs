using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Nexo.Modules.Threats.Firewall;
using Nexo.Native.Audit;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee los eventos 5157 del registro de Seguridad de Windows. Exige administrador: sin el devuelve
    /// <see cref="EstadoDeFuente.SinPermisos"/>, que es "no pude leer", no "no hubo bloqueos".
    ///
    /// No activa la auditoria. Windows no escribe el 5157 si no esta activa la auditoria de fallos de
    /// "Filtering Platform Connection"; activarla cambia la politica del equipo y llena el registro de
    /// Seguridad, asi que es una decision del administrador:
    ///   auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
    /// </summary>
    public sealed class FuenteDeBloqueosWindows : IFuenteDeBloqueos
    {
        public bool? AuditoriaActiva()
        {
            AuditoriaActiva? a = PoliticaDeAuditoria.Consultar(PoliticaDeAuditoria.FiltradoDeConexiones);
            return a is null ? null : (a.Value & Nexo.Native.Audit.AuditoriaActiva.Fallo) != 0;
        }

        public LecturaCruda Leer(DateTimeOffset desde, int maximo)
        {
            // El instante va en UTC y con formato fijo: el XPath no entiende la cultura del equipo.
            string desdeUtc = desde.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            string consulta = "*[System[(EventID=5157) and TimeCreated[@SystemTime>='" + desdeUtc + "']]]";

            var xml = new List<string>();
            try
            {
                var q = new EventLogQuery("Security", PathType.LogName, consulta) { ReverseDirection = true };
                using var lector = new EventLogReader(q);
                EventRecord? e;
                while ((e = lector.ReadEvent()) is not null)
                {
                    using (e)
                    {
                        if (xml.Count >= maximo) return new LecturaCruda(xml, EstadoDeFuente.Ok, null, Truncada: true);
                        xml.Add(e.ToXml());
                    }
                }
                return new LecturaCruda(xml, EstadoDeFuente.Ok);
            }
            catch (UnauthorizedAccessException)
            {
                return new LecturaCruda(Array.Empty<string>(), EstadoDeFuente.SinPermisos,
                    "Leer el registro de Seguridad exige administrador.");
            }
            catch (EventLogException e)
            {
                return new LecturaCruda(Array.Empty<string>(), EstadoDeFuente.NoDisponible,
                    "No se pudo leer el registro de Seguridad: " + e.Message);
            }
        }
    }
}
