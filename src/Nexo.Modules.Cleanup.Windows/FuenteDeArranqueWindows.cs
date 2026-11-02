using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Nexo.Modules.Cleanup.Inicio;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Lee los eventos 100-103 de <c>Microsoft-Windows-Diagnostics-Performance/Operational</c>. Sin permisos
    /// devuelve <see cref="EstadoDeLecturaDeArranque.SinPermisos"/>, que es "no pude leer", no "arranque sin
    /// problemas". Solo lee. Windows solo escribe estos eventos si el Servicio de directivas de diagnostico
    /// (DPS) esta en marcha.
    /// </summary>
    public sealed class FuenteDeArranqueWindows : IFuenteDeArranque
    {
        public const string Registro = "Microsoft-Windows-Diagnostics-Performance/Operational";

        public LecturaDeArranque Leer(DateTimeOffset desde, int maximo)
        {
            // El instante va en UTC y con formato fijo: el XPath no entiende la cultura del equipo.
            string desdeUtc = desde.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            string consulta = "*[System[(EventID>=100 and EventID<=103) and TimeCreated[@SystemTime>='" + desdeUtc + "']]]";

            var xml = new List<string>();
            try
            {
                var q = new EventLogQuery(Registro, PathType.LogName, consulta) { ReverseDirection = true };
                using var lector = new EventLogReader(q);
                EventRecord? e;
                while ((e = lector.ReadEvent()) is not null)
                {
                    using (e)
                    {
                        if (xml.Count >= maximo) return new LecturaDeArranque(xml, EstadoDeLecturaDeArranque.Ok, null, Truncada: true);
                        xml.Add(e.ToXml());
                    }
                }
                return new LecturaDeArranque(xml, EstadoDeLecturaDeArranque.Ok);
            }
            catch (UnauthorizedAccessException)
            {
                return new LecturaDeArranque(Array.Empty<string>(), EstadoDeLecturaDeArranque.SinPermisos,
                    "Leer el registro de diagnostico de rendimiento exige administrador.");
            }
            catch (EventLogException e)
            {
                return new LecturaDeArranque(Array.Empty<string>(), EstadoDeLecturaDeArranque.NoDisponible,
                    "No se pudo leer " + Registro + ": " + e.Message);
            }
        }
    }
}
