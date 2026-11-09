using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Nexo.Modules.Threats.Alertas;
using Nexo.Native.Audit;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee de los registros de Seguridad y de Sistema los eventos que usa <see cref="AnalizadorDeAlertas"/>, y que subcategorias audita
    /// Windows. Solo LECTURA: no cambia la politica de auditoria (activarla es decision del administrador). El de Seguridad exige
    /// administrador: sin el se dice que no se reviso, nunca «sin alertas». Cada consulta tiene tope; si se alcanza, se dice.
    /// </summary>
    public static class LectorDeAlertasWindows
    {
        public const int MaximoPorConsulta = 2000;

        public static LecturaDeAlertas Leer(TimeSpan periodo, DateTimeOffset ahora)
        {
            string desde = (ahora - periodo).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            string tiempo = "TimeCreated[@SystemTime>='" + desde + "']";
            var eventos = new List<EventoDeWindows>();
            var noLeido = new List<string>();
            int descartados = 0;

            void Consultar(string registro, string xpath, string queSeRevisa)
            {
                try
                {
                    var q = new EventLogQuery(registro, PathType.LogName, xpath) { ReverseDirection = true };
                    using var lector = new EventLogReader(q);
                    int n = 0;
                    EventRecord? r;
                    while ((r = lector.ReadEvent()) is not null)
                    {
                        using (r)
                        {
                            if (++n > MaximoPorConsulta)
                            {
                                noLeido.Add("Hay más de " + MaximoPorConsulta + " eventos de " + queSeRevisa + ": solo se revisaron los más recientes.");
                                return;
                            }
                            if (ParserDeEventoDeWindows.TryParse(r.ToXml(), out EventoDeWindows? e, out _) && e is not null) eventos.Add(e);
                            else descartados++;
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    noLeido.Add("No se pudo leer el registro " + (registro == "Security" ? "de Seguridad" : "de Sistema") + " (hace falta ser administrador): no se revisaron " + queSeRevisa + ".");
                }
                catch (EventLogException ex)
                {
                    noLeido.Add("No se pudo leer el registro " + (registro == "Security" ? "de Seguridad" : "de Sistema") + " (" + ex.GetType().Name + "): no se revisaron " + queSeRevisa + ".");
                }
            }

            Consultar("Security", "*[System[(EventID=1102 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4740 or EventID=4698) and " + tiempo + "]]",
                      "las cuentas, los grupos, el borrado del registro ni las tareas programadas");
            Consultar("Security", "*[System[EventID=4624 and " + tiempo + "] and EventData[Data[@Name='LogonType']='10']]", "los accesos por Escritorio remoto");
            Consultar("Security", "*[System[EventID=4625 and " + tiempo + "]]", "los intentos fallidos de contraseña");
            Consultar("System", "*[System[(EventID=104 or EventID=7045) and " + tiempo + "]]", "los servicios instalados ni el borrado del registro de Sistema");

            var auditoria = new Dictionary<Guid, Auditoria?>();
            foreach (Guid g in new[] { AnalizadorDeAlertas.InicioDeSesion, AnalizadorDeAlertas.CuentasDeUsuario, AnalizadorDeAlertas.GruposDeSeguridad, AnalizadorDeAlertas.OtrosAccesosAObjetos })
            {
                AuditoriaActiva? a = PoliticaDeAuditoria.Consultar(g);
                auditoria[g] = a is null ? null : (Auditoria)(int)a.Value;
            }
            return new LecturaDeAlertas(eventos, auditoria, noLeido, descartados, periodo);
        }
    }
}
