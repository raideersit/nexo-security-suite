using System;
using System.Linq;
using System.Security.Principal;
using Nexo.Modules.Threats.Alertas;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private static void ProbarAlertasReales()
        {
            Console.WriteLine("11. Registros REALES de Windows para las alertas (30 días)");
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            LecturaDeAlertas l = LectorDeAlertasWindows.Leer(TimeSpan.FromDays(30), DateTimeOffset.UtcNow);
            ResultadoDeAnalisis r = AnalizadorDeAlertas.Analizar(l);
            Console.WriteLine("           administrador: " + admin + ", eventos leídos: " + l.Eventos.Count + " (" + string.Join(", ", l.Eventos.GroupBy(e => e.Id).OrderBy(g => g.Key).Select(g => g.Key + "×" + g.Count())) + "), descartados: " + l.Descartados);
            foreach (string n in l.NoLeido) Console.WriteLine("           no leído: " + n);
            foreach (var h in r.Hallazgos) Console.WriteLine("           " + h.Severidad + " · " + h.Titulo);
            Check(l.Descartados == 0, "ningún evento real se descartó (el parser entiende el formato real)", l.Descartados.ToString());
            if (!admin)
            {
                Check(l.NoLeido.Count(n => n.Contains("de Seguridad") && n.Contains("administrador")) == 3 && !r.Completo,
                    "sin administrador: las 3 consultas del registro de Seguridad se declaran no leídas (y la revisión queda incompleta, NUNCA «sin alertas»)");
                Check(l.Auditoria.Values.All(a => a is null) && r.NoEvaluado.Count(n => n.StartsWith("No se pudo saber")) == 5, "sin administrador no se puede consultar la auditoría: se dice");
            }
            Check(!l.NoLeido.Any(n => n.Contains("de Sistema")), "el registro de Sistema se lee sin administrador");
            Check(l.Eventos.Where(e => e.Id == 7045).All(e => e.Proveedor == "Service Control Manager" && e.Dato("ServiceName").Length > 0 && e.Dato("ImagePath").Length > 0),
                "cada 7045 real trae proveedor, nombre del servicio y programa");
        }
    }
}
