using System;
using System.Linq;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        private static void ProbarDispositivosReales()
        {
            Console.WriteLine("9. Cámara y micrófono REALES (ConsentStore del usuario actual, solo lectura)");
            InstantaneaDeDispositivos s = LectorDeDispositivosWindows.Leer();
            Check(s.Estado == EstadoDeLecturaDispositivos.Correcta, "se leyó el registro de uso", s.Estado.ToString());
            int cam = s.Registros.Count(r => r.Dispositivo == "webcam"), mic = s.Registros.Count(r => r.Dispositivo == "microphone");
            Console.WriteLine("      INFO: filas webcam=" + cam + " (paquetes " + s.Registros.Count(r => r.Dispositivo == "webcam" && r.Empaquetada) + "), microphone=" + mic +
                              " (paquetes " + s.Registros.Count(r => r.Dispositivo == "microphone" && r.Empaquetada) + "), ilegibles=" + s.Ilegibles +
                              ", permiso global cámara=" + s.PermisoGlobalCamara + ", micrófono=" + s.PermisoGlobalMicrofono);
            Check(s.Registros.All(r => r.Dispositivo is "webcam" or "microphone" && r.Clave.Length > 0), "toda fila es de la cámara o del micrófono y tiene nombre");
            Check(s.Registros.Where(r => !r.Empaquetada).All(r => !r.Clave.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase)), "la clave «NonPackaged» no se cuenta como un programa");
            Check(s.Registros.Count(r => !r.Empaquetada) == 0 || s.Registros.Where(r => !r.Empaquetada).All(r => r.Clave.Contains('#')), "los programas normales traen su ruta con «#»");

            ResultadoDeAnalisis a = AnalizadorDeDispositivos.Analizar(s, DateTimeOffset.UtcNow);
            Console.WriteLine("      INFO: " + a.Hallazgos.Count + " hallazgo(s), completo=" + a.Completo);
            foreach (HallazgoDeSistema h in a.Hallazgos) Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));
            foreach (string n in a.NoEvaluado) Console.WriteLine("        ! " + n);
            Check(a.Completo || s.Ilegibles > 0, "el análisis es completo salvo entradas ilegibles");
            int sinFin = s.Registros.Count(r => r.InicioFiletime is > 0 && r.FinFiletime == 0);
            int enUso = s.Registros.Where(r => AnalizadorDeDispositivos.EnUsoAhora(r, DateTimeOffset.UtcNow)).Select(AnalizadorDeDispositivos.ProgramaDe).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            Console.WriteLine("      INFO: filas sin fin (fin = 0)=" + sinFin + ", de ellas en uso de verdad (inicio en las últimas 24 h, por programa)=" + enUso);
            Check(a.Hallazgos.Count(h => h.Id == "DISP-EN-USO") == enUso, "tantos «en uso ahora» como programas con fin = 0 y inicio en las últimas 24 h (" + enUso + ")");
            int recientes = s.Registros.Count(r => AnalizadorDeDispositivos.Fecha(r.InicioFiletime) is DateTimeOffset i && DateTimeOffset.UtcNow - i <= AnalizadorDeDispositivos.VentanaReciente);
            Console.WriteLine("      INFO: filas con uso en los últimos 7 días=" + recientes + "; programas distintos por dispositivo en los resúmenes: " +
                              string.Join(" / ", a.Hallazgos.Where(h => h.Id == "DISP-RECIENTE").Select(h => h.Titulo)));
        }
    }
}
