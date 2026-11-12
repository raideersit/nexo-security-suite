using System;
using System.Linq;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static string EstadoC(string hallazgos = "", bool activa = true, long recibidos = 500, long perdidos = 0, string noEvaluado = "", string aviso = "null")
            => "{\"activo\":true,\"sesion_activa\":" + (activa ? "true" : "false") + ",\"desde\":null,\"eventos_recibidos\":" + recibidos + ",\"eventos_perdidos\":" + perdidos
             + ",\"sin_sospechas\":false,\"completo\":true,\"severidad_maxima\":null,\"hallazgos\":[" + hallazgos + "],\"no_evaluado\":[" + noEvaluado + "],\"aviso\":" + aviso + ",\"nota\":\"x\"}";

        private static string HallazgoC(string severidad)
            => "{\"id\":\"COMPORTAMIENTO-SOSPECHOSO\",\"severidad\":\"" + severidad + "\",\"titulo\":\"«x.exe» junta varias señales de comportamiento sospechoso\",\"detalle\":\"«x.exe» no tiene firma digital, creó un servicio.\","
             + "\"recomendacion\":\"Si no reconoces el programa, analízalo con Nexo.\",\"sujeto\":\"x.exe\"}";

        private static void ProbarComportamientoEnLaVentana()
        {
            Console.WriteLine("Pestaña Seguridad: comportamiento sospechoso (lo que dice el servicio)");

            Consulta<RevisionDeComportamiento> c = LectorDeComportamientoDelServicio.Leer(JsonS("{\"activo\":false,\"sin_sospechas\":false,\"nota\":\"apagado\"}"));
            Check(c.Valor is { Nota: not null, Eventos: 0 } && c.Valor.Nota.Contains("Nexo:Comportamiento:Activo") && c.Valor.Analisis.Completo, "apagado: una nota con dónde activarlo (no es un fallo)");

            c = LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC()));
            Check(c.Valor is { Eventos: 500 } && c.Valor.Analisis.Completo && c.Valor.Analisis.Hallazgos.Count == 0, "sesión viva y limpia: completo y sin hallazgos");

            c = LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(HallazgoC("Alta"))));
            Check(c.Valor!.Analisis.Hallazgos.Single() is { Id: "COMPORTAMIENTO-SOSPECHOSO", Severidad: Severidad.Alta, Sujeto: "x.exe" } h && h.Recomendacion.Contains("analízalo"), "un hallazgo del servicio llega tal cual, con sujeto y recomendación");

            c = LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(activa: false, recibidos: 0, aviso: "\"hace falta ejecutar como administrador\"")));
            Check(!c.Valor!.Analisis.Completo && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("sesión de eventos")) && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("administrador")),
                  "sesión parada: «no evaluado» con el motivo, nunca verde");

            c = LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(noEvaluado: "\"se perdieron 7 eventos por exceso de actividad\"")));
            Check(!c.Valor!.Analisis.Completo && c.Valor.Analisis.NoEvaluado.Single().Contains("se perdieron 7"), "eventos perdidos: «no evaluado»");

            Check(LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(HallazgoC("Grave")))).Error == "respuesta del servicio no reconocida", "una gravedad desconocida invalida la respuesta entera");
            Check(LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(HallazgoC("99")))).Error == "respuesta del servicio no reconocida", "una gravedad numérica fuera de rango («99») también invalida la respuesta");
            Check(LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC().Replace("\"sesion_activa\":true,", ""))).Error is not null, "sin «sesion_activa»: no se interpreta a medias");
            Check(LectorDeComportamientoDelServicio.Leer(JsonS(EstadoC(perdidos: -1))).Error is not null, "eventos perdidos negativos: respuesta no válida");
            Check(LectorDeComportamientoDelServicio.Leer(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("versión sin análisis de comportamiento"), "un servicio antiguo (método desconocido): se dice");
            Check(LectorDeComportamientoDelServicio.Leer(new RespuestaCruda(false, "otra cosa", null)).Error == "otra cosa", "otro error del servicio: tal cual");
            Check(LectorDeComportamientoDelServicio.Leer(new RespuestaCruda(true, null, null)).Error is not null, "respuesta vacía: error");

            // La sección se llama y se resume como el resto.
            Check(ResumirSeguridad.Nombre(SeccionDeSeguridad.Comportamiento).StartsWith("Comportamiento sospechoso"), "la sección tiene nombre en español");
        }
    }
}
