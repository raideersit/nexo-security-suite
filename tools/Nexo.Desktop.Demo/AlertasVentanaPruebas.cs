using System;
using System.Linq;
using System.Text.Json;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static RespuestaCruda Cruda(string json) => new(true, null, JsonDocument.Parse(json).RootElement.Clone());

        public static void ProbarAlertasEnLaVentana()
        {
            Console.WriteLine("Seguridad: la sección «Accesos y cuentas» (respuesta del servicio)");
            const string bien = "{\"periodo_dias\":7,\"eventos\":12,\"hallazgos\":[{\"id\":\"ALR-REGISTRO-BORRADO\",\"severidad\":\"Alta\",\"titulo\":\"Alguien borró el registro de Seguridad de Windows\",\"detalle\":\"d\",\"recomendacion\":\"r\",\"sujeto\":\"intruso\"}," +
                                "{\"id\":\"ALR-SERVICIO-INSTALADO\",\"severidad\":\"Info\",\"titulo\":\"t\",\"detalle\":\"d\",\"recomendacion\":\"r\",\"sujeto\":null}],\"no_evaluado\":[\"Windows no lo está auditando: x.\"]}";
            Consulta<RevisionDeAlertas> c = LectorDeAlertasDelServicio.Leer(Cruda(bien));
            Check(c.Valor is { Eventos: 12 } v && v.Analisis.Hallazgos.Count == 2 && v.Analisis.Hallazgos[0].Severidad == Severidad.Alta && v.Analisis.Hallazgos[0].Sujeto == "intruso"
                  && v.Analisis.Hallazgos[1].Sujeto is null && !v.Analisis.Completo, "una respuesta buena: hallazgos, sujeto, eventos y lo no evaluado", c.Error);
            Check(LectorDeAlertasDelServicio.Leer(Cruda(bien.Replace("\"Alta\"", "\"Altisima\""))).Error == "respuesta del servicio no reconocida", "una gravedad desconocida invalida la respuesta ENTERA (no se muestra a medias)");
            Check(LectorDeAlertasDelServicio.Leer(Cruda(bien.Replace("\"Alta\"", "\"7\""))).Valor is null, "una gravedad numérica tampoco se acepta");
            Check(LectorDeAlertasDelServicio.Leer(Cruda(bien.Replace(",\"no_evaluado\":[\"Windows no lo está auditando: x.\"]", ""))).Valor is null, "sin «no_evaluado» no se acepta (no se puede saber si fue completa)");
            Check(LectorDeAlertasDelServicio.Leer(new RespuestaCruda(false, "se acaba de revisar: espera unos segundos", null)).Error == "se acaba de revisar: espera unos segundos", "un error del servicio se muestra tal cual");
            Check(new ServicioDeSeguridadNoDisponible("sin servicio").RevisarAsync(SeccionDeSeguridad.Accesos, default).Result.Error == "sin servicio", "sin servicio: lo dice");
            Check(LectorDeAlertasDelServicio.SinServicio.Contains("exige administrador"), "el motivo explica por qué esta sección necesita el servicio");
        }
    }
}
