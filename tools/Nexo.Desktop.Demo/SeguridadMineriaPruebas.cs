using System;
using System.Linq;
using System.Threading;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static string EstadoM(string hallazgos = "", int muestras = 12, bool observando = false, string ultima = "\"2026-11-10T20:00:30-03:00\"",
                                      string noEvaluado = "", string aviso = "null")
            => "{\"activo\":true,\"intervalo_segundos\":30,\"ultima_muestra\":" + ultima + ",\"muestras\":" + muestras + ",\"observando\":" + (observando ? "true" : "false")
             + ",\"muestras_necesarias\":8,\"sin_sospechas\":false,\"completo\":true,\"severidad_maxima\":null,\"hallazgos\":[" + hallazgos + "],\"no_evaluado\":[" + noEvaluado
             + "],\"lista_ips\":1,\"lista_dominios\":0,\"aviso\":" + aviso + ",\"nota\":\"x\"}";

        private static string HallazgoM(string severidad)
            => "{\"id\":\"MINERIA-CPU\",\"severidad\":\"" + severidad + "\",\"titulo\":\"Un programa gasta mucha CPU en segundo plano\",\"detalle\":\"m.exe usó el 90 % de la CPU durante unos 4 minutos.\","
             + "\"recomendacion\":\"Ábrelo en el Administrador de tareas y comprueba si lo reconoces.\",\"sujeto\":\"m.exe\"}";

        private static void ProbarMineriaEnLaVentana()
        {
            Console.WriteLine("Pestaña Seguridad: posible criptominería (lo que dice el servicio)");

            Consulta<RevisionDeMineria> c = LectorDeMineriaDelServicio.Leer(JsonS("{\"activo\":false,\"sin_sospechas\":false,\"nota\":\"apagada\"}"));
            Check(c.Valor is { Nota: not null, Muestras: 0 } && c.Valor.Nota.Contains("Nexo:Mineria:Activo") && c.Valor.Analisis.Completo, "apagada: una nota con dónde activarla (no es un fallo)");

            c = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM()));
            Check(c.Valor is { Muestras: 12 } && c.Valor.Analisis.Completo && c.Valor.Analisis.Hallazgos.Count == 0, "estado limpio con 12 muestras: completo y sin hallazgos");

            c = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(HallazgoM("Media"))));
            Check(c.Valor!.Analisis.Hallazgos.Single() is { Id: "MINERIA-CPU", Severidad: Severidad.Media, Sujeto: "m.exe" } h && h.Recomendacion.Contains("Administrador de tareas"), "un hallazgo del servicio llega tal cual, con sujeto y recomendación");

            c = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(muestras: 3, observando: true)));
            Check(!c.Valor!.Analisis.Completo && c.Valor.Analisis.NoEvaluado.Single().Contains("3 de 8"), "observando (3 de 8): «no evaluado», no verde");

            c = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(muestras: 0, observando: true, ultima: "null")));
            Check(!c.Valor!.Analisis.Completo && c.Valor.Analisis.NoEvaluado.Single().Contains("ninguna muestra"), "sin ninguna muestra: lo dice (y no repite «observando»)");

            c = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(noEvaluado: "\"lista de servidores de minería: vacía\"", aviso: "\"la última muestra falló (IOException)\"")));
            Check(c.Valor!.Analisis.NoEvaluado.Count == 2 && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("lista")) && c.Valor.Analisis.NoEvaluado.Any(x => x.Contains("aviso del servicio")), "lo no leído y el aviso del servicio van a «no evaluado»");

            Check(LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(HallazgoM("Grave")))).Error == "respuesta del servicio no reconocida", "una gravedad desconocida invalida la respuesta entera");
            Check(LectorDeMineriaDelServicio.Leer(JsonS(EstadoM().Replace("\"muestras\":12,", ""))).Error is not null, "sin «muestras»: no se interpreta a medias");
            Check(LectorDeMineriaDelServicio.Leer(JsonS(EstadoM().Replace("\"muestras_necesarias\":8", "\"muestras_necesarias\":0"))).Error is not null, "muestras necesarias = 0: respuesta no válida");
            Check(LectorDeMineriaDelServicio.Leer(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("versión sin vigilancia"), "un servicio antiguo (método desconocido): se dice");
            Check(LectorDeMineriaDelServicio.Leer(new RespuestaCruda(false, "otra cosa", null)).Error == "otra cosa", "otro error del servicio: tal cual");

            // En la pestaña: la sección existe, y solo lee (ninguna acción).
            var f = new SeguridadConSenuelosFalsa();
            var m = new SeguridadModelo(f);
            FilaDeSeccion Fila() => m.Secciones.Single(x => x.Seccion == SeccionDeSeguridad.Mineria);
            Check(Fila().Nombre.Contains("criptominería") && Fila().Estado == "Sin revisar" && !Fila().HayAccion, "la sección «criptominería» empieza «Sin revisar», sin acciones");

            var apagada = LectorDeMineriaDelServicio.Leer(JsonS("{\"activo\":false}")).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Mineria ? Rev(s, apagada.Analisis.Hallazgos, apagada.Analisis.NoEvaluado, apagada.Nota, null) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Mineria));
            Check(Fila().Estado == "No aplica" && Fila().Resumen.Contains("Nexo:Mineria:Activo"), "apagada en la pestaña: «No aplica», con dónde activarla");

            var grave = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(HallazgoM("Critica")))).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Mineria ? Rev(s, grave.Analisis.Hallazgos, grave.Analisis.NoEvaluado, null, grave.Muestras) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Mineria));
            Check(Fila().Estado == "Hay hallazgos graves" && Fila().Resumen.Contains("12 muestras tomadas") && Fila().Hallazgos.Single().Gravedad == "Crítica" && !Fila().HayAccion,
                  "un hallazgo crítico: «Hay hallazgos graves», con las muestras, y sin botón que cambie nada", Fila().Estado + " / " + Fila().Resumen);

            var obs = LectorDeMineriaDelServicio.Leer(JsonS(EstadoM(muestras: 2, observando: true))).Valor!;
            f.Responde = s => s == SeccionDeSeguridad.Mineria ? Rev(s, obs.Analisis.Hallazgos, obs.Analisis.NoEvaluado, null, obs.Muestras) : Limpia(s);
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Mineria));
            Check(Fila().Estado == "Revisión incompleta" && Fila().HayNoEvaluado, "observando todavía: «Revisión incompleta», nunca verde");

            // Sin conexión con el servicio.
            Check(LectorDeMineriaDelServicio.SinServicio.Contains("servicio"), "sin servicio: el motivo lo dice");
        }
    }
}
