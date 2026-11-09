using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Alertas;
using Nexo.Reports.Model;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        public static async Task ProbarAlertasDelServicio()
        {
            Console.WriteLine("Alertas por el servicio: alertas.revisar");
            var ahora = new DateTimeOffset(2026, 11, 9, 15, 0, 0, TimeSpan.Zero);
            TimeSpan? pedido = null;
            var auditoria = new Dictionary<Guid, Auditoria?>
            {
                [AnalizadorDeAlertas.InicioDeSesion] = Auditoria.Exito | Auditoria.Fallo, [AnalizadorDeAlertas.CuentasDeUsuario] = Auditoria.Exito,
                [AnalizadorDeAlertas.GruposDeSeguridad] = Auditoria.Exito, [AnalizadorDeAlertas.OtrosAccesosAObjetos] = Auditoria.Exito
            };
            var eventos = new List<EventoDeWindows>
            {
                new(1102, "Microsoft-Windows-Eventlog", "Security", ahora.AddHours(-1), new Dictionary<string, string> { ["SubjectUserName"] = "intruso" }),
                new(4720, "Microsoft-Windows-Security-Auditing", "Security", ahora.AddHours(-2), new Dictionary<string, string> { ["TargetUserName"] = "soporte2", ["SubjectUserName"] = "intruso" })
            };
            LecturaDeAlertas Leer(TimeSpan p, DateTimeOffset _) { pedido = p; return new LecturaDeAlertas(eventos, auditoria, Array.Empty<string>(), 0, p); }

            var w = new EscritorFalso();
            var m = new ModuloAlertas(Leer, w, () => ahora);
            Check(m.Metodos.SequenceEqual(new[] { "alertas.revisar" }), "un solo método");

            async Task<(bool Ok, int Codigo, JsonElement? R)> Pedir(object? p)
            {
                try
                {
                    object? r = await m.ManejarAsync("alertas.revisar", p is null ? null : JsonSerializer.SerializeToElement(p), CancellationToken.None);
                    return (true, 0, JsonSerializer.SerializeToElement(r));
                }
                catch (ErrorDeComando e) { return (false, e.Codigo, null); }
            }

            var r1 = await Pedir(null);
            Check(r1.Ok && pedido == TimeSpan.FromDays(7) && r1.R!.Value.GetProperty("periodo_dias").GetInt32() == 7 && r1.R.Value.GetProperty("eventos").GetInt32() == 2,
                "sin parámetros: revisa los últimos 7 días");
            JsonElement hs = r1.R!.Value.GetProperty("hallazgos");
            Check(hs.GetArrayLength() == 2 && hs[0].GetProperty("id").GetString() == "ALR-REGISTRO-BORRADO" && hs[0].GetProperty("severidad").GetString() == "Alta"
                  && r1.R.Value.GetProperty("no_evaluado").GetArrayLength() == 0, "devuelve los hallazgos (el más grave primero) y lo no evaluado");
            NexoEvent? ev = w.Eventos.SingleOrDefault();
            Check(ev is { Modulo: ModuloOrigen.Identidad, Tipo: TipoEvento.AlertaIdentidad, Severidad: Severidad.Alta } && ev.Titulo.Contains("2 hallazgo(s)") && ev.Cuerpo!.Contains("registro de Seguridad"),
                "deja una nota en el vault con la gravedad más alta", ev?.Titulo);

            var r2 = await Pedir(new { dias = 3 });
            Check(!r2.Ok && w.Eventos.Count == 1, "otra revisión a los 0 s: rechazada (tope de frecuencia), sin leer ni escribir");
            ahora = ahora.AddSeconds(11);
            var r3 = await Pedir(new { dias = 3 });
            Check(r3.Ok && pedido == TimeSpan.FromDays(3), "a los 11 s, con 3 días: se revisa ese periodo");
            ahora = ahora.AddSeconds(11);
            foreach (object malo in new object[] { new { dias = 0 }, new { dias = 31 }, new { dias = "7" }, new { dias = 2.5 } })
                Check(!(await Pedir(malo)).Ok, "días inválidos se rechazan: " + JsonSerializer.Serialize(malo));

            eventos.Clear();
            auditoria[AnalizadorDeAlertas.GruposDeSeguridad] = null;
            ahora = ahora.AddSeconds(11);
            var r4 = await Pedir(null);
            Check(r4.Ok && r4.R!.Value.GetProperty("hallazgos").GetArrayLength() == 0 && r4.R.Value.GetProperty("no_evaluado").GetArrayLength() == 1
                  && w.Eventos.Last().Titulo.EndsWith("incompleta") && w.Eventos.Last().Severidad == Severidad.Media,
                "sin hallazgos pero sin saber una auditoría: la nota dice «incompleta» (Media), nunca «sin hallazgos»", w.Eventos.Last().Titulo);
        }
    }
}
