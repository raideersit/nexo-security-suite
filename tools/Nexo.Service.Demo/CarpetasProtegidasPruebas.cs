using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports.Model;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private sealed class LectorCfaFalso : ILectorDeEstadoDeCfa
        {
            public EstadoDeDefenderCfa Valor = new(0, true, "Normal");
            public EstadoDeDefenderCfa Leer() => Valor;
        }

        private sealed class EjecutorCfaFalso : IEjecutorDeCfa
        {
            public readonly List<ModoDeCarpetasProtegidas> Llamadas = new();
            public Action<ModoDeCarpetasProtegidas>? AlFijar;
            public string? Fijar(ModoDeCarpetasProtegidas modo) { Llamadas.Add(modo); AlFijar?.Invoke(modo); return null; }
        }

        private static async Task<(bool Ok, int Codigo, JsonElement? R)> PedirCfa(ModuloCarpetasProtegidas m, string metodo, object? parametros)
        {
            try
            {
                JsonElement? p = parametros is null ? null : JsonSerializer.SerializeToElement(parametros);
                object? r = await m.ManejarAsync(metodo, p, CancellationToken.None).ConfigureAwait(false);
                return (true, 0, JsonSerializer.SerializeToElement(r));
            }
            catch (ErrorDeComando e) { return (false, e.Codigo, null); }
        }

        public static async Task ProbarCarpetasProtegidasDelServicio()
        {
            Console.WriteLine("Carpetas protegidas por el servicio: cfa.previsualizar, cfa.aplicar");
            var l = new LectorCfaFalso();
            var ej = new EjecutorCfaFalso();
            ej.AlFijar = m => l.Valor = l.Valor with { Modo = (int)m };
            var w = new EscritorFalso();
            var m = new ModuloCarpetasProtegidas(l, ej, w, PoliticaDeAprobacion.Ninguna);
            Check(m.Metodos.SequenceEqual(new[] { "cfa.previsualizar", "cfa.aplicar" }), "dos métodos (no hay uno para apagar)");

            var pre = await PedirCfa(m, "cfa.previsualizar", new { modo = "activar" });
            string? token = pre.R?.GetProperty("token").GetString();
            Check(pre.Ok && pre.R!.Value.GetProperty("hay_cambios").GetBoolean() && token?.Length == 64 && ej.Llamadas.Count == 0 && pre.R.Value.GetProperty("avisos").GetArrayLength() >= 2,
                "previsualizar: token, avisos y NADA cambiado");

            foreach (object malo in new object[] { new { modo = "apagar" }, new { modo = "desactivar" }, new { modo = 0 }, new { otro = "activar" }, new { modo = new string('a', 40) } })
            {
                var r = await PedirCfa(m, "cfa.previsualizar", malo);
                Check(!r.Ok && r.Codigo == (int)CodigoDeError.ParametrosInvalidos, "parámetros no válidos se rechazan: " + JsonSerializer.Serialize(malo));
            }
            Check(!(await PedirCfa(m, "cfa.previsualizar", null)).Ok, "sin parámetros: rechazado");

            var mElevada = new ModuloCarpetasProtegidas(l, ej, w, PoliticaDeAprobacion.Elevada);
            string tokE = (await PedirCfa(mElevada, "cfa.previsualizar", new { modo = "activar" })).R!.Value.GetProperty("token").GetString()!;
            var sinUac = await PedirCfa(mElevada, "cfa.aplicar", new { token = tokE });
            Check(!sinUac.Ok && sinUac.Codigo == PoliticaDeAprobacion.AprobacionRequerida && ej.Llamadas.Count == 0, "con la política «elevada», aplicar sin UAC se rechaza y Defender no se toca");
            var falsoE = await PedirCfa(mElevada, "cfa.aplicar", new { token = new string('d', 64) });
            Check(!falsoE.Ok && falsoE.Codigo == PoliticaDeAprobacion.AprobacionRequerida,
                "la aprobación se exige ANTES de mirar el token: uno inventado da «aprobación», no «token inválido» (el token no se gasta sin UAC)");

            var ap = await PedirCfa(m, "cfa.aplicar", new { token });
            Check(ap.Ok && ap.R!.Value.GetProperty("exito").GetBoolean() && ap.R.Value.GetProperty("modo_final").GetInt32() == 1 && ej.Llamadas.SequenceEqual(new[] { ModoDeCarpetasProtegidas.Activado }),
                "aplicar con el token: una orden, y el modo final comprobado");
            var otraVez = await PedirCfa(m, "cfa.aplicar", new { token });
            Check(!otraVez.Ok && otraVez.Codigo == ModuloCarpetasProtegidas.TokenInvalido && ej.Llamadas.Count == 1, "el token es de un solo uso");
            Check(!(await PedirCfa(m, "cfa.aplicar", new { token = new string('0', 64) })).Ok && ej.Llamadas.Count == 1, "un token inventado no aplica nada");
            NexoEvent? ev = w.Eventos.LastOrDefault(e => e.Tipo == TipoEvento.ProteccionRansomwareCambiada);
            Check(ev is { Titulo: "Protección contra ransomware: activada", Modulo: ModuloOrigen.Amenazas } && Equals(ev.Campos["exito"], true) && Equals(ev.Campos["modo_anterior"], 0),
                "queda en el vault, con el modo anterior y el resultado", ev?.Titulo);

            // Ya activado: la vista previa no da token.
            var nada = await PedirCfa(m, "cfa.previsualizar", new { modo = "activar" });
            Check(nada.Ok && !nada.R!.Value.GetProperty("hay_cambios").GetBoolean() && nada.R.Value.GetProperty("token").ValueKind == JsonValueKind.Null, "ya activado: sin cambios y sin token");
            Check(!(await PedirCfa(m, "cfa.previsualizar", new { modo = "auditar" })).R!.Value.GetProperty("hay_cambios").GetBoolean(), "activado -> auditar: sin token (quitaría protección)");

            // Windows acepta y no aplica: el servicio responde exito = false y el vault lo dice.
            l.Valor = new EstadoDeDefenderCfa(0, true, "Normal");
            ej.AlFijar = null;
            string tok2 = (await PedirCfa(m, "cfa.previsualizar", new { modo = "activar" })).R!.Value.GetProperty("token").GetString()!;
            var ign = await PedirCfa(m, "cfa.aplicar", new { token = tok2 });
            Check(ign.Ok && !ign.R!.Value.GetProperty("exito").GetBoolean() && ign.R.Value.GetProperty("mensaje").GetString()!.Contains("no cambió")
                  && w.Eventos.Last().Titulo.EndsWith("(no se aplicó)") && w.Eventos.Last().Severidad == Severidad.Media,
                "Windows acepta pero no aplica: «exito» falso, y el vault dice «no se aplicó»");
        }
    }
}
