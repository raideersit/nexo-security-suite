using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// Activar las carpetas protegidas contra ransomware de Defender por el pipe, con el mismo camino que el firewall y la VPN:
    /// «cfa.previsualizar» no cambia nada y devuelve un token; «cfa.aplicar» ejecuta SOLO el plan de ese token, despues de la aprobacion
    /// (UAC, si la politica la exige) y volviendo a mirar el estado. Las reglas son de <see cref="PlanificadorDeCarpetasProtegidas"/>: Nexo
    /// solo activa (o pone en auditoria si esta apagado), nunca apaga ni debilita.
    /// </summary>
    public sealed class ModuloCarpetasProtegidas : IModuloDelServicio
    {
        public const int TokenInvalido = -32010;

        private readonly ILectorDeEstadoDeCfa _lector;
        private readonly IEjecutorDeCfa _ejecutor;
        private readonly IReportWriter _reportes;
        private readonly PoliticaDeAprobacion _politica;
        private readonly PlanesPendientes<PlanDeCarpetasProtegidas> _planes;

        public ModuloCarpetasProtegidas(ILectorDeEstadoDeCfa lector, IEjecutorDeCfa ejecutor, IReportWriter reportes, PoliticaDeAprobacion? politica = null, Func<DateTimeOffset>? reloj = null)
        {
            _lector = lector;
            _ejecutor = ejecutor;
            _reportes = reportes;
            _politica = politica ?? PoliticaDeAprobacion.Ninguna;
            _planes = new PlanesPendientes<PlanDeCarpetasProtegidas>(TimeSpan.FromMinutes(10), reloj: reloj);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "cfa.previsualizar", "cfa.aplicar" };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "cfa.previsualizar":
                {
                    string modo = Texto(Objeto(p), "modo", 16) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'modo'");
                    ModoDeCarpetasProtegidas destino = modo switch
                    {
                        "activar" => ModoDeCarpetasProtegidas.Activado,
                        "auditar" => ModoDeCarpetasProtegidas.Auditoria,
                        _ => throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'modo' debe ser activar o auditar")
                    };
                    EstadoDeDefenderCfa estado = await Task.Run(_lector.Leer, ct).ConfigureAwait(false);
                    PlanDeCarpetasProtegidas plan = PlanificadorDeCarpetasProtegidas.Preparar(destino, estado);
                    string? token = null;
                    DateTimeOffset? expira = null;
                    if (plan.HayCambios) (token, expira) = _planes.Guardar(plan);
                    return new { descripcion = plan.Describir(), hay_cambios = plan.HayCambios, avisos = plan.Advertencias, token, expira };
                }
                case "cfa.aplicar":
                    return await AplicarAsync(p, ct).ConfigureAwait(false);
                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        private async Task<object> AplicarAsync(JsonElement? p, CancellationToken ct)
        {
            string token = Texto(Objeto(p), "token", 64) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'token'");
            // Aprobacion antes de gastar el token: si falta, el plan sigue vigente.
            _politica.Exigir(ContextoDeLlamada.Actual);
            PlanDeCarpetasProtegidas plan = _planes.Tomar(token) ?? throw new ErrorDeComando(TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");

            ResultadoDeCfa r = await Task.Run(() => PlanificadorDeCarpetasProtegidas.Aplicar(plan, _lector, _ejecutor), ct).ConfigureAwait(false);
            string destino = plan.Destino == ModoDeCarpetasProtegidas.Activado ? "activar" : "auditar";
            var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.ProteccionRansomwareCambiada,
                "Protección contra ransomware: " + (plan.Destino == ModoDeCarpetasProtegidas.Activado ? "activada" : "en modo auditoría") + (r.Exito ? "" : " (no se aplicó)"))
            {
                Severidad = r.Exito ? Severidad.Info : Severidad.Media,
                Accion = r.Exito ? Accion.Registrada : Accion.Omitida,
                Cuerpo = r.Mensaje
            };
            e.Campos["destino"] = destino;
            e.Campos["modo_anterior"] = plan.ModoAnterior;
            e.Campos["modo_final"] = r.ModoFinal;
            e.Campos["exito"] = r.Exito;
            try { await _reportes.EscribirAsync(e, ct).ConfigureAwait(false); } catch (Exception) when (!ct.IsCancellationRequested) { /* el vault nunca deshace la accion */ }
            return new { exito = r.Exito, mensaje = r.Mensaje, modo_final = r.ModoFinal, destino };
        }

        private static JsonElement Objeto(JsonElement? p)
            => p is { ValueKind: JsonValueKind.Object } o ? o : throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se esperaba un objeto de parametros");

        private static string? Texto(JsonElement o, string nombre, int max)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v) || v.ValueKind == JsonValueKind.Null) return null;
            if (v.ValueKind != JsonValueKind.String) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' debe ser texto");
            string s = v.GetString()!;
            if (s.Length > max) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' es demasiado largo");
            return s;
        }
    }
}
