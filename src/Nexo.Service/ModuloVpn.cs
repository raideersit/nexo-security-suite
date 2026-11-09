using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Vpn;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// La VPN por el pipe, con el mismo camino que el firewall: «vpn.previsualizar» no cambia nada y devuelve un token; «vpn.aplicar» ejecuta
    /// SOLO el plan de ese token, despues de la aprobacion (UAC, si la politica la exige) y volviendo a mirar el estado. Las reglas (que se
    /// conecta, que se rechaza) son de <see cref="PlanificadorDeVpn"/>, no de esta clase. El texto del archivo viaja por el pipe local (solo
    /// el usuario y SYSTEM pueden abrirlo) y vive en memoria hasta que se aplica o caduca el token; nunca se escribe en el vault.
    /// </summary>
    public sealed class ModuloVpn : IModuloDelServicio
    {
        public const int TokenInvalido = -32010;

        private readonly ILectorDeWireGuard _lector;
        private readonly IEjecutorDeWireGuard _ejecutor;
        private readonly IReportWriter _reportes;
        private readonly PoliticaDeAprobacion _politica;
        private readonly PlanesPendientes<PlanDeVpn> _planes;

        public ModuloVpn(ILectorDeWireGuard lector, IEjecutorDeWireGuard ejecutor, IReportWriter reportes, PoliticaDeAprobacion? politica = null, Func<DateTimeOffset>? reloj = null)
        {
            _lector = lector;
            _ejecutor = ejecutor;
            _reportes = reportes;
            _politica = politica ?? PoliticaDeAprobacion.Ninguna;
            _planes = new PlanesPendientes<PlanDeVpn>(TimeSpan.FromMinutes(10), reloj: reloj);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "vpn.estado", "vpn.previsualizar", "vpn.aplicar" };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "vpn.estado":
                {
                    EstadoDeWireGuard e = _lector.Leer();
                    return new
                    {
                        instalado = e.Instalado,
                        version = e.Version,
                        error = e.Error,
                        tuneles = e.Tuneles.Select(t => new { nombre = t.Nombre, estado = t.Estado.ToString(), de_nexo = _ejecutor.EsDeNexo(t.Nombre) }).ToList()
                    };
                }
                case "vpn.previsualizar":
                    return Previsualizar(p);
                case "vpn.aplicar":
                    return await AplicarAsync(p, ct).ConfigureAwait(false);
                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        private object Previsualizar(JsonElement? p)
        {
            JsonElement o = Objeto(p);
            string tipo = Texto(o, "tipo", 16) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'tipo'");
            EstadoDeWireGuard estado = _lector.Leer();
            PlanDeVpn plan = tipo switch
            {
                "conectar" => PlanificadorDeVpn.PrepararConexion(
                    Texto(o, "conf", ParserDeWireGuard.MaximoDeCaracteres) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'conf'"),
                    Texto(o, "archivo", 260) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'archivo'"),
                    estado, _ejecutor),
                "desconectar" => PlanificadorDeVpn.PrepararDesconexion(
                    Texto(o, "tunel", 64) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'tunel'"), estado, _ejecutor),
                _ => throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'tipo' debe ser conectar o desconectar")
            };

            string? token = null;
            DateTimeOffset? expira = null;
            if (plan.HayCambios) (token, expira) = _planes.Guardar(plan);
            return new { descripcion = plan.Describir(), hay_cambios = plan.HayCambios, avisos = plan.Advertencias, token, expira };
        }

        private async Task<object> AplicarAsync(JsonElement? p, CancellationToken ct)
        {
            string token = Texto(Objeto(p), "token", 64) ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'token'");
            // Aprobacion antes de gastar el token: si falta, el plan sigue vigente.
            _politica.Exigir(ContextoDeLlamada.Actual);
            PlanDeVpn plan = _planes.Tomar(token) ?? throw new ErrorDeComando(TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");

            ResultadoDeVpn r = await PlanificadorDeVpn.AplicarAsync(plan, _lector.Leer(), _ejecutor, ct).ConfigureAwait(false);
            var e = new NexoEvent(ModuloOrigen.Privacidad, TipoEvento.ConexionVpn,
                (plan.Accion == AccionDeVpn.Conectar ? "VPN conectada: " : "VPN desconectada: ") + plan.Tunel + (r.Exito ? "" : " (falló)"))
            {
                Severidad = r.Exito ? Severidad.Info : Severidad.Media,
                Accion = r.Exito ? Accion.Registrada : Accion.Omitida,
                Cuerpo = r.Mensaje + "\n\n*El archivo de configuración (con la clave privada) nunca se escribe en estas notas.*"
            };
            e.Campos["tunel"] = plan.Tunel;
            e.Campos["accion"] = plan.Accion == AccionDeVpn.Conectar ? "conectar" : "desconectar";
            e.Campos["exito"] = r.Exito;
            try { await _reportes.EscribirAsync(e, ct).ConfigureAwait(false); } catch (Exception) when (!ct.IsCancellationRequested) { /* el vault nunca deshace la accion */ }
            return new { exito = r.Exito, mensaje = r.Mensaje, tunel = plan.Tunel, accion = e.Campos["accion"] };
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
