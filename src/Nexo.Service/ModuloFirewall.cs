using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Firewall;

namespace Nexo.Service
{
    /// <summary>
    /// El firewall por aplicacion expuesto por el pipe. Dos pasos, como en la consola:
    /// "firewall.previsualizar" no cambia nada y devuelve un token; "firewall.aplicar"
    /// ejecuta SOLO el plan guardado bajo ese token. Toda validacion de rutas y de procesos
    /// protegidos la hace AdministradorDeFirewall (GuardiaDeReglas), no esta clase.
    /// </summary>
    public sealed class ModuloFirewall : IModuloDelServicio
    {
        public const int TokenInvalido = -32010;

        private readonly AdministradorDeFirewall _admin;
        private readonly PlanesPendientes<VistaPreviaFirewall> _planes;

        public ModuloFirewall(AdministradorDeFirewall admin, Func<DateTimeOffset>? reloj = null)
        {
            _admin = admin;
            _planes = new PlanesPendientes<VistaPreviaFirewall>(TokenDeCambio.Vigencia, reloj: reloj);
        }

        public int PlanesPendientes => _planes.Pendientes;

        public IReadOnlyList<string> Metodos { get; } = new[] { "firewall.estado", "firewall.previsualizar", "firewall.aplicar" };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "firewall.estado":
                    return new
                    {
                        reglas_de_nexo = _admin.ListarDeNexo().Select(r => new
                        {
                            nombre = r.Nombre, accion = r.Accion.ToString(), direccion = r.Direccion.ToString(),
                            ruta = r.RutaApp, habilitada = r.Habilitada
                        }).ToList(),
                        sigiloso = _admin.SigilosoActivo(),
                        perfiles = _admin.LeerPoliticas().Select(x => new
                        {
                            perfil = x.Perfil.ToString(), activo = x.FirewallActivo,
                            entrada_por_defecto = x.EntradaPorDefecto.ToString()
                        }).ToList()
                    };

                case "firewall.previsualizar":
                    return Previsualizar(p);

                case "firewall.aplicar":
                    return await AplicarAsync(p, ct).ConfigureAwait(false);

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        private object Previsualizar(JsonElement? p)
        {
            JsonElement o = Objeto(p);
            string tipo = Texto(o, "tipo", obligatorio: true)!;

            VistaPreviaFirewall vista;
            switch (tipo)
            {
                case "regla":
                    string ruta = Texto(o, "ruta", obligatorio: true, max: 520)!;
                    AccionDeRegla accion = Enumerado(o, "accion", new Dictionary<string, AccionDeRegla>
                        { ["bloquear"] = AccionDeRegla.Bloquear, ["permitir"] = AccionDeRegla.Permitir });
                    DireccionDeRegla? dir = o.TryGetProperty("direccion", out JsonElement d) && d.ValueKind != JsonValueKind.Null
                        ? Enumerado(o, "direccion", new Dictionary<string, DireccionDeRegla>
                            { ["entrante"] = DireccionDeRegla.Entrante, ["saliente"] = DireccionDeRegla.Saliente })
                        : null;
                    vista = _admin.PrepararRegla(ruta, accion, dir);
                    break;

                case "quitar":
                    vista = _admin.PrepararQuitar(Texto(o, "nombre", obligatorio: true, max: 260)!);
                    break;

                case "sigiloso":
                    if (!o.TryGetProperty("activar", out JsonElement a) || a.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'activar' debe ser true o false");
                    vista = _admin.PrepararSigiloso(a.GetBoolean());
                    break;

                default:
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'tipo' debe ser regla, quitar o sigiloso");
            }

            // Sin cambios no hay nada que confirmar: no se guarda un plan vacio ni se emite token.
            string? token = null;
            DateTimeOffset? expira = null;
            if (vista.HayCambios)
            {
                (string t, DateTimeOffset e) = _planes.Guardar(vista);
                token = t;
                expira = e;
            }

            return new
            {
                descripcion = vista.Describir(),
                hay_cambios = vista.HayCambios,
                cambios = vista.Cambios.Select(c => c.Describir()).ToList(),
                rechazos = vista.Rechazos,
                advertencias = vista.Advertencias,
                token,
                expira
            };
        }

        private async Task<object> AplicarAsync(JsonElement? p, CancellationToken ct)
        {
            JsonElement o = Objeto(p);
            string? token = Texto(o, "token", obligatorio: true, max: 64);

            VistaPreviaFirewall? vista = _planes.Tomar(token);
            if (vista is null)
                throw new ErrorDeComando(TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");

            try
            {
                ResultadoFirewall r = await _admin.AplicarAsync(vista, vista.Token, ct).ConfigureAwait(false);
                return new { aplicados = r.Aplicados, omitidos = r.Omitidos };
            }
            catch (InvalidOperationException)
            {
                // El token interno del plan (huella) no coincide o caduco: mismo trato que un token malo.
                throw new ErrorDeComando(TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");
            }
        }

        // ------------------------------------------------------------
        private static JsonElement Objeto(JsonElement? p)
        {
            if (p is { ValueKind: JsonValueKind.Object } o) return o;
            throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se esperaba un objeto de parametros");
        }

        private static string? Texto(JsonElement o, string nombre, bool obligatorio = false, int max = 128)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                if (obligatorio) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta '" + nombre + "'");
                return null;
            }
            if (v.ValueKind != JsonValueKind.String)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' debe ser texto");
            string s = v.GetString()!;
            if (s.Length > max)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' es demasiado largo");
            return s;
        }

        private static T Enumerado<T>(JsonElement o, string nombre, Dictionary<string, T> permitidos)
        {
            string? s = Texto(o, nombre, obligatorio: true, max: 16);
            if (s is not null && permitidos.TryGetValue(s, out T? v)) return v;
            throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos,
                "'" + nombre + "' debe ser uno de: " + string.Join(", ", permitidos.Keys));
        }
    }
}
