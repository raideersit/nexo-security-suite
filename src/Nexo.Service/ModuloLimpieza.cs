using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Reports;

namespace Nexo.Service
{
    /// <summary>
    /// La limpieza de archivos basura por el pipe: vista previa + token, y aplicar.
    ///
    /// Reglas que la hacen segura frente a un cliente no fiable:
    ///  1. Todo se hace CON LA IDENTIDAD DEL LLAMADOR y sobre SU perfil. La vista previa y el borrado corren
    ///     suplantandolo (RunImpersonatedAsync, que cruza los await): solo se puede listar y borrar lo que ese
    ///     usuario podria listar y borrar. Las carpetas base (AppData...) son las del perfil del llamador, no
    ///     las de la cuenta del servicio. Sin identidad utilizable o sin perfil: se rechaza.
    ///  2. El cliente elige REGLAS DEL CATALOGO por id, nunca rutas. El catalogo es la lista de lo que Nexo tiene
    ///     permiso para destruir y vive en el ensamblado.
    ///  3. Se borra exactamente lo previsualizado: el plan se guarda aqui y el cliente solo devuelve un token
    ///     de un solo uso; el limpiador revalida cada archivo (guardia, tamano, enlaces) antes de borrar.
    ///  4. Un plan solo lo puede aplicar quien lo previsualizo.
    ///  5. El modo de borrado (Papelera por omision) lo decide la configuracion del servicio, no el cliente.
    ///  6. Las notas se escriben con la identidad del servicio, no con la del usuario.
    /// </summary>
    public sealed class ModuloLimpieza : IModuloDelServicio
    {
        private const int MaxReglas = 64;
        private const int MaxOmitidosEnRespuesta = 100;
        private const int MaxEjemplos = 20;

        private sealed record Plan(LimpiadorDeBasura Limpiador, VistaPreviaLimpieza Vista, SecurityIdentifier? Dueno);

        private readonly CatalogoDeRutas _catalogo;
        private readonly IBorrador _borrador;
        private readonly IReportWriter _reportes;
        private readonly Func<ContextoDeLlamada, IReadOnlyDictionary<BaseDeRuta, string>?> _bases;
        private readonly PlanesPendientes<Plan> _planes;
        private readonly PoliticaDeAprobacion _politica;

        public ModuloLimpieza(
            CatalogoDeRutas catalogo, IBorrador borrador, IReportWriter reportes,
            Func<ContextoDeLlamada, IReadOnlyDictionary<BaseDeRuta, string>?>? basesDelLlamador = null,
            Func<DateTimeOffset>? reloj = null, PoliticaDeAprobacion? politica = null)
        {
            _politica = politica ?? PoliticaDeAprobacion.Ninguna;
            _catalogo = catalogo;
            _borrador = borrador;
            _reportes = new ReportesFueraDeSuplantacion(reportes);
            _bases = basesDelLlamador ?? (c => c.Usuario is null ? null : PerfilDeUsuario.BasesDe(c.Usuario));
            _planes = new PlanesPendientes<Plan>(Nexo.Modules.Cleanup.Seguridad.TokenConfirmacion.Vigencia, reloj: reloj);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "limpieza.reglas", "limpieza.previsualizar", "limpieza.aplicar" };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "limpieza.reglas":
                    return new
                    {
                        modo = _borrador.EsReversible ? "papelera" : "borrado-permanente",
                        reversible = _borrador.EsReversible,
                        reglas = _catalogo.Reglas.Select(r => new
                        {
                            id = r.Id, nombre = r.Nombre, categoria = r.Categoria, riesgo = r.Riesgo.ToString(),
                            requiere_admin = r.RequiereAdmin, activa_por_defecto = r.ActivaPorDefecto
                        }).ToList()
                    };

                case "limpieza.previsualizar":
                    return await PrevisualizarAsync(p, ct).ConfigureAwait(false);

                case "limpieza.aplicar":
                    return await AplicarAsync(p, ct).ConfigureAwait(false);

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        // ------------------------------------------------------------
        private async Task<object> PrevisualizarAsync(JsonElement? p, CancellationToken ct)
        {
            // Sin identidad utilizable no se hace nada (nunca como SYSTEM).
            AccesoComoLlamador.Requerir();
            ContextoDeLlamada contexto = ContextoDeLlamada.Actual!;

            IReadOnlyCollection<string>? ids = LeerReglas(p);

            IReadOnlyDictionary<BaseDeRuta, string>? bases = _bases(contexto);
            if (bases is null)
                throw new ErrorDeComando(CodigoDeError.ErrorInterno, "no se encontro el perfil del usuario: no se limpia nada");

            var limpiador = new LimpiadorDeBasura(_catalogo, bases, _borrador, _reportes, esAdministrador: contexto.EsAdministrador);

            // Todo el recorrido va con la identidad del llamador, tambien a traves de los await.
            VistaPreviaLimpieza vista = await contexto.EjecutarAsync(() => limpiador.PrepararVistaPreviaAsync(ids, ct)).ConfigureAwait(false);

            string? token = null;
            DateTimeOffset? expira = null;
            if (vista.TotalArchivos > 0)
            {
                (string t, DateTimeOffset e) = _planes.Guardar(new Plan(limpiador, vista, contexto.Usuario));
                token = t;
                expira = e;
            }

            return new
            {
                total_archivos = vista.TotalArchivos,
                total_bytes = vista.TotalBytes,
                reversible = _borrador.EsReversible,
                categorias = vista.PorCategoria().Select(c => new { categoria = c.Categoria, archivos = c.Archivos, bytes = c.Bytes }).ToList(),
                ejemplos = vista.Elementos.OrderByDescending(e => e.Bytes).Take(MaxEjemplos)
                    .Select(e => new { ruta = e.Ruta, bytes = e.Bytes, categoria = e.Categoria }).ToList(),
                omitidas = vista.RutasOmitidas.Take(MaxOmitidosEnRespuesta).ToList(),
                omitidas_total = vista.RutasOmitidas.Count,
                reglas_sin_permisos = vista.ReglasSaltadasPorPermisos,
                token,
                expira
            };
        }

        private async Task<object> AplicarAsync(JsonElement? p, CancellationToken ct)
        {
            // Primero la identidad y despues el token: si no se puede actuar como el llamador, el token NO se gasta.
            AccesoComoLlamador.Requerir();
            ContextoDeLlamada contexto = ContextoDeLlamada.Actual!;
            _politica.Exigir(contexto);

            if (p is not { ValueKind: JsonValueKind.Object } o || !o.TryGetProperty("token", out JsonElement t)
                || t.ValueKind != JsonValueKind.String || t.GetString()!.Length > 64)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'token' (texto)");

            Plan? plan = _planes.Tomar(t.GetString());
            // Mismo error para token falso, usado, caducado o de OTRO usuario: no se dan pistas.
            if (plan is null || (plan.Dueno is not null && contexto.Usuario != plan.Dueno))
                throw new ErrorDeComando(ModuloFirewall.TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");

            try
            {
                ResultadoBorrado r = await contexto.EjecutarAsync(() => plan.Limpiador.EjecutarAsync(plan.Vista, plan.Vista.Token, ct)).ConfigureAwait(false);
                return new
                {
                    eliminados = r.Eliminados,
                    bytes_liberados = r.BytesLiberados,
                    reversible = _borrador.EsReversible,
                    omitidos = r.Omitidos.Take(MaxOmitidosEnRespuesta).ToList(),
                    omitidos_total = r.Omitidos.Count
                };
            }
            catch (InvalidOperationException)
            {
                // El token interno (huella) no coincide o caduco: mismo trato que un token malo.
                throw new ErrorDeComando(ModuloFirewall.TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");
            }
        }

        private IReadOnlyCollection<string>? LeerReglas(JsonElement? p)
        {
            if (p is not { ValueKind: JsonValueKind.Object } o || !o.TryGetProperty("reglas", out JsonElement arr) || arr.ValueKind == JsonValueKind.Null)
                return null;                                    // por omision: solo las de riesgo bajo

            if (arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() is 0 or > MaxReglas)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'reglas' debe ser una lista de 1 a " + MaxReglas + " ids");

            var conocidas = new HashSet<string>(_catalogo.Reglas.Select(r => r.Id), StringComparer.OrdinalIgnoreCase);
            var ids = new List<string>();
            foreach (JsonElement e in arr.EnumerateArray())
            {
                string? id = e.ValueKind == JsonValueKind.String ? e.GetString() : null;
                if (id is null || id.Length > 64 || !conocidas.Contains(id))
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "regla desconocida (solo ids del catalogo, ver limpieza.reglas)");
                ids.Add(id);
            }
            return ids;
        }
    }
}
