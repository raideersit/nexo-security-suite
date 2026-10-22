using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Cuarentena;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.Firewall;

namespace Nexo.Service
{
    /// <summary>
    /// La cuarentena por el pipe. Reglas que la hacen segura frente a un cliente no fiable:
    ///
    ///  1. SOLO se pone en cuarentena lo que detecto un escaneo del propio servicio y se
    ///     nombra por el id de ese escaneo. El cliente NO puede pasar una ruta suya: si pudiera,
    ///     tendria a SYSTEM moviendo (es decir, quitando de su sitio) cualquier archivo del equipo.
    ///  0. El original se lee, se retira y se restaura CON LA IDENTIDAD DEL LLAMADOR (no como SYSTEM): solo
    ///     se puede poner en cuarentena lo que ese usuario podria leer y borrar por si mismo, y solo se
    ///     restaura donde el podria escribir. Si no se puede actuar como el, se rechaza.
    ///  2. Restaurar es SOLO a la ruta original y nunca pisa un archivo; no hay parametro
    ///     "destino" por el pipe (seria escribir un archivo donde diga el cliente, como SYSTEM).
    ///  3. Todo lo que cambia algo (poner, restaurar, purgar) es vista previa + token de un solo uso.
    ///  4. La carpeta de cuarentena guarda la clave junto a cada archivo cifrado: debe ser
    ///     escribible solo por SYSTEM y Administradores (la ACL de %ProgramData%\Nexo, que
    ///     fija el script de instalacion). Si un usuario normal pudiera escribir ahi, podria
    ///     fabricar una entrada valida y hacer que "restaurar" escriba donde quiera.
    /// </summary>
    public sealed class ModuloCuarentena : IModuloDelServicio
    {
        private sealed record Plan(string Tipo, VistaPreviaCuarentena? Poner = null, ElementoDeCuarentena? Restaurar = null,
                                   VistaPreviaPurga? Purgar = null);

        private readonly AlmacenDeCuarentena _almacen;
        private readonly IResultadosDeEscaneo _escaneos;
        private readonly PlanesPendientes<Plan> _planes;

        private readonly PoliticaDeAprobacion _politica;

        public ModuloCuarentena(AlmacenDeCuarentena almacen, IResultadosDeEscaneo escaneos, Func<DateTimeOffset>? reloj = null,
                                PoliticaDeAprobacion? politica = null)
        {
            _politica = politica ?? PoliticaDeAprobacion.Ninguna;
            _almacen = almacen;
            _escaneos = escaneos;
            _planes = new PlanesPendientes<Plan>(TokenDeCambio.Vigencia, reloj: reloj);
        }

        public IReadOnlyList<string> Metodos { get; } = new[]
        {
            "cuarentena.listar",
            "cuarentena.previsualizar", "cuarentena.aplicar",
            "cuarentena.previsualizar-restauracion", "cuarentena.restaurar",
            "cuarentena.previsualizar-purga", "cuarentena.purgar"
        };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "cuarentena.listar":
                    return new
                    {
                        elementos = _almacen.Listar().Select(e => new
                        {
                            id = e.Id, ruta_original = e.RutaOriginal, bytes = e.Bytes, firma = e.Firma, fecha = e.Fecha,
                            vence = e.Fecha + AlmacenDeCuarentena.Retencion
                        }).ToList()
                    };

                case "cuarentena.previsualizar":
                    return PrevisualizarPoner(p);

                case "cuarentena.previsualizar-restauracion":
                    return PrevisualizarRestauracion(p);

                case "cuarentena.previsualizar-purga":
                {
                    VistaPreviaPurga v = _almacen.PrepararPurga();
                    return Respuesta(v.Describir(), v.HayCambios, v.Elementos.Count, Array.Empty<string>(),
                                     v.HayCambios ? new Plan("purgar", Purgar: v) : null);
                }

                case "cuarentena.aplicar":
                {
                    // Primero la identidad y despues el token: si no se puede actuar como el llamador, el token NO se
                    // gasta y puede reintentar desde una conexion con suplantacion.
                    AccesoComoLlamador.Requerir();
                    _politica.Exigir(ContextoDeLlamada.Actual);
                    // El original se lee y se retira CON LA IDENTIDAD DEL DUENO DEL PLAN (el llamador, o el usuario estandar cuyo
                    // plan aprobo un administrador): solo lo que el podria leer y borrar.
                    using PlanTomado<Plan> tomado = Tomar(p, "poner");
                    Plan plan = tomado.Plan;
                    ResultadoCuarentena r = await _almacen.AplicarAsync(plan.Poner!, plan.Poner!.Token, ct, new AccesoComoLlamador(tomado.Contexto)).ConfigureAwait(false);
                    return new
                    {
                        movidos = r.Movidos.Select(e => new { id = e.Id, ruta_original = e.RutaOriginal }).ToList(),
                        omitidos = r.Omitidos
                    };
                }

                case "cuarentena.restaurar":
                {
                    AccesoComoLlamador.Requerir();
                    _politica.Exigir(ContextoDeLlamada.Actual);
                    // Se escribe en la ruta original CON LA IDENTIDAD DEL DUENO DEL PLAN: no donde el no podria escribir.
                    using PlanTomado<Plan> tomado = Tomar(p, "restaurar");
                    Plan plan = tomado.Plan;
                    ResultadoRestauracion r = await _almacen.RestaurarAsync(plan.Restaurar!.Id, destino: null, ct, new AccesoComoLlamador(tomado.Contexto)).ConfigureAwait(false);
                    return new { exito = r.Exito, ruta = r.Ruta, motivo = r.Motivo };
                }

                case "cuarentena.purgar":
                {
                    _politica.Exigir(ContextoDeLlamada.Actual);
                    using PlanTomado<Plan> tomado = Tomar(p, "purgar");
                    Plan plan = tomado.Plan;
                    ResultadoPurga r = await _almacen.AplicarPurgaAsync(plan.Purgar!, plan.Purgar!.Token, ct).ConfigureAwait(false);
                    return new { purgados = r.Purgados.Count, omitidos = r.Omitidos };
                }

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        // ------------------------------------------------------------
        private object PrevisualizarPoner(JsonElement? p)
        {
            JsonElement o = Objeto(p);
            string id = Cadena(o, "escaneo", 32);
            ResultadoDeEscaneo? escaneo = _escaneos.Obtener(id);
            if (escaneo is null)
                throw new ErrorDeComando(ModuloEscaneo.NoExiste, "no existe ese escaneo, o todavia no termino");

            IEnumerable<Deteccion> candidatas = escaneo.Detecciones;

            // Un subconjunto opcional, pero SIEMPRE dentro de lo que ese escaneo detecto.
            if (o.TryGetProperty("rutas", out JsonElement arr) && arr.ValueKind != JsonValueKind.Null)
            {
                if (arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() > 1000)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'rutas' debe ser una lista corta");
                var pedidas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonElement e in arr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.String)
                        throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "cada ruta debe ser texto");
                    pedidas.Add(e.GetString()!);
                }
                var conocidas = new HashSet<string>(escaneo.Detecciones.Select(d => d.Ruta), StringComparer.OrdinalIgnoreCase);
                string? ajena = pedidas.FirstOrDefault(x => !conocidas.Contains(x));
                if (ajena is not null)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "esa ruta no es una deteccion de ese escaneo");
                candidatas = escaneo.Detecciones.Where(d => pedidas.Contains(d.Ruta));
            }

            VistaPreviaCuarentena v = _almacen.Preparar(candidatas);
            return Respuesta(v.Describir(), v.HayCambios, v.Elementos.Count, v.Rechazos,
                             v.HayCambios ? new Plan("poner", Poner: v) : null);
        }

        private object PrevisualizarRestauracion(JsonElement? p)
        {
            string id = Cadena(Objeto(p), "id", 32);
            ElementoDeCuarentena? e = _almacen.Listar().FirstOrDefault(x => x.Id == id);
            if (e is null) throw new ErrorDeComando(ModuloEscaneo.NoExiste, "no existe esa entrada de cuarentena");

            var avisos = new List<string>();
            AccesoComoLlamador acceso = AccesoComoLlamador.Requerir();
            if (acceso.Ejecutar(() => File.Exists(e.RutaOriginal) || Directory.Exists(e.RutaOriginal)))
                avisos.Add("el destino ya existe: la restauracion no lo sobrescribira");
            avisos.Add("Se restaura un archivo que se detecto como " + e.Firma + ". Es tu decision.");

            return Respuesta("Restaurar " + e.RutaOriginal + " (" + e.Firma + ")", true, 1, avisos, new Plan("restaurar", Restaurar: e));
        }

        private object Respuesta(string descripcion, bool hayCambios, int elementos, IReadOnlyList<string> avisos, Plan? plan)
        {
            string? token = null;
            DateTimeOffset? expira = null;
            if (plan is not null)
            {
                (string t, DateTimeOffset x) = _planes.Guardar(plan, plan.Tipo == "purgar" ? null : ContextoDeLlamada.Actual);
                token = t;
                expira = x;
            }
            return new { descripcion, hay_cambios = hayCambios, elementos, avisos, token, expira };
        }

        private PlanTomado<Plan> Tomar(JsonElement? p, string tipoEsperado)
        {
            string? token = Cadena(Objeto(p), "token", 64);
            PlanTomado<Plan>? tomado = _planes.Tomar(token, ContextoDeLlamada.Actual);
            // Un token de otra accion, o de otro usuario sin aprobacion de un administrador, se trata igual que uno falso (y queda consumido).
            if (tomado is null || tomado.Plan.Tipo != tipoEsperado)
            {
                tomado?.Dispose();
                throw new ErrorDeComando(ModuloFirewall.TokenInvalido, "token invalido, ya usado o caducado: hay que previsualizar de nuevo");
            }
            return tomado;
        }

        private static JsonElement Objeto(JsonElement? p)
        {
            if (p is { ValueKind: JsonValueKind.Object } o) return o;
            throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se esperaba un objeto de parametros");
        }

        private static string Cadena(JsonElement o, string nombre, int max)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v) || v.ValueKind != JsonValueKind.String)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta '" + nombre + "' (texto)");
            string s = v.GetString()!;
            if (s.Length > max) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'" + nombre + "' es demasiado largo");
            return s;
        }
    }
}
