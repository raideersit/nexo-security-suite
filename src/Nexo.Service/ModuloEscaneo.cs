using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Escaner;
using Nexo.Reports;

namespace Nexo.Service
{
    /// <summary>De donde la cuarentena toma lo que puede mover: SOLO resultados de escaneos del propio servicio.</summary>
    public interface IResultadosDeEscaneo
    {
        ResultadoDeEscaneo? Obtener(string id);
    }

    /// <summary>
    /// Escaneo bajo demanda por el pipe. Un escaneo dura mas que el limite por peticion, asi que
    /// es un TRABAJO: "iniciar" devuelve un id y se consulta con "progreso" y "resultado".
    ///
    /// Escanear no modifica nada. Pero el servicio lee los archivos con SU cuenta, no con la del
    /// llamador (ver "Limite" abajo), asi que se acota lo que se puede pedir: hasta 8 rutas
    /// absolutas y locales, nunca de red (UNC), y un solo escaneo a la vez.
    ///
    /// El servicio lee los archivos CON LA IDENTIDAD DEL LLAMADOR (recorrido, tamano y apertura), no
    /// como SYSTEM: solo se analiza lo que ese usuario podria leer por si mismo, asi que escanear no
    /// le revela nada que no pudiera saber. Si el cliente no deja actuar en su nombre, se rechaza.
    /// </summary>
    public sealed class ModuloEscaneo : IModuloDelServicio, IResultadosDeEscaneo, IAsyncDisposable
    {
        public const int MotorNoDisponible = -32020;
        public const int Ocupado = -32021;
        public const int NoExiste = -32022;

        public const int MaxRutas = 8;
        private const int MaxOmitidosEnRespuesta = 200;
        private const int MaxTrabajosGuardados = 4;

        private sealed class Trabajo
        {
            public string Id = "";
            public volatile string Estado = "corriendo";       // corriendo | terminado | cancelado | fallido
            public int Analizados;
            public volatile ResultadoDeEscaneo? Resultado;
            public string? Error;
            public CancellationTokenSource Cts = new CancellationTokenSource();
            public Task? Tarea;
            public DateTimeOffset Inicio;
        }

        private readonly IMotorDeFirmas _motor;
        private readonly IReportWriter _reportes;
        private readonly IReadOnlyList<string> _excluir;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Dictionary<string, Trabajo> _trabajos = new Dictionary<string, Trabajo>(StringComparer.Ordinal);
        private readonly object _candado = new object();

        public ModuloEscaneo(IMotorDeFirmas motor, IReportWriter reportes, IEnumerable<string>? excluir = null, Func<DateTimeOffset>? reloj = null)
        {
            _motor = motor;
            _reportes = reportes;
            _excluir = (excluir ?? Array.Empty<string>()).ToList();
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        public IReadOnlyList<string> Metodos { get; } = new[]
        {
            "escaneo.estado", "escaneo.iniciar", "escaneo.progreso", "escaneo.resultado", "escaneo.cancelar"
        };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            switch (metodo)
            {
                case "escaneo.estado":
                    try
                    {
                        return new { motor_disponible = true, motor = _motor.Nombre, version = await _motor.VersionAsync(ct).ConfigureAwait(false) };
                    }
                    catch (MotorNoDisponibleException)
                    {
                        return new { motor_disponible = false, motor = _motor.Nombre };
                    }

                case "escaneo.iniciar":
                    return await IniciarAsync(p, ct).ConfigureAwait(false);

                case "escaneo.progreso":
                {
                    Trabajo t = Buscar(p);
                    return new { id = t.Id, estado = t.Estado, analizados = Volatile.Read(ref t.Analizados), error = t.Error };
                }

                case "escaneo.resultado":
                {
                    Trabajo t = Buscar(p);
                    if (t.Resultado is null)
                        return new { id = t.Id, estado = t.Estado, listo = false, error = t.Error };
                    ResultadoDeEscaneo r = t.Resultado;
                    return new
                    {
                        id = t.Id,
                        estado = t.Estado,
                        listo = true,
                        analizados = r.Analizados,
                        completamente_limpio = r.CompletamenteLimpio,
                        incompleto = r.Incompleto,
                        motivo_incompleto = r.MotivoIncompleto,
                        duracion_segundos = Math.Round(r.Duracion.TotalSeconds, 1),
                        detecciones = r.Detecciones.Select(d => new { ruta = d.Ruta, firma = d.Firma, bytes = d.Bytes, sha256 = d.Sha256 }).ToList(),
                        omitidos = r.Omitidos.Take(MaxOmitidosEnRespuesta).ToList(),
                        omitidos_total = r.Omitidos.Count
                    };
                }

                case "escaneo.cancelar":
                {
                    Trabajo t = Buscar(p);
                    t.Cts.Cancel();
                    return new { id = t.Id, cancelando = t.Estado == "corriendo" };
                }

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        // ------------------------------------------------------------
        private async Task<object> IniciarAsync(JsonElement? p, CancellationToken ct)
        {
            if (p is not { ValueKind: JsonValueKind.Object } o)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "se esperaba un objeto de parametros");

            List<string> rutas = LeerRutas(o);
            int paralelo = 1;
            if (o.TryGetProperty("paralelo", out JsonElement pa) && pa.ValueKind != JsonValueKind.Null)
            {
                if (pa.ValueKind != JsonValueKind.Number || !pa.TryGetInt32(out paralelo) || paralelo < 1)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'paralelo' debe ser un entero positivo");
            }

            // Se escanea CON LA IDENTIDAD DEL LLAMADOR: solo se lee lo que el podria leer. Si no se puede
            // actuar como el, se rechaza (nunca se escanea como SYSTEM). La copia sobrevive a la peticion.
            AccesoComoLlamador acceso = AccesoComoLlamador.Requerir().Duplicar();

            // Se avisa YA si no hay motor, en vez de arrancar un trabajo que fallara despues.
            try { await _motor.VersionAsync(ct).ConfigureAwait(false); }
            catch (MotorNoDisponibleException ex)
            {
                acceso.Dispose();
                throw new ErrorDeComando(MotorNoDisponible, "el motor de analisis no esta disponible: " + ex.Message);
            }

            Trabajo t;
            lock (_candado)
            {
                if (_trabajos.Values.Any(x => x.Estado == "corriendo"))
                {
                    acceso.Dispose();
                    throw new ErrorDeComando(Ocupado, "ya hay un escaneo en curso");
                }

                // Se descartan los terminados mas antiguos: no se acumulan resultados sin limite.
                foreach (string k in _trabajos.Values.Where(x => x.Estado != "corriendo").OrderBy(x => x.Inicio)
                             .Take(Math.Max(0, _trabajos.Count - MaxTrabajosGuardados + 1)).Select(x => x.Id).ToList())
                    _trabajos.Remove(k);

                t = new Trabajo { Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(), Inicio = _reloj() };
                _trabajos[t.Id] = t;
            }

            var opciones = new OpcionesDeEscaneo { Excluir = _excluir, Paralelismo = paralelo, Acceso = acceso };
            var progreso = new Progress<ProgresoDeEscaneo>(x => Volatile.Write(ref t.Analizados, x.Analizados));
            t.Tarea = Task.Run(async () =>
            {
                try
                {
                    t.Resultado = await new EscanerBajoDemanda(_motor, _reportes, opciones)
                        .EscanearAsync(rutas, progreso, t.Cts.Token).ConfigureAwait(false);
                    Volatile.Write(ref t.Analizados, t.Resultado.Analizados);
                    t.Estado = "terminado";
                }
                catch (OperationCanceledException) { t.Estado = "cancelado"; }
                catch (MotorNoDisponibleException ex) { t.Error = ex.Message; t.Estado = "fallido"; }
                catch (Exception)
                {
                    // Sin detalles: una excepcion puede contener rutas o estado interno.
                    t.Error = "el escaneo fallo por un error interno";
                    t.Estado = "fallido";
                }
                finally { acceso.Dispose(); }
            });

            return new { id = t.Id, rutas };
        }

        private static List<string> LeerRutas(JsonElement o)
        {
            if (!o.TryGetProperty("rutas", out JsonElement arr) || arr.ValueKind != JsonValueKind.Array)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'rutas' debe ser una lista");
            if (arr.GetArrayLength() is 0 or > MaxRutas)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "'rutas' debe tener entre 1 y " + MaxRutas + " elementos");

            var rutas = new List<string>();
            foreach (JsonElement e in arr.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.String)
                    throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "cada ruta debe ser texto");
                string r = e.GetString()!.Trim();
                string? motivo = MotivoDeRechazo(r);
                if (motivo is not null) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "ruta no valida: " + motivo);
                rutas.Add(r);
            }
            return rutas;
        }

        /// <summary>Solo rutas absolutas con letra de unidad. Nada de UNC (el servicio no toca la red), comodines ni '..'.</summary>
        internal static string? MotivoDeRechazo(string r)
        {
            if (r.Length == 0 || r.Length >= 260) return "vacia o demasiado larga";
            if (r.IndexOfAny(new[] { '*', '?', '"', '<', '>', '|', '\0' }) >= 0) return "contiene caracteres no permitidos";
            if (r.StartsWith(@"\\", StringComparison.Ordinal) || r.StartsWith("//", StringComparison.Ordinal))
                return "las rutas de red y de dispositivo (\\\\...) no se escanean desde el servicio";
            if (r.Length < 3 || !char.IsAsciiLetter(r[0]) || r[1] != ':' || (r[2] != '\\' && r[2] != '/'))
                return "debe ser una ruta absoluta con letra de unidad";
            if (r.Split('\\', '/').Any(s => s == ".." || s == ".")) return "contiene '.' o '..'";
            return null;
        }

        private Trabajo Buscar(JsonElement? p)
        {
            if (p is not { ValueKind: JsonValueKind.Object } o || !o.TryGetProperty("id", out JsonElement v) || v.ValueKind != JsonValueKind.String)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta 'id'");
            string id = v.GetString()!;
            lock (_candado)
            {
                if (id.Length == 32 && _trabajos.TryGetValue(id, out Trabajo? t)) return t;
            }
            throw new ErrorDeComando(NoExiste, "no existe ese escaneo");
        }

        public ResultadoDeEscaneo? Obtener(string id)
        {
            lock (_candado) return _trabajos.TryGetValue(id, out Trabajo? t) ? t.Resultado : null;
        }

        public async ValueTask DisposeAsync()
        {
            Trabajo[] todos;
            lock (_candado) todos = _trabajos.Values.ToArray();
            foreach (Trabajo t in todos) t.Cts.Cancel();
            // El SCM da 5 s para parar: se espera poco y no se bloquea.
            await Task.WhenAny(Task.WhenAll(todos.Select(t => t.Tarea ?? Task.CompletedTask)), Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
        }
    }
}
