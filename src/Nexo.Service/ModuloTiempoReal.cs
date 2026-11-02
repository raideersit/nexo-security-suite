using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Escaner;
using Nexo.Modules.Threats.TiempoReal;

namespace Nexo.Service
{
    /// <summary>
    /// El analisis en tiempo real expuesto por el pipe, SOLO DE LECTURA.
    ///
    /// No hay metodos para activarlo, desactivarlo ni cambiar que carpetas vigila: un proceso
    /// malicioso del usuario los usaria para apagar la proteccion. Se configura en
    /// appsettings.json (carpeta del servicio, que solo Administradores pueden escribir).
    ///
    /// Las detecciones se pueden llevar a cuarentena por el flujo de siempre (vista previa y
    /// token) usando el id de escaneo <see cref="IdDeEscaneo"/>.
    /// </summary>
    public sealed class ModuloTiempoReal : IModuloDelServicio, IResultadosDeEscaneo, IAsyncDisposable
    {
        /// <summary>Id "de escaneo" con el que la cuarentena ve las detecciones del tiempo real.</summary>
        public const string IdDeEscaneo = "tiempo-real";

        private readonly VigilanteEnTiempoReal _vigilante;
        private readonly IFuenteDeCambios _fuente;
        private readonly IReadOnlyList<string> _raices;
        private readonly string _motor;

        public ModuloTiempoReal(VigilanteEnTiempoReal vigilante, IFuenteDeCambios fuente, IEnumerable<string> raices, string motor)
        {
            _vigilante = vigilante;
            _fuente = fuente;
            _raices = raices.ToList();
            _motor = motor;
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { "tiempo-real.estado", "tiempo-real.detecciones" };

        public void Iniciar() => _vigilante.Iniciar(_fuente);

        // Lo que la fuente NO pudo vigilar (volumen sin permisos, carpeta inexistente...). Se pregunta en cada
        // consulta: algunas fuentes lo descubren despues de arrancar.
        private IReadOnlyList<string> NoVigiladas => (_fuente as IFuenteConCobertura)?.NoVigiladas ?? Array.Empty<string>();

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
        {
            switch (metodo)
            {
                case "tiempo-real.estado":
                {
                    EstadoDeTiempoReal e = _vigilante.Estado();
                    IReadOnlyList<string> porRevisar = CarpetasPorRevisar();
                    // «cobertura_completa» solo es verdad si no queda nada perdido o sin analizar por revisar. Los contadores
                    // son historicos; lo que se reviso con un escaneo completo deja de contar (ver EscaneoCompleto).
                    bool completa = e.Activo && !e.MotorCaido && NoVigiladas.Count == 0 && porRevisar.Count == 0;
                    return Task.FromResult<object?>(new
                    {
                        activo = e.Activo,
                        cobertura_completa = completa,
                        raices = _raices,
                        raices_no_vigiladas = NoVigiladas,
                        motor = _motor,
                        motor_caido = e.MotorCaido,
                        cambios_vistos = e.CambiosVistos,
                        analizados = e.Analizados,
                        no_analizados = e.NoAnalizados,
                        perdidos = e.Perdidos,
                        perdidos_es_minimo = e.PerdidosEsMinimo,
                        desbordes_de_fuente = e.DesbordesDeFuente,
                        por_revisar = porRevisar,
                        descartados = e.Descartados,
                        pendientes = e.Pendientes,
                        detecciones = e.Detecciones,
                        ultimo_aviso = e.UltimoAviso,
                        // Siempre presente: no se promete lo que el modo usuario no puede dar.
                        nota = "Detecta y avisa DESPUES de que el archivo se escribe; no puede impedir que se cree ni que se ejecute."
                    });
                }

                case "tiempo-real.detecciones":
                    return Task.FromResult<object?>(new
                    {
                        id_escaneo = IdDeEscaneo,
                        detecciones = _vigilante.Detecciones().Select(d => new
                        {
                            ruta = d.Ruta, firma = d.Firma, bytes = d.Bytes, sha256 = d.Sha256, modificado = d.Modificado
                        }).ToList()
                    });

                default:
                    throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            }
        }

        /// <summary>Carpetas a revisar con un escaneo bajo demanda; si se perdieron eventos sin carpeta conocida, las raices.</summary>
        private IReadOnlyList<string> CarpetasPorRevisar()
        {
            PorRevisar p = _vigilante.CarpetasPorRevisar();
            return p.Todo ? _raices.Union(p.Carpetas, StringComparer.OrdinalIgnoreCase).ToList() : p.Carpetas;
        }

        /// <summary>Un escaneo bajo demanda COMPLETO termino: lo que cubrio deja de estar por revisar.</summary>
        public void EscaneoCompleto(IReadOnlyList<string> rutas, DateTimeOffset inicio, ResultadoDeEscaneo r)
        {
            bool todas = _raices.All(raiz => rutas.Any(x => VigilanteEnTiempoReal.Contiene(x, raiz)));
            _vigilante.MarcarRevisado(rutas, r.CarpetasNoLeidas, todas, inicio);
        }

        public ResultadoDeEscaneo? Obtener(string id)
        {
            if (id != IdDeEscaneo) return null;
            IReadOnlyList<Deteccion> d = _vigilante.Detecciones();
            return new ResultadoDeEscaneo(_motor, "tiempo-real", (int)Math.Min(int.MaxValue, _vigilante.Estado().Analizados), d, Array.Empty<string>(),
                                          TimeSpan.Zero, incompleto: false, motivoIncompleto: null);
        }

        public ValueTask DisposeAsync()
        {
            _vigilante.Dispose();
            return ValueTask.CompletedTask;
        }

        /// <summary>Carpetas donde llegan los archivos nuevos: Descargas, Escritorio y Temp de cada perfil, mas Temp del sistema.</summary>
        public static IReadOnlyList<string> RaicesPorDefecto()
        {
            var r = new List<string>();
            string? sistema = Environment.GetEnvironmentVariable("SystemRoot");
            string unidad = Path.GetPathRoot(sistema ?? Environment.SystemDirectory) ?? @"C:\";
            string usuarios = Path.Combine(unidad, "Users");

            if (Directory.Exists(usuarios))
            {
                foreach (string perfil in SafeDirs(usuarios))
                {
                    string nombre = Path.GetFileName(perfil);
                    if (nombre.Equals("Default", StringComparison.OrdinalIgnoreCase) || nombre.Equals("Default User", StringComparison.OrdinalIgnoreCase)
                        || nombre.Equals("All Users", StringComparison.OrdinalIgnoreCase)) continue;
                    r.Add(Path.Combine(perfil, "Downloads"));
                    r.Add(Path.Combine(perfil, "Desktop"));
                    r.Add(Path.Combine(perfil, "AppData", "Local", "Temp"));
                }
            }
            if (sistema is not null) r.Add(Path.Combine(sistema, "Temp"));
            return r.Where(Directory.Exists).ToList();
        }

        private static IEnumerable<string> SafeDirs(string d)
        {
            try { return Directory.GetDirectories(d); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return Array.Empty<string>(); }
        }
    }

    /// <summary>Lo que contesta el servicio cuando el tiempo real esta apagado: que la interfaz pueda decirlo claramente.</summary>
    public sealed class ModuloTiempoRealApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "tiempo-real.estado", "tiempo-real.detecciones" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo switch
            {
                "tiempo-real.estado" => Task.FromResult<object?>(new
                {
                    activo = false,
                    cobertura_completa = false,
                    nota = "El analisis en tiempo real esta apagado. Se activa en appsettings.json (Nexo:TiempoReal:Activo)."
                }),
                "tiempo-real.detecciones" => Task.FromResult<object?>(new { id_escaneo = ModuloTiempoReal.IdDeEscaneo, detecciones = Array.Empty<object>() }),
                _ => throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido")
            };
    }

    /// <summary>Busca el resultado de un escaneo en varias fuentes (los escaneos bajo demanda y el tiempo real).</summary>
    public sealed class ResultadosCombinados : IResultadosDeEscaneo
    {
        private readonly IReadOnlyList<IResultadosDeEscaneo> _fuentes;
        public ResultadosCombinados(params IResultadosDeEscaneo[] fuentes) => _fuentes = fuentes;

        public ResultadoDeEscaneo? Obtener(string id)
            => _fuentes.Select(f => f.Obtener(id)).FirstOrDefault(r => r is not null);
    }
}
