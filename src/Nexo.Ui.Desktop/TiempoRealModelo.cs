using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Ui.Desktop.Nucleo;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeCarpetaVigilada(string Ruta, string Estado, IBrush Color);

    public sealed record FilaDeDeteccionEnTiempoReal(string Ruta, string Firma, string Tamano, string Cuando);

    /// <summary>
    /// La pestaña «Tiempo real». Solo lee el estado: encender, apagar o cambiar carpetas no existe en el pipe (a proposito) y la
    /// pestaña lo explica en vez de ofrecerlo. Dos acciones, las dos por caminos que ya existen:
    /// - poner en cuarentena lo detectado: vista previa del servicio con el id «tiempo-real», confirmar y token;
    /// - revisar lo que no se vio: un escaneo bajo demanda de esas carpetas (solo lee), que se sigue en la pestaña «Escaneo».
    /// Si la lectura falla, no se muestra lo anterior como si fuera actual.
    /// </summary>
    public sealed class TiempoRealModelo : INotifyPropertyChanged
    {
        private static readonly IBrush Verde = Colores.De(Indicador.Correcto);
        private static readonly IBrush Amarillo = Colores.De(Indicador.Atencion);

        private readonly IServicioDeTiempoReal _servicio;
        private readonly IServicioDeEscaneo _escaneo;
        private Consulta<DetalleDeTiempoReal>? _ultima;
        private string _mensaje = "";
        private bool _ocupado;

        public TiempoRealModelo(IServicioDeTiempoReal servicio, IServicioDeEscaneo escaneo)
        {
            _servicio = servicio;
            _escaneo = escaneo;
            Calcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>Lo ultimo que se leyo, si se pudo. Null si no se sabe.</summary>
        public DetalleDeTiempoReal? Detalle => _ultima?.Valor;

        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public string Motor { get; private set; } = "";
        public string Contadores { get; private set; } = "";
        public string UltimoAviso { get; private set; } = "";
        public string Nota { get; private set; } = "";
        public IReadOnlyList<FilaDeCarpetaVigilada> Carpetas { get; private set; } = Array.Empty<FilaDeCarpetaVigilada>();
        public IReadOnlyList<string> PorRevisar { get; private set; } = Array.Empty<string>();
        public string TextoPorRevisar { get; private set; } = "";
        public IReadOnlyList<FilaDeDeteccionEnTiempoReal> Detecciones { get; private set; } = Array.Empty<FilaDeDeteccionEnTiempoReal>();
        public string TextoDetecciones { get; private set; } = "";
        public bool PuedePonerEnCuarentena { get; private set; }
        public bool PuedeRevisar { get; private set; }

        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        /// <summary>Las carpetas que se pedirian al revisar: sin repetidas ni subcarpetas, como maximo 8 (lo que acepta el servicio).</summary>
        public IReadOnlyList<string> RutasParaRevisar() => RevisionDeLoNoVisto.RutasParaRevisar(PorRevisar);

        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_ocupado) return;
            _ocupado = true;
            try
            {
                Consulta<DetalleDeTiempoReal> c;
                try
                {
                    c = await _servicio.ConsultarAsync(ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    c = Consulta<DetalleDeTiempoReal>.Mal("error inesperado al consultar (" + ex.GetType().Name + ")");
                }
                _ultima = c;
            }
            finally
            {
                _ocupado = false;
                Calcular();
            }
        }

        /// <summary>Paso 1 de la cuarentena: que se moveria. No cambia nada.</summary>
        public async Task<Consulta<PlanDelServicio>> PrevisualizarCuarentenaAsync(CancellationToken ct = default)
        {
            if (!PuedePonerEnCuarentena) return Consulta<PlanDelServicio>.Mal("no hay detecciones del tiempo real");
            return await _escaneo.PrevisualizarCuarentenaAsync(LectorDeTiempoReal.IdDeEscaneo, ct);
        }

        /// <summary>Paso 2: aplicar el plan de ese token (con UAC por la bandeja si el servicio lo exige). Despues se vuelve a leer.</summary>
        public async Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct = default)
        {
            ResultadoDeAccion r = await _escaneo.AplicarCuarentenaAsync(token, ct);
            Mensaje = r.Mensaje;
            await ActualizarAsync(ct);
            return r;
        }

        // ------------------------------------------------------------
        private void Calcular()
        {
            (Indicador ind, string titulo, string explicacion) = ResumirTiempoReal.Desde(_ultima);
            Titulo = titulo;
            Explicacion = explicacion;
            Color = Colores.De(ind);

            DetalleDeTiempoReal? t = _ultima?.Valor;
            if (t is null)
            {
                Motor = Contadores = UltimoAviso = Nota = TextoPorRevisar = TextoDetecciones = "";
                Carpetas = Array.Empty<FilaDeCarpetaVigilada>();
                PorRevisar = Array.Empty<string>();
                Detecciones = Array.Empty<FilaDeDeteccionEnTiempoReal>();
            }
            else
            {
                Motor = !t.Activo ? "" : "Motor: " + (t.Motor ?? "sin nombre") + (t.MotorCaido ? " — NO RESPONDE" : " — responde");
                Contadores = ResumirTiempoReal.Contadores(t);
                UltimoAviso = string.IsNullOrEmpty(t.UltimoAviso) ? "" : "Último aviso: " + t.UltimoAviso;
                Nota = t.Nota ?? "";

                var noVigiladas = new HashSet<string>(t.RaicesNoVigiladas, StringComparer.OrdinalIgnoreCase);
                Carpetas = t.Raices.Select(r => noVigiladas.Contains(r)
                                    ? new FilaDeCarpetaVigilada(r, "NO vigilada", Amarillo)
                                    : new FilaDeCarpetaVigilada(r, "Vigilada", Verde))
                                .Concat(t.RaicesNoVigiladas.Where(r => !t.Raices.Contains(r, StringComparer.OrdinalIgnoreCase))
                                                           .Select(r => new FilaDeCarpetaVigilada(r, "NO vigilada", Amarillo)))
                                .ToList();

                PorRevisar = t.PorRevisar;
                int enUnaPasada = RutasParaRevisar().Count;
                TextoPorRevisar = t.PorRevisar.Count == 0 ? "Nada por revisar."
                    : (t.PorRevisar.Count == 1 ? "1 carpeta" : t.PorRevisar.Count + " carpetas")
                      + " con cambios que no se pudieron analizar (perdidos o sin analizar). No cuentan como limpias."
                      + (enUnaPasada < t.PorRevisar.Count ? " Se revisan " + enUnaPasada + " por pasada." : "");

                Detecciones = t.Detecciones
                    .Select(d => new FilaDeDeteccionEnTiempoReal(d.Ruta, d.Firma, Tamano(d.Bytes),
                                                                d.Modificado is DateTimeOffset m ? Resumir.Fecha(m) : "—"))
                    .ToList();
                TextoDetecciones = t.Detecciones.Count == 0 ? "Sin detecciones."
                    : "Los archivos no se han tocado. Siguen aquí hasta que se pongan en cuarentena.";
            }

            PuedePonerEnCuarentena = t is { Detecciones.Count: > 0 };
            PuedeRevisar = t is { PorRevisar.Count: > 0 };

            foreach (string p in new[]
                     {
                         nameof(Detalle), nameof(Titulo), nameof(Explicacion), nameof(Color), nameof(Motor), nameof(Contadores),
                         nameof(UltimoAviso), nameof(Nota), nameof(Carpetas), nameof(PorRevisar), nameof(TextoPorRevisar),
                         nameof(Detecciones), nameof(TextoDetecciones), nameof(PuedePonerEnCuarentena), nameof(PuedeRevisar)
                     })
                Avisar(p);
        }

        private static string Tamano(long b)
            => b >= 1L << 20 ? (b / (double)(1L << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MB"
             : b >= 1L << 10 ? (b / (double)(1L << 10)).ToString("0.0", CultureInfo.InvariantCulture) + " KB"
             : b + " B";

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
