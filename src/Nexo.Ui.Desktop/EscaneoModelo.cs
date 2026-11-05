using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public enum DestinoDeEscaneo
    {
        Usuario,
        Descargas,
        Unidad,
        Otra
    }

    public sealed record FilaDeDeteccion(string Ruta, string Firma, string Tamano);

    /// <summary>
    /// La pestaña «Escaneo». Escanear solo lee; el servicio decide que se puede escanear (y lo hace con la identidad del
    /// usuario). Poner en cuarentena se pide aparte: vista previa (no cambia nada) y despues aplicar con el token.
    /// </summary>
    public sealed class EscaneoModelo : INotifyPropertyChanged
    {
        /// <summary>Cuantas consultas de avance seguidas pueden fallar antes de dejar de seguir el escaneo.</summary>
        public const int FallosDeAvanceTolerados = 5;

        private readonly IServicioDeEscaneo _servicio;
        private DestinoDeEscaneo _destino = DestinoDeEscaneo.Descargas;
        private string _rutaOtra = "";
        private int _paralelo = 4;
        private FaseDeEscaneo _fase = FaseDeEscaneo.Listo;
        private string? _id;
        private int _analizados;
        private int _fallosDeAvance;
        private ResultadoDeEscaneoVista? _resultado;
        private string? _error;
        private string _mensaje = "";
        private bool _ocupado;

        public EscaneoModelo(IServicioDeEscaneo servicio, string? carpetaDeUsuario = null, string? unidadDelSistema = null)
        {
            _servicio = servicio;
            RutaUsuario = carpetaDeUsuario ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            RutaDescargas = Path.Combine(RutaUsuario, "Downloads");
            RutaUnidad = unidadDelSistema ?? Path.GetPathRoot(Environment.SystemDirectory) ?? Path.GetPathRoot(RutaUsuario) ?? "";
            Actualizar();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string RutaUsuario { get; }
        public string RutaDescargas { get; }
        public string RutaUnidad { get; }
        public IReadOnlyList<int> OpcionesDeParalelo { get; } = new[] { 1, 2, 4, 8 };

        public string TextoUsuario => "Carpeta del usuario (" + RutaUsuario + ")";
        public string TextoDescargas => "Descargas (" + RutaDescargas + ")";
        public string TextoUnidad => "Unidad completa (" + RutaUnidad + ")";

        public bool DestinoUsuario { get => _destino == DestinoDeEscaneo.Usuario; set { if (value) Destino = DestinoDeEscaneo.Usuario; } }
        public bool DestinoDescargas { get => _destino == DestinoDeEscaneo.Descargas; set { if (value) Destino = DestinoDeEscaneo.Descargas; } }
        public bool DestinoUnidad { get => _destino == DestinoDeEscaneo.Unidad; set { if (value) Destino = DestinoDeEscaneo.Unidad; } }
        public bool DestinoOtra { get => _destino == DestinoDeEscaneo.Otra; set { if (value) Destino = DestinoDeEscaneo.Otra; } }

        public DestinoDeEscaneo Destino
        {
            get => _destino;
            set
            {
                if (_destino == value) return;
                _destino = value;
                Avisar(nameof(DestinoUsuario)); Avisar(nameof(DestinoDescargas)); Avisar(nameof(DestinoUnidad)); Avisar(nameof(DestinoOtra));
                Avisar();
            }
        }

        public string RutaOtra { get => _rutaOtra; set { if (_rutaOtra == value) return; _rutaOtra = value; Avisar(); } }
        public int Paralelo { get => _paralelo; set { if (_paralelo == value) return; _paralelo = value; Avisar(); } }

        public FaseDeEscaneo Fase => _fase;
        public string? IdDeEscaneo => _id;
        public ResultadoDeEscaneoVista? Resultado => _resultado;

        public bool PuedeIniciar { get; private set; }
        public bool PuedeCancelar { get; private set; }
        public bool PuedePonerEnCuarentena { get; private set; }
        public bool EnCurso { get; private set; }
        public string TextoDeAvance { get; private set; } = "";
        public string Titulo { get; private set; } = "";
        public string Detalle { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public IReadOnlyList<FilaDeDeteccion> Detecciones { get; private set; } = Array.Empty<FilaDeDeteccion>();
        public IReadOnlyList<string> Omitidos { get; private set; } = Array.Empty<string>();
        public string TextoOmitidos { get; private set; } = "";
        public bool HayOmitidos { get; private set; }

        /// <summary>Lo ultimo que paso fuera del flujo normal (un rechazo del servicio, una accion). Vacio si nada.</summary>
        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        /// <summary>Las rutas que se pedirian ahora, o null y el motivo si no hay ninguna valida.</summary>
        public (IReadOnlyList<string>? Rutas, string? Motivo) RutasElegidas()
        {
            string r = _destino switch
            {
                DestinoDeEscaneo.Usuario => RutaUsuario,
                DestinoDeEscaneo.Descargas => RutaDescargas,
                DestinoDeEscaneo.Unidad => RutaUnidad,
                _ => _rutaOtra.Trim()
            };
            // El servicio valida de verdad (rutas absolutas y locales); aqui solo se evita mandar algo vacio.
            return string.IsNullOrWhiteSpace(r) ? (null, "escriba o elija la carpeta que quiere analizar") : (new[] { r }, null);
        }

        public async Task IniciarAsync(CancellationToken ct = default)
        {
            if (!PuedeIniciar) return;
            (IReadOnlyList<string>? rutas, string? motivo) = RutasElegidas();
            if (rutas is null) { Mensaje = "No se puede iniciar: " + motivo + "."; return; }

            _fase = FaseDeEscaneo.Iniciando;
            _id = null; _resultado = null; _error = null; _analizados = 0; _fallosDeAvance = 0;
            Mensaje = "";
            Actualizar();

            Consulta<string> c = await _servicio.IniciarAsync(rutas, _paralelo, ct);
            if (c.Valor is null)
            {
                _fase = FaseDeEscaneo.Listo;
                Mensaje = "No se pudo iniciar: " + c.Error + ".";
            }
            else
            {
                _id = c.Valor;
                _fase = FaseDeEscaneo.Corriendo;
            }
            Actualizar();
        }

        /// <summary>Lo llama un temporizador. Solo hace algo mientras hay un escaneo corriendo; no se solapa consigo mismo.</summary>
        public async Task SondearAsync(CancellationToken ct = default)
        {
            if (_fase != FaseDeEscaneo.Corriendo || _id is null || _ocupado) return;
            _ocupado = true;
            try
            {
                Consulta<AvanceDeEscaneo> a = await _servicio.AvanceAsync(_id, ct);
                if (a.Valor is null)
                {
                    // Un fallo suelto no corta: el escaneo sigue en el servicio. Varios seguidos, si.
                    if (++_fallosDeAvance >= FallosDeAvanceTolerados)
                    {
                        _fase = FaseDeEscaneo.Fallido;
                        _error = "se perdió el contacto con el servicio (" + a.Error + "); el escaneo puede seguir allí";
                    }
                    else Mensaje = "No se pudo consultar el avance: " + a.Error + ". Se reintenta.";
                    Actualizar();
                    return;
                }

                _fallosDeAvance = 0;
                Mensaje = "";
                _analizados = a.Valor.Analizados;
                if (a.Valor.Estado == "corriendo") { Actualizar(); return; }

                if (a.Valor.Estado == "cancelado") _fase = FaseDeEscaneo.Cancelado;
                else if (a.Valor.Estado == "fallido") { _fase = FaseDeEscaneo.Fallido; _error = a.Valor.Error; }
                else
                {
                    Consulta<ResultadoDeEscaneoVista> r = await _servicio.ResultadoAsync(_id, ct);
                    if (r.Valor is { Listo: true })
                    {
                        _resultado = r.Valor;
                        _analizados = r.Valor.Analizados;
                        _fase = FaseDeEscaneo.Terminado;
                    }
                    else
                    {
                        // Termino pero no hay resultado que mostrar: no se presenta como limpio.
                        _fase = FaseDeEscaneo.Fallido;
                        _error = r.Error ?? r.Valor?.Error ?? "terminó sin resultado";
                    }
                }
                Actualizar();
            }
            finally
            {
                _ocupado = false;
            }
        }

        public async Task CancelarAsync(CancellationToken ct = default)
        {
            if (_fase != FaseDeEscaneo.Corriendo || _id is null) return;
            Consulta<string> c = await _servicio.CancelarAsync(_id, ct);
            // El estado final lo dice el siguiente sondeo (puede haber terminado justo antes).
            Mensaje = c.Valor is null ? "No se pudo cancelar: " + c.Error + "." : "Cancelando...";
        }

        /// <summary>Paso 1 de la cuarentena: que se moveria. No cambia nada.</summary>
        public async Task<Consulta<PlanDeCuarentena>> PrevisualizarCuarentenaAsync(CancellationToken ct = default)
        {
            if (!PuedePonerEnCuarentena || _id is null) return Consulta<PlanDeCuarentena>.Mal("no hay detecciones de un escaneo terminado");
            return await _servicio.PrevisualizarCuarentenaAsync(_id, ct);
        }

        /// <summary>Paso 2: aplicar el plan de ese token. Puede abrir el aviso de aprobacion (UAC) a traves de la bandeja.</summary>
        public async Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct = default)
        {
            ResultadoDeAccion r = await _servicio.AplicarCuarentenaAsync(token, ct);
            Mensaje = r.Mensaje;
            return r;
        }

        // ------------------------------------------------------------
        private void Actualizar()
        {
            EnCurso = _fase is FaseDeEscaneo.Iniciando or FaseDeEscaneo.Corriendo;
            PuedeIniciar = !EnCurso;
            PuedeCancelar = _fase == FaseDeEscaneo.Corriendo;
            PuedePonerEnCuarentena = _fase == FaseDeEscaneo.Terminado && _resultado is { Detecciones.Count: > 0 };
            TextoDeAvance = _fase switch
            {
                FaseDeEscaneo.Iniciando => "Pidiendo el escaneo al servicio...",
                FaseDeEscaneo.Corriendo => "Analizados: " + _analizados.ToString(CultureInfo.InvariantCulture) + " archivos",
                FaseDeEscaneo.Listo => "Sin escaneo en curso.",
                _ => "Analizados: " + _analizados.ToString(CultureInfo.InvariantCulture) + " archivos"
            };

            (Indicador ind, string titulo, string detalle) = ResumirEscaneo.Desde(_fase, _analizados, _resultado, _error);
            Titulo = titulo;
            Detalle = detalle;
            Color = Colores.De(ind);

            Detecciones = (_resultado?.Detecciones ?? Array.Empty<DeteccionDeEscaneo>())
                .Select(d => new FilaDeDeteccion(d.Ruta, d.Firma, Tamano(d.Bytes))).ToList();
            Omitidos = _resultado?.Omitidos ?? Array.Empty<string>();
            int total = _resultado?.OmitidosTotal ?? 0;
            HayOmitidos = total > 0;
            TextoOmitidos = total == 0 ? ""
                : Omitidos.Count < total ? "Sin analizar (se muestran " + Omitidos.Count + " de " + total + "; la lista completa está en el vault):"
                : "Sin analizar (" + total + "):";

            foreach (string p in new[]
                     {
                         nameof(Fase), nameof(IdDeEscaneo), nameof(Resultado), nameof(EnCurso), nameof(PuedeIniciar), nameof(PuedeCancelar),
                         nameof(PuedePonerEnCuarentena), nameof(TextoDeAvance), nameof(Titulo), nameof(Detalle), nameof(Color),
                         nameof(Detecciones), nameof(Omitidos), nameof(TextoOmitidos), nameof(HayOmitidos)
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
