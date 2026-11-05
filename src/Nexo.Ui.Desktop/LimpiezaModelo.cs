using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    /// <summary>Una regla con su casilla. Cambiar la casilla invalida la vista previa (ya no es lo que se previsualizo).</summary>
    public sealed class FilaDeReglaDeLimpieza : INotifyPropertyChanged
    {
        private readonly Action _alCambiar;
        private bool _marcada;

        public FilaDeReglaDeLimpieza(ReglaDeLimpiezaVista r, Action alCambiar)
        {
            Id = r.Id;
            Nombre = r.Nombre;
            Detalle = r.Categoria + " · riesgo " + r.Riesgo.ToLowerInvariant() + (r.RequiereAdmin ? " · requiere administrador" : "");
            _marcada = r.ActivaPorDefecto;
            _alCambiar = alCambiar;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string Id { get; }
        public string Nombre { get; }
        public string Detalle { get; }

        public bool Marcada
        {
            get => _marcada;
            set
            {
                if (_marcada == value) return;
                _marcada = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Marcada)));
                _alCambiar();
            }
        }
    }

    public sealed record FilaDeCategoria(string Categoria, string Archivos, string Tamano);

    /// <summary>
    /// La pestaña «Limpieza». Tres pasos: elegir reglas, «Vista previa» (el servicio recorre y dice que borraria; no borra) y
    /// «Limpiar» (solo con una vista previa vigente y escribiendo BORRAR). Si se cambia la seleccion despues de la vista previa,
    /// esa vista previa ya no vale y hay que pedir otra: nunca se limpia algo distinto de lo que se ve en pantalla.
    /// </summary>
    public sealed class LimpiezaModelo : INotifyPropertyChanged
    {
        public const string PalabraDeConfirmacion = "BORRAR";

        private readonly IServicioDeLimpieza _servicio;
        private readonly Func<DateTimeOffset> _reloj;
        private IReadOnlyList<FilaDeReglaDeLimpieza> _reglas = Array.Empty<FilaDeReglaDeLimpieza>();
        private CatalogoDeLimpieza? _catalogo;
        private VistaDeLimpieza? _vista;
        private string _confirmacion = "";
        private string _mensaje = "";
        private bool _ocupado;

        public LimpiezaModelo(IServicioDeLimpieza servicio, Func<DateTimeOffset>? reloj = null)
        {
            _servicio = servicio;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            Recalcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public IReadOnlyList<FilaDeReglaDeLimpieza> Reglas { get => _reglas; private set { _reglas = value; Avisar(); } }
        public VistaDeLimpieza? Vista => _vista;

        public string Confirmacion { get => _confirmacion; set { if (_confirmacion == value) return; _confirmacion = value; Avisar(); Recalcular(); } }
        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        public string TextoModo { get; private set; } = "";
        public bool ModoPermanente { get; private set; }
        public bool CatalogoLeido { get; private set; }
        public string TituloVista { get; private set; } = "";
        public string DetalleVista { get; private set; } = "";
        public IReadOnlyList<FilaDeCategoria> Categorias { get; private set; } = Array.Empty<FilaDeCategoria>();
        public IReadOnlyList<string> Ejemplos { get; private set; } = Array.Empty<string>();
        public IReadOnlyList<string> Avisos { get; private set; } = Array.Empty<string>();
        public bool HayAvisos { get; private set; }
        public bool PuedePrevisualizar { get; private set; }
        public bool PuedeLimpiar { get; private set; }
        public bool PuedeEscribirConfirmacion { get; private set; }
        public string TextoBotonLimpiar { get; private set; } = "Limpiar";

        public async Task CargarReglasAsync(CancellationToken ct = default)
        {
            if (_ocupado || CatalogoLeido) return;
            _ocupado = true;
            Recalcular();
            try
            {
                Consulta<CatalogoDeLimpieza> c = await _servicio.ReglasAsync(ct);
                if (c.Valor is not CatalogoDeLimpieza cat)
                {
                    Mensaje = "No se pudo leer el catálogo de limpieza: " + c.Error + ".";
                    return;
                }
                _catalogo = cat;
                CatalogoLeido = true;
                Reglas = cat.Reglas.Select(r => new FilaDeReglaDeLimpieza(r, () => { Invalidar(); Recalcular(); })).ToList();
                Mensaje = "";
            }
            finally
            {
                _ocupado = false;
                Recalcular();
            }
        }

        public async Task PrevisualizarAsync(CancellationToken ct = default)
        {
            if (!PuedePrevisualizar) return;
            List<string> ids = _reglas.Where(r => r.Marcada).Select(r => r.Id).ToList();
            if (ids.Count == 0) { Mensaje = "Marque al menos una categoría."; return; }

            _ocupado = true;
            _vista = null;
            Confirmacion = "";
            Mensaje = "Buscando lo que se puede limpiar... (no se borra nada)";
            Recalcular();
            try
            {
                Consulta<VistaDeLimpieza> c = await _servicio.PrevisualizarAsync(ids, ct);
                if (c.Valor is null) Mensaje = "No se pudo preparar la vista previa: " + c.Error + ".";
                else { _vista = c.Valor; Mensaje = ""; }
            }
            finally
            {
                _ocupado = false;
                Recalcular();
            }
        }

        /// <summary>Solo con la vista previa vigente y BORRAR escrito. El token es de un solo uso: despues hay que previsualizar otra vez.</summary>
        public async Task<ResultadoDeAccion?> LimpiarAsync(CancellationToken ct = default)
        {
            if (!PuedeLimpiar || _vista?.Token is not string token) return null;
            if (_vista.Expira is DateTimeOffset e && e <= _reloj())
            {
                Invalidar();
                Mensaje = "La vista previa caducó: pida otra.";
                return null;
            }

            _ocupado = true;
            Recalcular();
            try
            {
                ResultadoDeAccion r = await _servicio.AplicarAsync(token, ct);
                Mensaje = r.Mensaje;
                // Se gasto (o el servicio lo rechazo): en cualquier caso esta vista previa ya no sirve.
                _vista = null;
                _confirmacion = "";
                Avisar(nameof(Confirmacion));
                return r;
            }
            finally
            {
                _ocupado = false;
                Recalcular();
            }
        }

        // ------------------------------------------------------------
        private void Invalidar()
        {
            if (_vista is null) return;
            _vista = null;
            _confirmacion = "";
            Avisar(nameof(Confirmacion));
            Mensaje = "Cambió la selección: pida una vista previa nueva.";
            Recalcular();
        }

        private void Recalcular()
        {
            TextoModo = _catalogo is null ? "" : "Modo del servicio: " + LectorDeLimpieza.Modo(_catalogo.Modo) + ".";
            ModoPermanente = _catalogo?.Modo == "borrado-permanente";
            PuedePrevisualizar = !_ocupado && CatalogoLeido && _reglas.Any(r => r.Marcada);

            VistaDeLimpieza? v = _vista;
            bool hayAlgo = v is { TotalArchivos: > 0, Token: not null };
            PuedeEscribirConfirmacion = !_ocupado && hayAlgo;
            PuedeLimpiar = PuedeEscribirConfirmacion && string.Equals(_confirmacion.Trim(), PalabraDeConfirmacion, StringComparison.Ordinal);
            TextoBotonLimpiar = _catalogo?.Modo switch
            {
                "papelera" => "Mover a la Papelera",
                "simulado" => "Simular limpieza",
                "borrado-permanente" => "Borrar para siempre",
                _ => "Limpiar"
            };

            if (v is null)
            {
                TituloVista = CatalogoLeido ? "Marque qué limpiar y pulse «Vista previa»." : "";
                DetalleVista = CatalogoLeido ? "La vista previa no borra nada." : "";
                Categorias = Array.Empty<FilaDeCategoria>();
                Ejemplos = Array.Empty<string>();
                Avisos = Array.Empty<string>();
            }
            else
            {
                TituloVista = v.TotalArchivos == 0 ? "No hay nada que limpiar en lo marcado."
                    : "Se liberarían " + Tamano(v.TotalBytes) + " (" + Archivos(v.TotalArchivos) + ").";
                DetalleVista = v.TotalArchivos == 0 ? ""
                    : "Todavía no se ha borrado nada." + (v.Expira is DateTimeOffset e
                        ? " Esta vista previa vale hasta las " + e.ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture) + "." : "");
                Categorias = v.Categorias.Select(c => new FilaDeCategoria(c.Categoria, c.Archivos.ToString(CultureInfo.InvariantCulture), Tamano(c.Bytes))).ToList();
                Ejemplos = v.Ejemplos.Select(x => Tamano(x.Bytes).PadLeft(9) + "  " + x.Ruta).ToList();
                var avisos = new List<string>();
                if (v.OmitidasTotal > 0)
                    avisos.Add((v.OmitidasTotal == 1 ? "1 archivo se omitirá" : v.OmitidasTotal + " archivos se omitirán")
                               + " (en uso o sin permiso)" + (v.Omitidas.Count < v.OmitidasTotal ? "; se muestran " + v.Omitidas.Count : "") + ".");
                avisos.AddRange(v.Omitidas.Select(o => "  " + o));
                avisos.AddRange(v.ReglasSinPermisos.Select(r => "Sin permisos para evaluar: " + r + " (necesita administrador)."));
                Avisos = avisos;
            }
            HayAvisos = Avisos.Count > 0;

            foreach (string p in new[]
                     {
                         nameof(TextoModo), nameof(ModoPermanente), nameof(CatalogoLeido), nameof(PuedePrevisualizar), nameof(PuedeLimpiar),
                         nameof(PuedeEscribirConfirmacion), nameof(TextoBotonLimpiar), nameof(TituloVista), nameof(DetalleVista),
                         nameof(Categorias), nameof(Ejemplos), nameof(Avisos), nameof(HayAvisos), nameof(Vista)
                     })
                Avisar(p);
        }

        private static string Archivos(int n) => n == 1 ? "1 archivo" : n.ToString(CultureInfo.InvariantCulture) + " archivos";

        private static string Tamano(long b)
            => b >= 1L << 30 ? (b / (double)(1L << 30)).ToString("0.0", CultureInfo.InvariantCulture) + " GB"
             : b >= 1L << 20 ? (b / (double)(1L << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MB"
             : b >= 1L << 10 ? (b / (double)(1L << 10)).ToString("0.0", CultureInfo.InvariantCulture) + " KB"
             : b + " B";

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
