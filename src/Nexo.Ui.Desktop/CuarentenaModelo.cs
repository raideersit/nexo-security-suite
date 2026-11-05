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
    public sealed record FilaDeCuarentena(string Id, string Ruta, string Firma, string Tamano, string Desde, string Vence, bool Vencido);

    /// <summary>
    /// La pestaña «Cuarentena». Listar solo lee. Restaurar y eliminar los vencidos: vista previa del servicio, confirmacion y
    /// token. El servicio NO purga solo: lo vencido se queda hasta que alguien lo elimina, y la pestaña lo dice asi.
    /// </summary>
    public sealed class CuarentenaModelo : INotifyPropertyChanged
    {
        private readonly IServicioDeCuarentena _servicio;
        private readonly Func<DateTimeOffset> _reloj;
        private IReadOnlyList<FilaDeCuarentena> _elementos = Array.Empty<FilaDeCuarentena>();
        private FilaDeCuarentena? _seleccionado;
        private string _resumen = "Sin consultar todavía.";
        private string _mensaje = "";
        private bool _ocupado;
        private bool _leida;

        public CuarentenaModelo(IServicioDeCuarentena servicio, Func<DateTimeOffset>? reloj = null)
        {
            _servicio = servicio;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public IReadOnlyList<FilaDeCuarentena> Elementos { get => _elementos; private set { _elementos = value; Avisar(); Recalcular(); } }

        public FilaDeCuarentena? Seleccionado { get => _seleccionado; set { if (_seleccionado == value) return; _seleccionado = value; Avisar(); Recalcular(); } }

        /// <summary>Si la ultima lectura salio bien. Si no, la lista esta vacia porque NO se sabe, no porque no haya nada.</summary>
        public bool Leida { get => _leida; private set { _leida = value; Avisar(); } }

        public string Resumen { get => _resumen; private set { _resumen = value; Avisar(); } }
        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        public bool PuedeRestaurar { get; private set; }
        public bool PuedeEliminarVencidos { get; private set; }

        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_ocupado) return;
            _ocupado = true;
            Recalcular();
            try
            {
                Consulta<ListaDeCuarentena> c = await _servicio.ListarAsync(ct);
                if (c.Valor is not ListaDeCuarentena l)
                {
                    // No se muestra la lista anterior como si fuera la actual.
                    Leida = false;
                    Elementos = Array.Empty<FilaDeCuarentena>();
                    Seleccionado = null;
                    Resumen = "No se pudo leer la cuarentena: " + c.Error + ".";
                    return;
                }

                DateTimeOffset ahora = _reloj();
                List<FilaDeCuarentena> filas = l.Elementos.OrderByDescending(e => e.Fecha).Select(e => Fila(e, ahora)).ToList();
                string? antes = _seleccionado?.Id;
                Leida = true;
                Elementos = filas;
                Seleccionado = filas.FirstOrDefault(f => f.Id == antes);

                long bytes = l.Elementos.Sum(e => e.Bytes);
                int vencidos = filas.Count(f => f.Vencido);
                Resumen = filas.Count == 0 ? "La cuarentena está vacía."
                    : (filas.Count == 1 ? "1 archivo" : filas.Count + " archivos") + " en cuarentena · " + Tamano(bytes)
                      + (vencidos == 0 ? "" : " · " + (vencidos == 1 ? "1 vencido" : vencidos + " vencidos") + " (se pueden eliminar)");
            }
            finally
            {
                _ocupado = false;
                Recalcular();
            }
        }

        /// <summary>Paso 1 de restaurar el seleccionado: que haria el servicio. No cambia nada.</summary>
        public async Task<Consulta<PlanDelServicio>> PrevisualizarRestauracionAsync(CancellationToken ct = default)
        {
            if (_seleccionado is null) return Consulta<PlanDelServicio>.Mal("elija un archivo de la lista");
            return await _servicio.PrevisualizarRestauracionAsync(_seleccionado.Id, ct);
        }

        public async Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct = default)
        {
            ResultadoDeAccion r = await _servicio.RestaurarAsync(token, ct);
            Mensaje = r.Mensaje;
            await ActualizarAsync(ct);
            return r;
        }

        /// <summary>Paso 1 de eliminar los vencidos: cuales serian. No cambia nada.</summary>
        public Task<Consulta<PlanDelServicio>> PrevisualizarPurgaAsync(CancellationToken ct = default) => _servicio.PrevisualizarPurgaAsync(ct);

        public async Task<ResultadoDeAccion> PurgarAsync(string token, CancellationToken ct = default)
        {
            ResultadoDeAccion r = await _servicio.PurgarAsync(token, ct);
            Mensaje = r.Mensaje;
            await ActualizarAsync(ct);
            return r;
        }

        // ------------------------------------------------------------
        private static FilaDeCuarentena Fila(ElementoDeCuarentena e, DateTimeOffset ahora)
        {
            TimeSpan falta = e.Vence - ahora;
            bool vencido = falta <= TimeSpan.Zero;
            int dias = (int)Math.Ceiling(falta.TotalDays);
            string vence = vencido ? "Vencido" : dias == 1 ? "en 1 día" : "en " + dias + " días";
            return new FilaDeCuarentena(e.Id, e.RutaOriginal, e.Firma, Tamano(e.Bytes), Resumir.Fecha(e.Fecha), vence, vencido);
        }

        private void Recalcular()
        {
            PuedeRestaurar = !_ocupado && _seleccionado is not null;
            PuedeEliminarVencidos = !_ocupado && _elementos.Any(f => f.Vencido);
            Avisar(nameof(PuedeRestaurar));
            Avisar(nameof(PuedeEliminarVencidos));
        }

        private static string Tamano(long b)
            => b >= 1L << 20 ? (b / (double)(1L << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MB"
             : b >= 1L << 10 ? (b / (double)(1L << 10)).ToString("0.0", CultureInfo.InvariantCulture) + " KB"
             : b + " B";

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
