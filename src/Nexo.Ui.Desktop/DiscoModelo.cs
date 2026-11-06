using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeDisco(
        string Modelo,
        string Serie,
        string Estado,
        IBrush Color,
        string Detalle,
        string Temperatura,
        string Desgaste,
        string Horas,
        IReadOnlyList<string> Alertas,
        string Limitaciones,
        bool HayLimitaciones);

    /// <summary>
    /// La pestaña «Disco». Muestra lo que el servicio leyo (no lee los discos al consultar) y permite pedir una lectura nueva,
    /// que solo lee y que el servicio limita a una cada 5 minutos. Si no se puede consultar, no muestra lo anterior.
    /// </summary>
    public sealed class DiscoModelo : INotifyPropertyChanged
    {
        private readonly IServicioDeDisco _servicio;
        private Consulta<EstadoDeDiscos>? _ultima;
        private string _mensaje = "";
        private bool _ocupado;

        public DiscoModelo(IServicioDeDisco servicio)
        {
            _servicio = servicio;
            Calcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public EstadoDeDiscos? Estado => _ultima?.Valor;
        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public string Lectura { get; private set; } = "";
        public string Advertencia { get; private set; } = "";
        public IReadOnlyList<FilaDeDisco> Discos { get; private set; } = Array.Empty<FilaDeDisco>();
        public bool PuedeLeer { get; private set; }

        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_ocupado) return;
            _ocupado = true;
            try
            {
                try
                {
                    _ultima = await _servicio.EstadoAsync(ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _ultima = Consulta<EstadoDeDiscos>.Mal("error inesperado al consultar (" + ex.GetType().Name + ")");
                }
            }
            finally
            {
                _ocupado = false;
                Calcular();
            }
        }

        /// <summary>Pide al servicio que vuelva a leer los discos (en segundo plano). El resultado llega en las siguientes consultas.</summary>
        public async Task PedirLecturaAsync(CancellationToken ct = default)
        {
            if (!PuedeLeer) return;
            Consulta<PedidoDeLectura> p = await _servicio.PedirLecturaAsync(ct);
            Mensaje = p.Valor is not PedidoDeLectura v ? "No se pudo pedir la lectura: " + p.Error + "."
                    : v.Iniciada ? "Leyendo los discos... el resultado aparece aquí en unos segundos."
                    : "No se volvió a leer: " + v.Motivo + ".";
            await ActualizarAsync(ct);
        }

        // ------------------------------------------------------------
        private void Calcular()
        {
            (Indicador ind, string estado, string detalle) = ResumirDisco.General(_ultima);
            Titulo = estado;
            Explicacion = detalle;
            Color = Colores.De(ind);

            EstadoDeDiscos? s = _ultima?.Valor;
            if (s is null)
            {
                Lectura = Advertencia = "";
                Discos = Array.Empty<FilaDeDisco>();
            }
            else
            {
                var partes = new List<string>();
                if (s.Leyendo) partes.Add("Leyendo los discos ahora...");
                if (s.UltimaLectura is DateTimeOffset u) partes.Add("Última lectura: " + Resumir.Fecha(u));
                if (s.ProximaLectura is DateTimeOffset p && s.Estado != "apagado") partes.Add("próxima: " + Resumir.Fecha(p));
                Lectura = string.Join(" · ", partes);
                Advertencia = s.AdvertenciaDeHistorial is { Length: > 0 } a
                    ? "Historial: " + a + " Sin historial no se puede saber si un contador está aumentando."
                    : "";

                Discos = s.Discos.Select(d =>
                {
                    (Indicador i, string e, string det) = ResumirDisco.Disco(d);
                    return new FilaDeDisco(
                        d.Modelo, d.Serie, e, Colores.De(i), det,
                        ResumirDisco.Temperatura(d), ResumirDisco.Desgaste(d), ResumirDisco.Horas(d),
                        d.Alertas.Select(x => "• " + x).ToList(),
                        d.Limitaciones.Count == 0 ? "" : "Limitaciones: " + string.Join(" ", d.Limitaciones),
                        d.Limitaciones.Count > 0);
                }).ToList();
            }

            PuedeLeer = s is not null && !s.Leyendo && s.Estado != "apagado";

            foreach (string n in new[]
                     {
                         nameof(Estado), nameof(Titulo), nameof(Explicacion), nameof(Color), nameof(Lectura), nameof(Advertencia),
                         nameof(Discos), nameof(PuedeLeer)
                     })
                Avisar(n);
        }

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
