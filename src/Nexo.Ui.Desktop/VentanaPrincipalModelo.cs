using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Ui.Desktop.Nucleo;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaVista(string Modulo, string Estado, string Detalle, IBrush Color);

    /// <summary>Lo que enlaza la ventana. Consulta la fuente, pasa el resultado por ModeloDeBandeja y lo resume.</summary>
    public sealed class VentanaPrincipalModelo : INotifyPropertyChanged
    {
        private readonly IFuenteDeEstado _fuente;
        private readonly Func<DateTime> _reloj;
        private readonly ModeloDeBandeja _modelo = new ModeloDeBandeja();
        private bool _consultando;

        private string _titulo = "Consultando al servicio...";
        private string _detalle = "";
        private IBrush _color = Colores.De(Indicador.SinDatos);
        private IReadOnlyList<FilaVista> _modulos = Array.Empty<FilaVista>();
        private string _barraServicio = "Servicio: consultando...";
        private string _barraTiempoReal = "Tiempo real: sin datos";
        private string _barraMotor = "Motor clamd: sin datos";
        private string _barraConsulta = "Sin consultar todavía";

        public VentanaPrincipalModelo(IFuenteDeEstado fuente, Func<DateTime>? reloj = null)
        {
            _fuente = fuente;
            _reloj = reloj ?? (() => DateTime.Now);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string Titulo { get => _titulo; private set => Poner(ref _titulo, value); }
        public string Detalle { get => _detalle; private set => Poner(ref _detalle, value); }
        public IBrush ColorDeEstado { get => _color; private set => Poner(ref _color, value); }
        public IReadOnlyList<FilaVista> Modulos { get => _modulos; private set => Poner(ref _modulos, value); }
        public string BarraServicio { get => _barraServicio; private set => Poner(ref _barraServicio, value); }
        public string BarraTiempoReal { get => _barraTiempoReal; private set => Poner(ref _barraTiempoReal, value); }
        public string BarraMotor { get => _barraMotor; private set => Poner(ref _barraMotor, value); }
        public string BarraConsulta { get => _barraConsulta; private set => Poner(ref _barraConsulta, value); }

        /// <summary>El ultimo resumen calculado (para las pruebas).</summary>
        public ResumenDeEstado? Resumen { get; private set; }

        /// <summary>Una consulta. Si ya hay una en curso no lanza otra (el temporizador puede adelantarse a un servicio lento).</summary>
        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_consultando) return;
            _consultando = true;
            try
            {
                EstadoCompleto e;
                try
                {
                    e = await _fuente.ConsultarAsync(ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // La ventana no se cae por una consulta: lo que no se supo se muestra como «sin conexion».
                    e = EstadoCompleto.SinConexion(
                        InstantaneaDelServicio.SinConexion("error inesperado al consultar (" + ex.GetType().Name + ")"));
                }

                _modelo.Actualizar(e.Servicio);
                Aplicar(Resumir.Desde(_modelo, e));
                BarraConsulta = "Última consulta: " + _reloj().ToString("HH:mm:ss");
            }
            finally
            {
                _consultando = false;
            }
        }

        private void Aplicar(ResumenDeEstado r)
        {
            Resumen = r;
            Titulo = r.Titulo;
            Detalle = r.Detalle;
            ColorDeEstado = Colores.De(r.Indicador);
            Modulos = r.Modulos.Select(f => new FilaVista(f.Modulo, f.Estado, f.Detalle, Colores.De(f.Indicador))).ToList();
            BarraServicio = r.BarraServicio;
            BarraTiempoReal = r.BarraTiempoReal;
            BarraMotor = r.BarraMotor;
        }

        private void Poner<T>(ref T campo, T valor, [CallerMemberName] string? nombre = null)
        {
            if (EqualityComparer<T>.Default.Equals(campo, valor)) return;
            campo = valor;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
        }
    }

    internal static class Colores
    {
        // Los colores de la paleta de 16 de Windows 9x.
        private static readonly IBrush Verde = new SolidColorBrush(Color.Parse("#00A000"));
        private static readonly IBrush Amarillo = new SolidColorBrush(Color.Parse("#FFFF00"));
        private static readonly IBrush Rojo = new SolidColorBrush(Color.Parse("#FF0000"));
        private static readonly IBrush Gris = new SolidColorBrush(Color.Parse("#C0C0C0"));

        public static IBrush De(Indicador i) => i switch
        {
            Indicador.Correcto => Verde,
            Indicador.Atencion => Amarillo,
            Indicador.Alerta => Rojo,
            _ => Gris
        };
    }
}
