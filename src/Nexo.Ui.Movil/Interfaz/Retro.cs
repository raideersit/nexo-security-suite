using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Ui.Movil.Interfaz;

/// <summary>
/// Piezas del estilo «Classic tactil»: biseles y gris de Windows clasico, pero con objetivos de 48 px o mas, letra de 16 px y lo importante arriba.
/// Medidas de las maquetas aprobadas: mosaicos de 132 px, filas de 60 px, interruptores de 72x44.
/// </summary>
public static class Retro
{
    public static readonly IBrush Rojo = new SolidColorBrush(Color.Parse("#9B1C1C"));
    public static readonly IBrush Verde = new SolidColorBrush(Color.Parse("#0B5B0B"));
    public static readonly IBrush Gris = new SolidColorBrush(Color.Parse("#404040"));
    public static readonly IBrush GrisClaro = new SolidColorBrush(Color.Parse("#808080"));

    public const double Cuerpo = 16, Secundario = 14, Titulo = 18, AlturaMinima = 48;

    // Iconos en una cuadricula de 32x32 (los mismos de las maquetas).
    public const string IconoEscudo = "M16 3 L27 7 V15 C27 22 22 27 16 29 C10 27 5 22 5 15 V7 Z M11 16 L15 20 L22 12";
    public const string IconoEscudoAviso = "M16 3 L27 7 V15 C27 22 22 27 16 29 C10 27 5 22 5 15 V7 Z M16 10 V18 M16 22 V23";
    public const string IconoApps = "M5 5 H14 V14 H5 Z M18 5 H27 V14 H18 Z M5 18 H14 V27 H5 Z M18 18 H27 V27 H18 Z";
    public const string IconoCampana = "M8 22 V14 C8 9 11 6 16 6 C21 6 24 9 24 14 V22 L27 25 H5 Z M13 28 H19";
    public const string IconoNotas = "M6 4 H26 V28 H6 Z M10 10 H22 M10 15 H22 M10 20 H17";
    public const string IconoEngranaje = "M10 16 A6 6 0 1 0 22 16 A6 6 0 1 0 10 16 Z M16 3 V8 M16 24 V29 M3 16 H8 M24 16 H29 M7 7 L10 10 M22 22 L25 25 M25 7 L22 10 M10 22 L7 25";
    public const string IconoMatraz = "M12 4 H20 M13 4 V13 L6 26 H26 L19 13 V4";

    public static TextBlock Texto(string texto, double tam = Cuerpo, bool negrita = false, IBrush? color = null) => new()
    {
        Text = texto, FontSize = tam, FontWeight = negrita ? FontWeight.Bold : FontWeight.Normal,
        Foreground = color ?? Brushes.Black, TextWrapping = TextWrapping.Wrap,
    };

    public static Path Icono(string datos, double tam = 40, IBrush? trazo = null) => new()
    {
        Data = Geometry.Parse(datos), Stroke = trazo ?? Brushes.Black, StrokeThickness = 2, Width = tam, Height = tam,
        Stretch = Stretch.Uniform, HorizontalAlignment = HorizontalAlignment.Left,
    };

    /// <summary>Marco hundido y blanco, como un campo de texto clasico.</summary>
    public static Border Hundido(Control hijo, double relleno = 12) => new()
    {
        Background = Brushes.White, BorderBrush = GrisClaro, BorderThickness = new Thickness(2), Padding = new Thickness(relleno), Child = hijo,
    };

    /// <summary>Cuadrado con ✓, ! o i: el estado de una comprobacion.</summary>
    public static Control Marca(NivelDeComprobacion nivel)
    {
        var (simbolo, fondo) = nivel switch
        {
            NivelDeComprobacion.Bien => ("✓", Verde),
            NivelDeComprobacion.Aviso => ("!", Rojo),
            _ => ("i", GrisClaro),
        };
        return new Border
        {
            Width = 30, Height = 30, Background = fondo, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 0, 0),
            Child = new TextBlock { Text = simbolo, Foreground = Brushes.White, FontWeight = FontWeight.Bold, FontSize = Cuerpo, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
        };
    }

    public static Control FilaDeComprobacion(Comprobacion c)
    {
        var fila = new Grid { ColumnDefinitions = new ColumnDefinitions("42,*"), MinHeight = 60, Margin = new Thickness(0, 4) };
        fila.Children.Add(Marca(c.Nivel));
        var texto = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
        texto.Children.Add(Texto(c.Nombre, Cuerpo, true));
        texto.Children.Add(Texto(c.Detalle, Secundario, false, Gris));
        Grid.SetColumn(texto, 1);
        fila.Children.Add(texto);
        return fila;
    }

    public static Button BotonGrande(string texto, Action alTocar, bool destacado = false)
    {
        var b = new Button
        {
            Content = new TextBlock { Text = texto, FontSize = destacado ? Titulo : Cuerpo, FontWeight = destacado ? FontWeight.Bold : FontWeight.Normal, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center },
            MinHeight = destacado ? 56 : AlturaMinima, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Center,
        };
        b.Click += (_, _) => alTocar();
        return b;
    }

    public sealed class MosaicoEnPantalla
    {
        public required Button Boton { get; init; }
        public required TextBlock Detalle { get; init; }
        public required Border Insignia { get; init; }
        public required TextBlock TextoInsignia { get; init; }
    }

    /// <summary>Un mosaico del inicio: icono, nombre, detalle y una insignia con un contador (oculta si no hay nada que contar).</summary>
    public static MosaicoEnPantalla Mosaico(string icono, string nombre, string detalle, Action alTocar)
    {
        var det = Texto(detalle, Secundario, false, Gris);
        var cuerpo = new Grid { RowDefinitions = new RowDefinitions("*,Auto") };
        cuerpo.Children.Add(Icono(icono, 40));
        var abajo = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Bottom };
        abajo.Children.Add(Texto(nombre, Titulo, true));
        abajo.Children.Add(det);
        Grid.SetRow(abajo, 1);
        cuerpo.Children.Add(abajo);
        var textoInsignia = new TextBlock { Foreground = Brushes.White, FontWeight = FontWeight.Bold, FontSize = Cuerpo, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        var insignia = new Border { Background = Rojo, MinWidth = 28, Height = 28, Padding = new Thickness(6, 0), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top, IsVisible = false, Child = textoInsignia };
        cuerpo.Children.Add(insignia);
        var boton = new Button { Content = cuerpo, Height = 132, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Stretch, Padding = new Thickness(10) };
        boton.Click += (_, _) => alTocar();
        return new MosaicoEnPantalla { Boton = boton, Detalle = det, Insignia = insignia, TextoInsignia = textoInsignia };
    }

    public static void PonerInsignia(MosaicoEnPantalla m, int cantidad)
    {
        m.Insignia.IsVisible = cantidad > 0;
        m.TextoInsignia.Text = cantidad.ToString();
    }

    /// <summary>
    /// Interruptor de dos mitades «NO | SÍ»: la mitad activa va rellena de azul con letra blanca, asi el estado se ve de lejos
    /// (el boton de dos estados del tema clasico solo cambia a un gris punteado casi imposible de distinguir).
    /// </summary>
    public sealed class InterruptorRetro : Button
    {
        private static readonly IBrush Azul = new SolidColorBrush(Color.Parse("#000080"));
        private readonly Border _no = new(), _si = new();
        private readonly TextBlock _textoNo = new() { Text = "NO", FontWeight = FontWeight.Bold, FontSize = Cuerpo, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        private readonly TextBlock _textoSi = new() { Text = "SÍ", FontWeight = FontWeight.Bold, FontSize = Cuerpo, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        private bool _activado;

        public event Action<bool>? Cambio;

        public bool Activado
        {
            get => _activado;
            set { _activado = value; Pintar(); }
        }

        public InterruptorRetro(bool activado)
        {
            Width = 112; Height = 48; Padding = new Thickness(3); VerticalAlignment = VerticalAlignment.Center;
            _no.Child = _textoNo; _si.Child = _textoSi;
            var rejilla = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*") };
            rejilla.Children.Add(_no);
            Grid.SetColumn(_si, 1);
            rejilla.Children.Add(_si);
            Content = rejilla;
            _activado = activado;
            Pintar();
            Click += (_, _) => { _activado = !_activado; Pintar(); Cambio?.Invoke(_activado); };
        }

        private void Pintar()
        {
            _si.Background = _activado ? Azul : Brushes.Transparent;
            _textoSi.Foreground = _activado ? Brushes.White : Gris;
            _no.Background = _activado ? Brushes.Transparent : Azul;
            _textoNo.Foreground = _activado ? Gris : Brushes.White;
        }
    }

    /// <summary>Fila «texto a la izquierda, interruptor SI/NO a la derecha». Reemplaza a las casillas pequeñas.</summary>
    public static Control FilaConInterruptor(string titulo, string? detalle, bool activado, Action<bool> alCambiar, out InterruptorRetro interruptor)
    {
        var tb = new InterruptorRetro(activado);
        tb.Cambio += alCambiar;
        var texto = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
        texto.Children.Add(Texto(titulo, Cuerpo, true));
        if (detalle != null) texto.Children.Add(Texto(detalle, Secundario, false, Gris));
        var fila = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), MinHeight = 68, Margin = new Thickness(0, 4), ColumnSpacing = 12 };
        fila.Children.Add(texto);
        Grid.SetColumn(tb, 1);
        fila.Children.Add(tb);
        interruptor = tb;
        return fila;
    }

    public static Control FilaQueNavega(string titulo, string? detalle, Action alTocar)
    {
        var texto = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
        texto.Children.Add(Texto(titulo, Cuerpo, true));
        if (detalle != null) texto.Children.Add(Texto(detalle, Secundario, false, Gris));
        var cuerpo = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        cuerpo.Children.Add(texto);
        var flecha = Icono("M11 5 L22 16 L11 27", 20);
        Grid.SetColumn(flecha, 1);
        cuerpo.Children.Add(flecha);
        var b = new Button { Content = cuerpo, MinHeight = 64, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(12, 6) };
        b.Click += (_, _) => alTocar();
        return b;
    }

    public static string HaceCuanto(long? ultimoMs, long ahoraMs)
    {
        if (ultimoMs is null) return "Aún no hay ninguna revisión.";
        var min = (ahoraMs - ultimoMs.Value) / 60000;
        return min < 1 ? "Última revisión: hace menos de 1 minuto." : min < 120 ? $"Última revisión: hace {min} min." : $"Última revisión: hace {min / 60} h.";
    }
}
