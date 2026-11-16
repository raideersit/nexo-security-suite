using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Nexo.Ui.Movil;

/// <summary>Contenedor: barra de titulo con Atras y una pila de pantallas (Estado es el inicio).</summary>
public sealed partial class PantallaPrincipal : UserControl
{
    private readonly Stack<(string Titulo, Control Vista)> _pila = new();

    public PantallaPrincipal()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("Atras")!.Click += (_, _) => Volver();
        Ir("Nexo Security Suite", new PantallaEstado(
            () => Ir("Apps instaladas", new PantallaApps()),
            () => Ir("Pruebas", new PantallaPruebas())));
        AttachedToVisualTree += (_, _) =>
        {
            if (TopLevel.GetTopLevel(this) is { } tl)
                tl.BackRequested += (_, e) => { if (_pila.Count > 1) { Volver(); e.Handled = true; } };
        };
    }

    private void Ir(string titulo, Control vista)
    {
        _pila.Push((titulo, vista));
        Mostrar();
    }

    private void Volver()
    {
        if (_pila.Count > 1) { _pila.Pop(); Mostrar(); }
    }

    private void Mostrar()
    {
        var (titulo, vista) = _pila.Peek();
        this.FindControl<TextBlock>("Titulo")!.Text = titulo;
        this.FindControl<Button>("Atras")!.IsVisible = _pila.Count > 1;
        this.FindControl<ContentControl>("Contenido")!.Content = vista;
    }
}
