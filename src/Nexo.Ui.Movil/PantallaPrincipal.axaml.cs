using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Nexo.Ui.Movil;

/// <summary>Contenedor: barra de titulo con Atras y una pila de pantallas (Inicio es la raiz).</summary>
public sealed partial class PantallaPrincipal : UserControl
{
    private readonly Stack<(string Titulo, Control Vista)> _pila = new();

    public PantallaPrincipal()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("Atras")!.Click += (_, _) => Volver();
        Ir("Nexo Security Suite", new PantallaInicio(
            irEstado: () => Ir("Estado del equipo", new PantallaEstado()),
            irApps: () => Ir("Apps instaladas", new PantallaApps()),
            irAvisos: () => Ir("Avisos", new PantallaAvisos()),
            irHistorial: () => Ir("Historial para Obsidian", new PantallaHistorial()),
            irAjustes: () => Ir("Ajustes", new PantallaAjustes(() => Ir("Apps instaladas", new PantallaApps()), () => Ir("Pruebas", new PantallaPruebas()))),
            irRevisar: () => Ir("Revisar un mensaje", new PantallaRevisar())));
        AttachedToVisualTree += (_, _) =>
        {
            // «Ver» de una notificacion: en frio llega como pendiente; con la app abierta, por el evento.
            MainActivity.DestinoPedido += AbrirDestinoPedido;
            if (MainActivity.TomarDestinoPendiente() is { } pendiente) AbrirDestino(pendiente);
            if (TopLevel.GetTopLevel(this) is { } tl)
            {
                tl.BackRequested += (_, e) => { if (_pila.Count > 1) { Volver(); e.Handled = true; } };
                // Barras del sistema en el gris clasico: el tema claro pone iconos OSCUROS, que se leen bien sobre gris (sobre azul no se veian).
                if (tl.InsetsManager is { } insets) insets.SystemBarColor = Avalonia.Media.Color.Parse("#D4D0C8");
            }
        };
        DetachedFromVisualTree += (_, _) => MainActivity.DestinoPedido -= AbrirDestinoPedido;
    }

    private void AbrirDestinoPedido(string destino) =>
        Avalonia.Threading.Dispatcher.UIThread.Post(() => AbrirDestino(destino));

    /// <summary>
    /// Vuelve al inicio y abre lo que pide la notificacion: «Apps instaladas» en la tarjeta de una app, o «Estado del equipo».
    /// Atras lleva al inicio, no a donde estaba. Un destino desconocido (o «inicio») deja el inicio.
    /// </summary>
    private void AbrirDestino(string destino)
    {
        while (_pila.Count > 1) _pila.Pop();
        if (Vigilancia.Destino.PaqueteDe(destino) is { } paquete) Ir("Apps instaladas", new PantallaApps(destacar: paquete));
        else if (destino == Vigilancia.Destino.Estado) Ir("Estado del equipo", new PantallaEstado());
        else if (destino == Vigilancia.Destino.Revisar) Ir("Revisar un mensaje", new PantallaRevisar(Revisar.Compartido.Tomar()));
        else Mostrar();
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
