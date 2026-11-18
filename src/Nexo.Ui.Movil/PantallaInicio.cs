using System;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Inicio estilo «Panel de control» (opcion A de las maquetas): una tarjeta con lo mas importante arriba y seis mosaicos grandes debajo.
/// Lo caro (leer todas las apps) se calcula aparte y rellena el mosaico de Apps cuando termina.
/// </summary>
public sealed class PantallaInicio : UserControl
{
    private readonly StackPanel _tarjetaIcono = new();
    private readonly TextBlock _titulo = Retro.Texto("", 24, true);
    private readonly TextBlock _importante = Retro.Texto("");
    private readonly TextBlock _revision = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly Border _iconoEstado = new();
    private readonly Button _botonPrincipal;
    private readonly Retro.MosaicoEnPantalla _estado, _apps, _avisos, _historial;
    private readonly Action _irEstado;

    public PantallaInicio(Action irEstado, Action irApps, Action irAvisos, Action irHistorial, Action irAjustes, Action irRevisar)
    {
        _irEstado = irEstado;
        _botonPrincipal = Retro.BotonGrande("Ver los avisos", irEstado, destacado: true);

        var cabecera = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 12 };
        _iconoEstado.VerticalAlignment = VerticalAlignment.Top;
        cabecera.Children.Add(_iconoEstado);
        var textos = new StackPanel { Spacing = 2 };
        textos.Children.Add(_titulo);
        textos.Children.Add(_revision);
        Grid.SetColumn(textos, 1);
        cabecera.Children.Add(textos);

        var interior = new StackPanel { Spacing = 10 };
        interior.Children.Add(cabecera);
        interior.Children.Add(_importante);
        interior.Children.Add(_botonPrincipal);

        _estado = Retro.Mosaico(Retro.IconoEscudo, "Estado", "Chequeo del equipo", irEstado);
        _apps = Retro.Mosaico(Retro.IconoApps, "Apps", "Calculando...", irApps);
        _avisos = Retro.Mosaico(Retro.IconoCampana, "Avisos", "", irAvisos);
        _historial = Retro.Mosaico(Retro.IconoNotas, "Historial", "", irHistorial);
        var ajustes = Retro.Mosaico(Retro.IconoEngranaje, "Ajustes", "Apps de confianza", irAjustes);
        // «Revisar» ocupa el lugar de «Pruebas» (que paso a Ajustes): enlaces, SMS y QR, tambien desde «Compartir».
        var revisar = Retro.Mosaico(Retro.IconoLupa, "Revisar", "Enlaces, SMS y QR", irRevisar);

        var rejilla = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*"), RowDefinitions = new RowDefinitions("Auto,Auto,Auto"), ColumnSpacing = 12, RowSpacing = 12 };
        void Poner(Retro.MosaicoEnPantalla m, int fila, int col) { Grid.SetRow(m.Boton, fila); Grid.SetColumn(m.Boton, col); rejilla.Children.Add(m.Boton); }
        Poner(_estado, 0, 0); Poner(_apps, 0, 1); Poner(_avisos, 1, 0); Poner(_historial, 1, 1); Poner(revisar, 2, 0); Poner(ajustes, 2, 1);

        var raiz = new StackPanel { Margin = new Avalonia.Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(interior, 14));
        raiz.Children.Add(rejilla);
        Content = new ScrollViewer { Content = raiz };

        // Al volver desde otra pantalla (por ejemplo tras activar los avisos) todo se refresca.
        AttachedToVisualTree += (_, _) => Refrescar();
    }

    private void Refrescar()
    {
        var contexto = Android.App.Application.Context;
        var datos = EquipoAhora.Leer();
        var lista = EquipoAhora.Evaluar(datos);
        var avisos = ChequeoDelEquipo.Avisos(lista);
        var primero = lista.FirstOrDefault(c => c.Nivel == NivelDeComprobacion.Aviso);

        _iconoEstado.Child = Retro.Icono(avisos > 0 ? Retro.IconoEscudoAviso : Retro.IconoEscudo, 44, avisos > 0 ? Retro.Rojo : Retro.Verde);
        _titulo.Text = avisos == 0 ? "Todo en orden" : avisos == 1 ? "1 aviso" : $"{avisos} avisos";
        _titulo.Foreground = avisos == 0 ? Retro.Verde : Retro.Rojo;
        _importante.Text = primero is null ? "El chequeo del equipo no encontró nada que atender." : $"Lo primero que conviene mirar: {primero.Nombre.ToLowerInvariant()}. {primero.Detalle}";
        _botonPrincipal.Content = new TextBlock { Text = avisos == 0 ? "Revisar de nuevo" : "Ver los avisos", FontSize = Retro.Titulo, FontWeight = FontWeight.Bold, HorizontalAlignment = HorizontalAlignment.Center };
        Retro.PonerInsignia(_estado, avisos);

        bool vigilando = ConfiguracionDeVigilancia.Activada(contexto);
        var estado = EstadoDeVigilancia.Cargar(RutasDeNexo.Vigilancia(contexto), out _);
        _revision.Text = vigilando ? Retro.HaceCuanto(estado.UltimaRevisionMs, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) : "Los avisos al instalar están apagados.";
        _avisos.Detalle.Text = vigilando ? "Activados" : "Apagados";
        _avisos.Detalle.Foreground = vigilando ? Retro.Verde : Retro.Gris;
        _avisos.Detalle.FontWeight = vigilando ? FontWeight.Bold : FontWeight.Normal;
        _historial.Detalle.Text = HistorialDeObsidian.Activado(contexto) ? "Obsidian · activado" : "Obsidian · apagado";

        _ = Task.Run(() =>
        {
            var apps = EquipoAhora.LeerApps();
            Dispatcher.UIThread.Post(() =>
            {
                var marcadas = apps.Prioritarias + apps.ARevisar;
                _apps.Detalle.Text = marcadas == 0 ? $"{apps.Usuario} · ninguna a revisar" : $"{apps.Usuario} · {marcadas} a revisar";
                Retro.PonerInsignia(_apps, marcadas);
            });
        });
    }
}
