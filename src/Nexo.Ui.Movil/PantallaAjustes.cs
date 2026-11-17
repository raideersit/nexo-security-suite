using System;
using Avalonia.Controls;
using Nexo.Ui.Movil.Interfaz;

namespace Nexo.Ui.Movil;

/// <summary>Ajustes: las apps de confianza (se administran en «Apps», donde se ven sus motivos) y datos de esta instalacion.</summary>
public sealed class PantallaAjustes : UserControl
{
    public PantallaAjustes(Action irApps)
    {
        var raiz = new StackPanel { Margin = new Avalonia.Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.FilaQueNavega("Apps de confianza", "Se ven al final de «Apps», con «Dejar de confiar»", irApps));
        var info = new StackPanel { Spacing = 4 };
        info.Children.Add(Retro.Texto("Esta instalación", Retro.Cuerpo, true));
        info.Children.Add(Retro.Texto($"Nexo móvil · Android {Android.OS.Build.VERSION.Release} (API {(int)Android.OS.Build.VERSION.SdkInt})", Retro.Secundario, false, Retro.Gris));
        info.Children.Add(Retro.Texto("Es una puntuación y listas de huellas: Nexo complementa a Google Play Protect, no lo reemplaza.", Retro.Secundario, false, Retro.Gris));
        raiz.Children.Add(Retro.Hundido(info, 12));
        Content = new ScrollViewer { Content = raiz };
    }
}
