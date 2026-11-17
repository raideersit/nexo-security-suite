using System;
using System.Threading.Tasks;
using Android.Content;
using Avalonia.Controls;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;

namespace Nexo.Ui.Movil;

/// <summary>Detalle del chequeo del equipo (§3.4): una fila de 60 px por comprobacion y «Revisar ahora».</summary>
public sealed class PantallaEstado : UserControl
{
    private readonly TextBlock _encabezado = Retro.Texto("", Retro.Cuerpo, true);
    private readonly StackPanel _filas = new() { Spacing = 0 };
    private DatosDelEquipo? _datos;

    public PantallaEstado()
    {
        var contexto = Android.App.Application.Context;
        var raiz = new StackPanel { Margin = new Avalonia.Thickness(12), Spacing = 12 };
        raiz.Children.Add(_encabezado);
        raiz.Children.Add(Retro.Hundido(_filas, 8));
        raiz.Children.Add(Retro.BotonGrande("Abrir Play Store (para revisar Play Protect)", () =>
        {
            var i = contexto.PackageManager?.GetLaunchIntentForPackage("com.android.vending");
            if (i is null) return;
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        }));
        raiz.Children.Add(Retro.BotonGrande("Revisar ahora", Revisar, destacado: true));
        Content = new ScrollViewer { Content = raiz };
        Revisar();
    }

    private void Revisar()
    {
        _datos = EquipoAhora.Leer();
        Pintar();
        // Lo que necesita leer todas las apps se calcula aparte, sin frenar la pantalla.
        _ = Task.Run(() =>
        {
            var apps = EquipoAhora.LeerApps();
            Dispatcher.UIThread.Post(() => { _datos = _datos! with { AppsQueInstalan = apps.Instalan }; Pintar(); });
        });
    }

    private void Pintar()
    {
        var lista = EquipoAhora.Evaluar(_datos!);
        var avisos = ChequeoDelEquipo.Avisos(lista);
        _encabezado.Text = avisos == 0 ? "Chequeo del equipo · sin avisos" : $"Chequeo del equipo · {avisos} aviso(s)";
        _filas.Children.Clear();
        foreach (var c in lista) _filas.Children.Add(Retro.FilaDeComprobacion(c));
    }
}
