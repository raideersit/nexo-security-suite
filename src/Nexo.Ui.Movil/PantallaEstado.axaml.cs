using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Nexo.Ui.Movil.Estado;

namespace Nexo.Ui.Movil;

/// <summary>Pantalla de inicio: chequeo del equipo y lista de secciones.</summary>
public sealed partial class PantallaEstado : UserControl
{
    public PantallaEstado(Action irApps, Action irPruebas)
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("IrApps")!.Click += (_, _) => irApps();
        this.FindControl<Button>("IrPruebas")!.Click += (_, _) => irPruebas();
        Mostrar();
    }

    private void Mostrar()
    {
        var filas = this.FindControl<StackPanel>("Filas")!;
        var resumen = this.FindControl<TextBlock>("Resumen")!;
        var lista = ChequeoEquipo.Ejecutar(Android.App.Application.Context, DateTime.Today);
        var avisos = lista.Count(c => c.Nivel == Nivel.Aviso);
        resumen.Text = avisos == 0 ? "Estado del equipo: sin avisos" : $"Estado del equipo: {avisos} aviso(s)";
        foreach (var c in lista)
        {
            var (marca, color) = c.Nivel switch
            {
                Nivel.Bien => ("[OK]", Brushes.DarkGreen),
                Nivel.Aviso => ("[!]", Brushes.Firebrick),
                _ => ("[i]", Brushes.DimGray),
            };
            var fila = new Grid { ColumnDefinitions = new ColumnDefinitions("40,*"), MinHeight = 48 };
            fila.Children.Add(new TextBlock { Text = marca, Foreground = color, FontWeight = FontWeight.Bold, VerticalAlignment = VerticalAlignment.Center });
            var texto = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(texto, 1);
            texto.Children.Add(new TextBlock { Text = c.Nombre, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
            texto.Children.Add(new TextBlock { Text = c.Detalle, TextWrapping = TextWrapping.Wrap });
            fila.Children.Add(texto);
            filas.Children.Add(fila);
        }
    }
}
