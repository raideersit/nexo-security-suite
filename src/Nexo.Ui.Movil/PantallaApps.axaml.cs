using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Nexo.Modules.Threats.Apps;
using Nexo.Modules.Threats.Movil;

namespace Nexo.Ui.Movil;

/// <summary>Inventario de apps con su puntuacion de riesgo (Salida 7, 3.1). Muestra «a revisar» con motivos, nunca «malware».</summary>
public sealed partial class PantallaApps : UserControl
{
    private static readonly Lazy<PuntuadorDeRiesgo> Puntuador = new(() => new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido()));

    public PantallaApps()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("Releer")!.Click += async (_, _) => await RevisarAsync();
        _ = RevisarAsync();
    }

    private async Task RevisarAsync()
    {
        var resumen = this.FindControl<TextBlock>("Resumen")!;
        var filas = this.FindControl<StackPanel>("Filas")!;
        var boton = this.FindControl<Button>("Releer")!;
        boton.IsEnabled = false;
        resumen.Text = "Revisando las apps...";
        filas.Children.Clear();
        try
        {
            var (resultados, avisos, leerMs, puntuarMs) = await Task.Run(() =>
            {
                var lector = new LectorDeAppsAndroid(Android.App.Application.Context);
                var t = Stopwatch.StartNew();
                var apps = lector.Leer();
                var leer = t.ElapsedMilliseconds;
                t.Restart();
                var res = Puntuador.Value.EvaluarTodas(apps);
                Android.Util.Log.Info("NEXO", "APPS tiempos " + string.Join(" ", lector.Tiempos.Select(k => k.Key + "=" + k.Value)));
                return (res, lector.Avisos, leer, t.ElapsedMilliseconds);
            });
            var usuario = resultados.Where(r => r.Nivel != NivelDeRiesgo.NoEvaluada).ToList();
            int prio = usuario.Count(r => r.Nivel == NivelDeRiesgo.Prioritaria), rev = usuario.Count(r => r.Nivel == NivelDeRiesgo.ARevisar);
            int normales = usuario.Count(r => r.Nivel is NivelDeRiesgo.Normal or NivelDeRiesgo.Confiada);
            resumen.Text = $"{usuario.Count} apps instaladas por ti: {prio} prioritarias, {rev} a revisar, {normales} normales.\n"
                         + $"Lectura {leerMs} ms, puntuacion {puntuarMs} ms."
                         + (avisos.Count > 0 ? "\n" + string.Join("\n", avisos) : "");
            Android.Util.Log.Info("NEXO", $"APPS usuario={usuario.Count} prioritarias={prio} a_revisar={rev} normales={normales} leer_ms={leerMs} puntuar_ms={puntuarMs} avisos={avisos.Count}");
            foreach (var r in usuario.Where(r => r.Nivel is NivelDeRiesgo.Prioritaria or NivelDeRiesgo.ARevisar))
                filas.Children.Add(Tarjeta(r));
            if (prio + rev == 0)
                filas.Children.Add(new TextBlock { Text = "Ninguna app tiene señales que revisar.", TextWrapping = TextWrapping.Wrap });
        }
        catch (Exception ex)
        {
            resumen.Text = "No se pudo revisar las apps: " + ex.Message;
        }
        boton.IsEnabled = true;
    }

    private static Control Tarjeta(ResultadoDeApp r)
    {
        var (etiqueta, color) = r.Nivel == NivelDeRiesgo.Prioritaria ? ("A REVISAR CON PRIORIDAD", Brushes.Firebrick) : ("A REVISAR", Brushes.DarkGoldenrod);
        var panel = new StackPanel { Spacing = 2, Margin = new Avalonia.Thickness(6) };
        panel.Children.Add(new TextBlock { Text = etiqueta + " · " + r.Puntos + " pts", Foreground = color, FontWeight = FontWeight.Bold });
        panel.Children.Add(new TextBlock { Text = string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre, FontSize = 18, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = r.Paquete, Foreground = Brushes.DimGray, TextWrapping = TextWrapping.Wrap });
        foreach (var m in r.Motivos) panel.Children.Add(new TextBlock { Text = "• " + m, TextWrapping = TextWrapping.Wrap });
        return new Border { BorderBrush = Brushes.Gray, BorderThickness = new Avalonia.Thickness(1), Child = panel, HorizontalAlignment = HorizontalAlignment.Stretch };
    }
}
