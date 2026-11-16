using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
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

    private CancellationTokenSource? _cancelar;
    private IReadOnlyList<ResultadoDeApp>? _ultimosResultados;

    public PantallaApps()
    {
        AvaloniaXamlLoader.Load(this);
        DetachedFromVisualTree += (_, _) => _cancelar?.Cancel();
        this.FindControl<Button>("GuardarRevision")!.Click += async (_, _) =>
        {
            if (_ultimosResultados is null) return;
            var texto = this.FindControl<TextBlock>("Resumen")!;
            try
            {
                // Solo viajan al vault las apps «a revisar»: EventosDeApps no recibe ni escribe la lista completa.
                await Task.Run(() => Vigilancia.HistorialDeObsidian.Escribir(new[] { EventosDeApps.RevisionDeApps(_ultimosResultados) }));
                texto.Text += "\nRevisión guardada en " + Vigilancia.HistorialDeObsidian.Carpeta() + ".";
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            { texto.Text += "\nNo se pudo guardar: " + ex.Message; }
        };
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
            var (resultados, avisos, leerMs, puntuarMs, modelos, almacen) = await Task.Run(() =>
            {
                var lector = new LectorDeAppsAndroid(Android.App.Application.Context);
                var t = Stopwatch.StartNew();
                var apps = lector.Leer();
                var leer = t.ElapsedMilliseconds;
                t.Restart();
                var contexto = Android.App.Application.Context;
                var almacen = AlmacenDeConfianza.Cargar(Vigilancia.RutasDeNexo.Confiadas(contexto), out var avisoConfianza);
                if (avisoConfianza != null) lector.Avisos.Add(avisoConfianza);
                if (almacen.Podar(apps) > 0) almacen.Guardar(Vigilancia.RutasDeNexo.Confiadas(contexto));
                var res = Puntuador.Value.EvaluarTodas(apps, almacen.Vigentes(apps));
                Android.Util.Log.Info("NEXO", "APPS tiempos " + string.Join(" ", lector.Tiempos.Select(k => k.Key + "=" + k.Value)));
                return (res, lector.Avisos, leer, t.ElapsedMilliseconds, apps, almacen);
            });
            var usuario = resultados.Where(r => r.Nivel != NivelDeRiesgo.NoEvaluada).ToList();
            int prio = usuario.Count(r => r.Nivel == NivelDeRiesgo.Prioritaria), rev = usuario.Count(r => r.Nivel == NivelDeRiesgo.ARevisar);
            int normales = usuario.Count(r => r.Nivel is NivelDeRiesgo.Normal or NivelDeRiesgo.Confiada);
            int confiadas = usuario.Count(r => r.Nivel == NivelDeRiesgo.Confiada);
            normales -= confiadas;
            resumen.Text = $"{usuario.Count} apps instaladas por ti: {prio} prioritarias, {rev} a revisar, {confiadas} de confianza, {normales} normales.\n"
                         + $"Lectura {leerMs} ms, puntuacion {puntuarMs} ms."
                         + (avisos.Count > 0 ? "\n" + string.Join("\n", avisos) : "");
            Android.Util.Log.Info("NEXO", $"APPS usuario={usuario.Count} prioritarias={prio} a_revisar={rev} normales={normales} leer_ms={leerMs} puntuar_ms={puntuarMs} avisos={avisos.Count}");
            foreach (var r in usuario.Where(r => r.Nivel is NivelDeRiesgo.Prioritaria or NivelDeRiesgo.ARevisar))
                filas.Children.Add(Tarjeta(r, modelos.First(m => m.Paquete == r.Paquete), almacen, () => _ = RevisarAsync()));
            if (prio + rev == 0)
                filas.Children.Add(new TextBlock { Text = "Ninguna app tiene señales que revisar.", TextWrapping = TextWrapping.Wrap });
            var deConfianza = usuario.Where(r => r.Nivel == NivelDeRiesgo.Confiada).ToList();
            if (deConfianza.Count > 0)
            {
                filas.Children.Add(new TextBlock { Text = "Apps en las que confías", FontSize = 18, FontWeight = FontWeight.Bold, Margin = new Avalonia.Thickness(0, 12, 0, 0) });
                foreach (var r in deConfianza) filas.Children.Add(TarjetaDeConfianza(r, almacen, () => _ = RevisarAsync()));
            }
            _ultimosResultados = resultados;
            var guardar = this.FindControl<Button>("GuardarRevision")!;
            guardar.IsVisible = Vigilancia.HistorialDeObsidian.Activado(Android.App.Application.Context);
            await CalcularHuellasAsync(modelos, resultados, filas);
        }
        catch (Exception ex)
        {
            resumen.Text = "No se pudo revisar las apps: " + ex.Message;
        }
        boton.IsEnabled = true;
    }

    /// <summary>Huellas SHA-256 de los APK (3.2): con cache, en segundo plano y cancelable. Compara contra las listas de la carpeta «listas».</summary>
    private async Task CalcularHuellasAsync(IReadOnlyList<ModeloDeApp> modelos, IReadOnlyList<ResultadoDeApp> resultados, StackPanel filas)
    {
        var texto = this.FindControl<TextBlock>("Huellas")!;
        _cancelar?.Cancel();
        _cancelar = new CancellationTokenSource();
        var ct = _cancelar.Token;
        var contexto = Android.App.Application.Context;
        var rutaCache = Vigilancia.RutasDeNexo.Cache(contexto);
        var carpetaListas = Vigilancia.RutasDeNexo.CarpetaDeListas(contexto);
        texto.Text = "Huellas: calculando...";
        var progreso = new Progress<(int Hechas, int Total)>(p => texto.Text = $"Huellas: {p.Hechas}/{p.Total} apps...");
        try
        {
            var salida = await Task.Run(() =>
            {
                var cache = CacheDeHuellas.Cargar(rutaCache, out var avisoCache);
                var t = Stopwatch.StartNew();
                try
                {
                    var r = new CalculadorDeHuellas(new OrigenDeApksEnDisco(), cache).Calcular(modelos, progreso, ct);
                    return (r, cache, avisoCache, t.ElapsedMilliseconds, (bool)false);
                }
                finally { cache.Guardar(rutaCache); }
            });
            var (res, cacheFinal, avisoCache2, ms, _) = salida;
            var listas = new List<ListaDeHuellas>();
            var avisosListas = new List<string>();
            if (Directory.Exists(carpetaListas))
                foreach (var f in Directory.EnumerateFiles(carpetaListas).Where(f => f.EndsWith(".txt") || f.EndsWith(".csv")).OrderBy(f => f))
                {
                    try { listas.Add(ListaDeHuellas.DesdeArchivo(f)); }
                    catch (Exception ex) when (ex is InvalidDataException or IOException) { avisosListas.Add(Path.GetFileName(f) + ": " + ex.Message); }
                }
            var coincidencias = BuscadorDeCoincidencias.Buscar(res.Huellas.Values, listas);
            var nombres = resultados.ToDictionary(r => r.Paquete, r => r.Nombre);
            for (int i = coincidencias.Count - 1; i >= 0; i--)
                filas.Children.Insert(0, TarjetaDeCoincidencia(coincidencias[i], nombres));
            var r2 = res.Resumen;
            texto.Text = $"Huellas: {r2.Calculadas} calculadas, {r2.DeCache} de la cache, {r2.Fallidas} fallidas ({r2.BytesLeidos / 1048576} MiB leidos en {ms} ms). "
                       + (listas.Count == 0 ? "Sin listas de huellas conocidas: no se compara nada." : $"{coincidencias.Count} coincidencia(s) con {listas.Count} lista(s), {listas.Sum(l => l.Cantidad)} huellas.")
                       + (avisoCache2 != null ? "\n" + avisoCache2 : "") + (avisosListas.Count > 0 ? "\n" + string.Join("\n", avisosListas) : "");
            Android.Util.Log.Info("NEXO", $"HUELLAS calculadas={r2.Calculadas} cache={r2.DeCache} fallidas={r2.Fallidas} podadas={r2.Podadas} mib={r2.BytesLeidos / 1048576} ms={ms} listas={listas.Count} huellas_en_listas={listas.Sum(l => l.Cantidad)} coincidencias={coincidencias.Count}"
                + string.Concat(coincidencias.Select(c => " COINCIDE=" + c.Paquete + "/" + c.Lista)));
        }
        catch (OperationCanceledException) { /* salio de la pantalla: lo calculado ya quedo en la cache */ }
        catch (Exception ex) { texto.Text = "Huellas: no se pudieron calcular: " + ex.Message; }
    }

    private static Control TarjetaDeCoincidencia(Coincidencia c, IReadOnlyDictionary<string, string> nombres)
    {
        var panel = new StackPanel { Spacing = 2, Margin = new Avalonia.Thickness(6) };
        panel.Children.Add(new TextBlock { Text = "COINCIDE CON UNA HUELLA CONOCIDA", Foreground = Brushes.Firebrick, FontWeight = FontWeight.Bold });
        panel.Children.Add(new TextBlock { Text = nombres.GetValueOrDefault(c.Paquete, c.Paquete), FontSize = 18, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = c.Paquete, Foreground = Brushes.DimGray, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = $"• El archivo {c.Archivo} es idéntico, byte a byte, a una huella de la lista «{c.Lista}». Es una coincidencia exacta con esa copia, no un análisis de la app.", TextWrapping = TextWrapping.Wrap });
        return new Border { BorderBrush = Brushes.Firebrick, BorderThickness = new Avalonia.Thickness(2), Child = panel, HorizontalAlignment = HorizontalAlignment.Stretch };
    }

    /// <summary>El boton pide DOS toques: confiar quita a la app de las alertas, y no debe ser un toque por accidente.</summary>
    private static Button BotonDeConfianza(string texto, string textoDeConfirmacion, Action alConfirmar)
    {
        var boton = new Button { Content = texto, MinHeight = 48, HorizontalAlignment = HorizontalAlignment.Stretch, Margin = new Avalonia.Thickness(0, 6, 0, 0) };
        bool pedida = false;
        boton.Click += (_, _) =>
        {
            if (!pedida) { pedida = true; boton.Content = textoDeConfirmacion; return; }
            alConfirmar();
        };
        return boton;
    }

    private static Control TarjetaDeConfianza(ResultadoDeApp r, AlmacenDeConfianza almacen, Action alCambiar)
    {
        var panel = new StackPanel { Spacing = 2, Margin = new Avalonia.Thickness(6) };
        panel.Children.Add(new TextBlock { Text = "DE CONFIANZA · " + r.Puntos + " pts", Foreground = Brushes.DarkGreen, FontWeight = FontWeight.Bold });
        panel.Children.Add(new TextBlock { Text = string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre, FontSize = 18, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = r.Paquete, Foreground = Brushes.DimGray, TextWrapping = TextWrapping.Wrap });
        foreach (var m in r.Motivos) panel.Children.Add(new TextBlock { Text = "• " + m, TextWrapping = TextWrapping.Wrap });
        var dejar = new Button { Content = "Dejar de confiar", MinHeight = 48, HorizontalAlignment = HorizontalAlignment.Stretch, Margin = new Avalonia.Thickness(0, 6, 0, 0) };
        dejar.Click += (_, _) =>
        {
            almacen.DejarDeConfiar(r.Paquete);
            almacen.Guardar(Vigilancia.RutasDeNexo.Confiadas(Android.App.Application.Context));
            alCambiar();
        };
        panel.Children.Add(dejar);
        return new Border { BorderBrush = Brushes.DarkGreen, BorderThickness = new Avalonia.Thickness(1), Child = panel, HorizontalAlignment = HorizontalAlignment.Stretch };
    }

    private static Control Tarjeta(ResultadoDeApp r, ModeloDeApp modelo, AlmacenDeConfianza almacen, Action alCambiar)
    {
        var (etiqueta, color) = r.Nivel == NivelDeRiesgo.Prioritaria ? ("A REVISAR CON PRIORIDAD", Brushes.Firebrick) : ("A REVISAR", Brushes.DarkGoldenrod);
        var panel = new StackPanel { Spacing = 2, Margin = new Avalonia.Thickness(6) };
        panel.Children.Add(new TextBlock { Text = etiqueta + " · " + r.Puntos + " pts", Foreground = color, FontWeight = FontWeight.Bold });
        panel.Children.Add(new TextBlock { Text = string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre, FontSize = 18, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = r.Paquete, Foreground = Brushes.DimGray, TextWrapping = TextWrapping.Wrap });
        foreach (var m in r.Motivos) panel.Children.Add(new TextBlock { Text = "• " + m, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(BotonDeConfianza("Confío en esta app", "Toca otra vez para confirmar: confío en esta app", () =>
        {
            if (almacen.Confiar(modelo)) almacen.Guardar(Vigilancia.RutasDeNexo.Confiadas(Android.App.Application.Context));
            alCambiar();
        }));
        return new Border { BorderBrush = Brushes.Gray, BorderThickness = new Avalonia.Thickness(1), Child = panel, HorizontalAlignment = HorizontalAlignment.Stretch };
    }
}
