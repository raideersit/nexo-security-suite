using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Nexo.Modules.Threats.Apps;
using Nexo.Modules.Threats.Movil;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Inventario de apps con su puntuacion de riesgo (Salida 7, 3.1), con el estilo «Classic tactil»: un titular claro arriba, tarjetas con franja de color,
/// el primer motivo a la vista y el resto plegado. Muestra «a revisar» con motivos, nunca «malware».
/// </summary>
public sealed class PantallaApps : UserControl
{
    private static readonly Lazy<PuntuadorDeRiesgo> Puntuador = new(() => new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido()));
    private static readonly IBrush Ambar = new SolidColorBrush(Color.Parse("#8A5A00"));

    private readonly TextBlock _titular = Retro.Texto("", 24, true);
    private readonly TextBlock _resumen = Retro.Texto("", Retro.Cuerpo);
    private readonly TextBlock _huellas = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _pie = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly StackPanel _filas = new() { Spacing = 10 };
    private readonly Button _releer, _guardar;

    private CancellationTokenSource? _cancelar;
    private IReadOnlyList<ResultadoDeApp>? _ultimosResultados;
    private int _aRevisar, _coincidencias;
    private bool _listo;

    // «Ver» de una notificacion: el paquete cuya tarjeta se marca y se pone a la vista. Null si se entro desde el inicio.
    private readonly string? _destacar;
    private bool _destacada;
    private readonly TextBlock _avisoDestacar = Retro.Texto("", Retro.Cuerpo);

    public PantallaApps(string? destacar = null)
    {
        _destacar = destacar;
        _avisoDestacar.IsVisible = false;
        _releer = Retro.BotonGrande("Revisar de nuevo", () => _ = RevisarAsync(), destacado: true);
        _guardar = Retro.BotonGrande("Guardar esta revisión en Obsidian", GuardarRevision);
        _guardar.IsVisible = false;

        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_resumen);
        cabecera.Children.Add(_huellas);
        cabecera.Children.Add(_avisoDestacar);

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));
        raiz.Children.Add(_releer);
        raiz.Children.Add(_guardar);
        raiz.Children.Add(_filas);
        raiz.Children.Add(_pie);
        Content = new ScrollViewer { Content = raiz };

        DetachedFromVisualTree += (_, _) => _cancelar?.Cancel();
        _ = RevisarAsync();
    }

    private void PonerTitular()
    {
        if (!_listo) { _titular.Text = "Revisando las apps..."; _titular.Foreground = Brushes.Black; return; }
        if (_coincidencias > 0)
        {
            _titular.Text = _coincidencias == 1 ? "1 coincidencia con una huella conocida" : $"{_coincidencias} coincidencias con huellas conocidas";
            _titular.Foreground = Retro.Rojo;
        }
        else if (_aRevisar > 0)
        {
            _titular.Text = _aRevisar == 1 ? "1 app a revisar" : $"{_aRevisar} apps a revisar";
            _titular.Foreground = Retro.Rojo;
        }
        else { _titular.Text = "Ninguna app a revisar"; _titular.Foreground = Retro.Verde; }
    }

    private async void GuardarRevision()
    {
        if (_ultimosResultados is null) return;
        try
        {
            // Solo viajan al vault las apps «a revisar»: EventosDeApps no recibe ni escribe la lista completa.
            await Task.Run(() => HistorialDeObsidian.Escribir(new[] { EventosDeApps.RevisionDeApps(_ultimosResultados) }));
            _resumen.Text += "\nRevisión guardada en " + HistorialDeObsidian.Carpeta() + ".";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        { _resumen.Text += "\nNo se pudo guardar: " + ex.Message; }
    }

    private async Task RevisarAsync()
    {
        _releer.IsEnabled = false;
        _listo = false; _aRevisar = 0; _coincidencias = 0;
        PonerTitular();
        _resumen.Text = "";
        _huellas.Text = "";
        _pie.Text = "";
        _filas.Children.Clear();
        _destacada = false;
        _avisoDestacar.IsVisible = false;
        try
        {
            var (resultados, avisos, leerMs, puntuarMs, modelos, almacen) = await Task.Run(() =>
            {
                var contexto = Android.App.Application.Context;
                var lector = new LectorDeAppsAndroid(contexto);
                var t = Stopwatch.StartNew();
                var apps = lector.Leer();
                var leer = t.ElapsedMilliseconds;
                t.Restart();
                var almacen = AlmacenDeConfianza.Cargar(RutasDeNexo.Confiadas(contexto), out var avisoConfianza);
                if (avisoConfianza != null) lector.Avisos.Add(avisoConfianza);
                if (almacen.Podar(apps) > 0) almacen.Guardar(RutasDeNexo.Confiadas(contexto));
                var res = Puntuador.Value.EvaluarTodas(apps, almacen.Vigentes(apps));
                Android.Util.Log.Info("NEXO", "APPS tiempos " + string.Join(" ", lector.Tiempos.Select(k => k.Key + "=" + k.Value)));
                return (res, lector.Avisos, leer, t.ElapsedMilliseconds, apps, almacen);
            });
            var usuario = resultados.Where(r => r.Nivel != NivelDeRiesgo.NoEvaluada).ToList();
            int prio = usuario.Count(r => r.Nivel == NivelDeRiesgo.Prioritaria), rev = usuario.Count(r => r.Nivel == NivelDeRiesgo.ARevisar);
            int confiadas = usuario.Count(r => r.Nivel == NivelDeRiesgo.Confiada);
            int normales = usuario.Count(r => r.Nivel == NivelDeRiesgo.Normal);
            _aRevisar = prio + rev;
            _listo = true;
            PonerTitular();
            _resumen.Text = $"{usuario.Count} apps instaladas por ti" + (confiadas > 0 ? $" · {confiadas} de confianza" : "") + (prio > 0 ? $" · {prio} con prioridad" : "") + ".";
            _pie.Text = $"Lectura {leerMs} ms · puntuación {puntuarMs} ms" + (avisos.Count > 0 ? "\n" + string.Join("\n", avisos) : "");
            Android.Util.Log.Info("NEXO", $"APPS usuario={usuario.Count} prioritarias={prio} a_revisar={rev} normales={normales} leer_ms={leerMs} puntuar_ms={puntuarMs} avisos={avisos.Count}");

            foreach (var r in usuario.Where(r => r.Nivel is NivelDeRiesgo.Prioritaria or NivelDeRiesgo.ARevisar))
                _filas.Children.Add(Destacar(r.Paquete, TarjetaARevisar(r, modelos.First(m => m.Paquete == r.Paquete), almacen)));
            if (_aRevisar == 0)
                _filas.Children.Add(Retro.Texto("Ninguna app tiene señales de riesgo. Si instalas una nueva y activas «Avisos», Nexo te avisará.", Retro.Cuerpo));
            var deConfianza = usuario.Where(r => r.Nivel == NivelDeRiesgo.Confiada).ToList();
            if (deConfianza.Count > 0) _filas.Children.Add(SeccionDeConfianza(deConfianza, almacen));

            _ultimosResultados = resultados;
            _guardar.IsVisible = HistorialDeObsidian.Activado(Android.App.Application.Context);
            await CalcularHuellasAsync(modelos, resultados);
            ExplicarSiNoSeDestaco(resultados);
        }
        catch (Exception ex) { _titular.Text = "No se pudo revisar las apps"; _resumen.Text = ex.Message; }
        _releer.IsEnabled = true;
    }

    /// <summary>Huellas SHA-256 de los APK (3.2): con cache, en segundo plano y cancelable. Compara contra las listas de la carpeta «listas».</summary>
    private async Task CalcularHuellasAsync(IReadOnlyList<ModeloDeApp> modelos, IReadOnlyList<ResultadoDeApp> resultados)
    {
        _cancelar?.Cancel();
        _cancelar = new CancellationTokenSource();
        var ct = _cancelar.Token;
        var contexto = Android.App.Application.Context;
        var rutaCache = RutasDeNexo.Cache(contexto);
        var carpetaListas = RutasDeNexo.CarpetaDeListas(contexto);
        _huellas.Text = "Huellas: calculando...";
        var progreso = new Progress<(int Hechas, int Total)>(p => _huellas.Text = $"Huellas: {p.Hechas}/{p.Total} apps...");
        try
        {
            var (res, avisoCache, ms) = await Task.Run(() =>
            {
                var cache = CacheDeHuellas.Cargar(rutaCache, out var aviso);
                var t = Stopwatch.StartNew();
                try { return (new CalculadorDeHuellas(new OrigenDeApksEnDisco(), cache).Calcular(modelos, progreso, ct), aviso, t.ElapsedMilliseconds); }
                finally { cache.Guardar(rutaCache); }
            });
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
                _filas.Children.Insert(0, Destacar(coincidencias[i].Paquete, TarjetaDeCoincidencia(coincidencias[i], nombres)));
            _coincidencias = coincidencias.Count;
            PonerTitular();
            var r2 = res.Resumen;
            _huellas.Text = (r2.Calculadas > 0 ? $"Huellas: {r2.Calculadas} calculadas ({r2.BytesLeidos / 1048576} MiB en {ms / 1000.0:0.#} s)" : "Huellas: todo desde la caché")
                          + (r2.Fallidas > 0 ? $" · {r2.Fallidas} no se pudieron leer" : "") + ". "
                          + (listas.Count == 0 ? "Sin listas de huellas conocidas: no se compara nada." : $"Comparadas con {listas.Sum(l => l.Cantidad)} huellas de {listas.Count} lista(s).")
                          + (avisoCache != null ? "\n" + avisoCache : "") + (avisosListas.Count > 0 ? "\n" + string.Join("\n", avisosListas) : "");
            Android.Util.Log.Info("NEXO", $"HUELLAS calculadas={r2.Calculadas} cache={r2.DeCache} fallidas={r2.Fallidas} podadas={r2.Podadas} mib={r2.BytesLeidos / 1048576} ms={ms} listas={listas.Count} huellas_en_listas={listas.Sum(l => l.Cantidad)} coincidencias={coincidencias.Count}"
                + string.Concat(coincidencias.Select(c => " COINCIDE=" + c.Paquete + "/" + c.Lista)));
        }
        catch (OperationCanceledException) { /* salio de la pantalla: lo calculado ya quedo en la cache */ }
        catch (Exception ex) { _huellas.Text = "Huellas: no se pudieron calcular: " + ex.Message; }
    }

    /// <summary>
    /// Si la tarjeta es de la app del aviso, la marca (borde negro grueso y «DEL AVISO») y la pone a la vista. Solo la primera:
    /// una coincidencia de huella llega despues y va arriba, pero si ya se marco la tarjeta de riesgo no se mueve la vista otra vez.
    /// </summary>
    private Control Destacar(string paquete, Border tarjeta)
    {
        if (_destacada || _destacar is null || paquete != _destacar) return tarjeta;
        _destacada = true;
        tarjeta.BorderBrush = Brushes.Black;
        tarjeta.BorderThickness = new Thickness(4);
        var envoltura = new StackPanel { Spacing = 0 };
        envoltura.Children.Add(new Border
        {
            Background = Brushes.Black,
            Padding = new Thickness(10, 4),
            HorizontalAlignment = HorizontalAlignment.Left,
            Child = Retro.Texto("DEL AVISO", Retro.Secundario, true, Brushes.White),
        });
        envoltura.Children.Add(tarjeta);
        // Se espera al diseño (layout) para que BringIntoView sepa donde quedo la tarjeta dentro del ScrollViewer.
        Avalonia.Threading.Dispatcher.UIThread.Post(() => envoltura.BringIntoView(), Avalonia.Threading.DispatcherPriority.Background);
        Android.Util.Log.Info("NEXO", "VER destacada=" + paquete);
        return envoltura;
    }

    /// <summary>La app del aviso puede no tener tarjeta: se desinstalo, el usuario confio en ella, o ya no tiene señales. Se dice, en vez de abrir la lista sin explicacion.</summary>
    private void ExplicarSiNoSeDestaco(IReadOnlyList<ResultadoDeApp> resultados)
    {
        if (_destacar is null || _destacada) return;
        var r = resultados.FirstOrDefault(x => x.Paquete == _destacar);
        var nombre = r is null || string.IsNullOrEmpty(r.Nombre) ? _destacar : r.Nombre;
        _avisoDestacar.Text = r is null ? $"La app del aviso ({_destacar}) ya no está instalada."
            : r.Nivel == NivelDeRiesgo.Confiada ? $"«{nombre}», la app del aviso, está entre las apps en las que confías."
            : $"«{nombre}», la app del aviso, ya no tiene señales de riesgo ni coincide con una huella.";
        _avisoDestacar.IsVisible = true;
        Android.Util.Log.Info("NEXO", "VER sin_tarjeta=" + _destacar + " instalada=" + (r is not null));
    }

    /// <summary>Tarjeta con franja de color a la izquierda: rojo, ambar o verde segun el caso.</summary>
    private static Border Tarjeta(IBrush franja, Control contenido)
    {
        var rejilla = new Grid { ColumnDefinitions = new ColumnDefinitions("10,*") };
        rejilla.Children.Add(new Border { Background = franja });
        Grid.SetColumn(contenido, 1);
        rejilla.Children.Add(contenido);
        return new Border { Background = Brushes.White, BorderBrush = Retro.GrisClaro, BorderThickness = new Thickness(2), Child = rejilla };
    }

    private static Control Cabecera(string etiqueta, IBrush color, ResultadoDeApp r)
    {
        var p = new StackPanel { Spacing = 2 };
        p.Children.Add(Retro.Texto(etiqueta, Retro.Secundario, true, color));
        p.Children.Add(Retro.Texto(string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre, Retro.Titulo, true));
        p.Children.Add(Retro.Texto(r.Paquete, Retro.Secundario, false, Retro.Gris));
        return p;
    }

    /// <summary>Primer motivo siempre visible; «Ver los N motivos» despliega el resto. Asi una app con 7 motivos no ocupa tres pantallas.</summary>
    private static Control Motivos(IReadOnlyList<string> motivos)
    {
        var p = new StackPanel { Spacing = 4 };
        if (motivos.Count == 0) return p;
        p.Children.Add(Retro.Texto("• " + motivos[0], Retro.Cuerpo));
        if (motivos.Count == 1) return p;
        var resto = new StackPanel { Spacing = 4, IsVisible = false };
        foreach (var m in motivos.Skip(1)) resto.Children.Add(Retro.Texto("• " + m, Retro.Secundario, false, Retro.Gris));
        var alternar = Retro.BotonGrande($"Ver los {motivos.Count} motivos", () => { });
        alternar.Click += (_, _) =>
        {
            resto.IsVisible = !resto.IsVisible;
            alternar.Content = new TextBlock { Text = resto.IsVisible ? "Ocultar los motivos" : $"Ver los {motivos.Count} motivos", FontSize = Retro.Cuerpo, HorizontalAlignment = HorizontalAlignment.Center };
        };
        p.Children.Add(resto);
        p.Children.Add(alternar);
        return p;
    }

    /// <summary>El boton pide DOS toques: confiar quita a la app de las alertas, y no debe ser un toque por accidente.</summary>
    private Button BotonDeConfianza(ModeloDeApp modelo, AlmacenDeConfianza almacen)
    {
        var boton = Retro.BotonGrande("Confío en esta app", () => { });
        bool pedida = false;
        boton.Click += (_, _) =>
        {
            if (!pedida)
            {
                pedida = true;
                boton.Content = new TextBlock { Text = "Toca otra vez para confirmar: confío en esta app", FontSize = Retro.Cuerpo, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center };
                return;
            }
            if (almacen.Confiar(modelo)) almacen.Guardar(RutasDeNexo.Confiadas(Android.App.Application.Context));
            _ = RevisarAsync();
        };
        return boton;
    }

    private Border TarjetaARevisar(ResultadoDeApp r, ModeloDeApp modelo, AlmacenDeConfianza almacen)
    {
        bool prioridad = r.Nivel == NivelDeRiesgo.Prioritaria;
        var color = prioridad ? Retro.Rojo : Ambar;
        var p = new StackPanel { Spacing = 8, Margin = new Thickness(12) };
        p.Children.Add(Cabecera((prioridad ? "A REVISAR CON PRIORIDAD" : "A REVISAR") + " · " + r.Puntos + " pts", color, r));
        p.Children.Add(Motivos(r.Motivos));
        p.Children.Add(BotonDeConfianza(modelo, almacen));
        return Tarjeta(color, p);
    }

    private static Border TarjetaDeCoincidencia(Coincidencia c, IReadOnlyDictionary<string, string> nombres)
    {
        var p = new StackPanel { Spacing = 6, Margin = new Thickness(12) };
        p.Children.Add(Retro.Texto("COINCIDE CON UNA HUELLA CONOCIDA", Retro.Secundario, true, Retro.Rojo));
        p.Children.Add(Retro.Texto(nombres.GetValueOrDefault(c.Paquete, c.Paquete), Retro.Titulo, true));
        p.Children.Add(Retro.Texto(c.Paquete, Retro.Secundario, false, Retro.Gris));
        p.Children.Add(Retro.Texto($"El archivo {c.Archivo} es idéntico, byte a byte, a una huella de la lista «{c.Lista}». Es una coincidencia exacta con esa copia, no un análisis de la app.", Retro.Cuerpo));
        return Tarjeta(Retro.Rojo, p);
    }

    /// <summary>«Apps en las que confías (N)»: plegada, se abre al tocar. Cada una conserva sus puntos y motivos, y se puede dejar de confiar.</summary>
    private Control SeccionDeConfianza(IReadOnlyList<ResultadoDeApp> apps, AlmacenDeConfianza almacen)
    {
        var contenido = new StackPanel { Spacing = 10, IsVisible = false };
        foreach (var r in apps)
        {
            var p = new StackPanel { Spacing = 8, Margin = new Thickness(12) };
            p.Children.Add(Cabecera("DE CONFIANZA · " + r.Puntos + " pts", Retro.Verde, r));
            p.Children.Add(Motivos(r.Motivos));
            p.Children.Add(Retro.BotonGrande("Dejar de confiar", () =>
            {
                almacen.DejarDeConfiar(r.Paquete);
                almacen.Guardar(RutasDeNexo.Confiadas(Android.App.Application.Context));
                _ = RevisarAsync();
            }));
            contenido.Children.Add(Tarjeta(Retro.Verde, p));
        }
        var titulo = new TextBlock { Text = $"Apps en las que confías ({apps.Count})  ▸", FontSize = Retro.Cuerpo, FontWeight = FontWeight.Bold, HorizontalAlignment = HorizontalAlignment.Left };
        var boton = new Button { Content = titulo, MinHeight = 56, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new Thickness(12, 6) };
        boton.Click += (_, _) =>
        {
            contenido.IsVisible = !contenido.IsVisible;
            titulo.Text = $"Apps en las que confías ({apps.Count})  " + (contenido.IsVisible ? "▾" : "▸");
        };
        var seccion = new StackPanel { Spacing = 10, Margin = new Thickness(0, 6, 0, 0) };
        seccion.Children.Add(boton);
        seccion.Children.Add(contenido);
        return seccion;
    }
}
