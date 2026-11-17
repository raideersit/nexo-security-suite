using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Android.Content;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Historial opcional en Obsidian (§3.9) con el estilo «Classic tactil v2»: titular (apagado / guardando y cuantas notas hay), una tarjeta con
/// el interruptor y lo que se guarda (y lo que no), y las ultimas notas escritas, leidas del propio vault.
/// </summary>
public sealed class PantallaHistorial : UserControl
{
    private const int UltimasAMostrar = 5;
    private const string PaqueteObsidian = "md.obsidian";

    private readonly TextBlock _titular = Retro.Texto("", 24, true);
    private readonly TextBlock _resumen = Retro.Texto("", Retro.Cuerpo);
    private readonly TextBlock _mensaje = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly Border _franja = new();
    private readonly StackPanel _ultimas = new() { Spacing = 10 };
    private readonly Button _guardar, _abrirObsidian;

    public PantallaHistorial()
    {
        var contexto = Android.App.Application.Context;

        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_resumen);
        cabecera.Children.Add(_mensaje);
        _mensaje.IsVisible = false;

        Retro.InterruptorRetro interruptor = null!;
        bool reponiendo = false;
        var fila = Retro.FilaConInterruptor("Guardar un historial en Obsidian", "En la carpeta Documents/Nexo del teléfono. Apagado, Nexo no escribe nada fuera de la app.",
            HistorialDeObsidian.Activado(contexto), activado =>
            {
                if (reponiendo) return;
                try
                {
                    if (activado) HistorialDeObsidian.Activar(contexto); else HistorialDeObsidian.Desactivar(contexto);
                    Mensaje(null);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
                {
                    HistorialDeObsidian.Desactivar(contexto);
                    reponiendo = true; interruptor.Activado = false; reponiendo = false;
                    Mensaje("No se pudo escribir en " + HistorialDeObsidian.Carpeta() + ": " + ex.Message);
                }
                Refrescar();
            }, out interruptor);

        var cuerpo = new StackPanel { Spacing = 6, Margin = new Thickness(12, 8) };
        cuerpo.Children.Add(fila);
        cuerpo.Children.Add(Retro.Texto("Se guarda: cada aviso de apps, las revisiones que guardes desde «Apps» y el chequeo del equipo. Solo las apps «a revisar», nunca la lista completa de lo que tienes instalado.", Retro.Secundario, false, Retro.Gris));
        cuerpo.Children.Add(Retro.Texto("Las notas de más de 90 días se borran solas.", Retro.Secundario, false, Retro.Gris));

        _guardar = Retro.BotonGrande("Guardar el chequeo del equipo ahora", GuardarChequeo, destacado: true);
        _abrirObsidian = Retro.BotonGrande("Abrir Obsidian", () =>
        {
            var i = contexto.PackageManager?.GetLaunchIntentForPackage(PaqueteObsidian);
            if (i is null) return;
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        });

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));
        raiz.Children.Add(Tarjeta(_franja, cuerpo));
        raiz.Children.Add(_guardar);
        raiz.Children.Add(_abrirObsidian);
        raiz.Children.Add(_ultimas);
        Content = new ScrollViewer { Content = raiz };
        Refrescar();
    }

    private static Border Tarjeta(Border franja, Control contenido)
    {
        var rejilla = new Grid { ColumnDefinitions = new ColumnDefinitions("10,*") };
        rejilla.Children.Add(franja);
        Grid.SetColumn(contenido, 1);
        rejilla.Children.Add(contenido);
        return new Border { Background = Brushes.White, BorderBrush = Retro.GrisClaro, BorderThickness = new Thickness(2), Child = rejilla };
    }

    private void Mensaje(string? texto)
    {
        _mensaje.Text = texto ?? "";
        _mensaje.IsVisible = texto is not null;
    }

    private async void GuardarChequeo()
    {
        var lista = EquipoAhora.Evaluar(EquipoAhora.Leer());
        try
        {
            await Task.Run(() => HistorialDeObsidian.Escribir(new[] { EventosDeApps.DelChequeo(lista) }));
            Mensaje("Chequeo guardado.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        { Mensaje("No se pudo guardar el chequeo: " + ex.Message); }
        Refrescar();
    }

    private void Refrescar()
    {
        var contexto = Android.App.Application.Context;
        bool on = HistorialDeObsidian.Activado(contexto);
        bool hayObsidian = contexto.PackageManager?.GetLaunchIntentForPackage(PaqueteObsidian) is not null;
        _franja.Background = on ? Retro.Verde : Retro.GrisClaro;
        _guardar.IsVisible = on;
        _abrirObsidian.IsVisible = on && hayObsidian;
        _ultimas.Children.Clear();

        if (!on)
        {
            _titular.Text = "Historial apagado"; _titular.Foreground = Brushes.Black;
            _resumen.Text = "Si usas Obsidian, actívalo para guardar ahí los avisos y el chequeo del equipo como notas.";
            return;
        }
        _titular.Foreground = Retro.Verde;
        _titular.Text = "Guardando en Obsidian";
        _resumen.Text = "Leyendo las notas...";
        _ = Task.Run(() =>
        {
            var notas = LeerUltimas(HistorialDeObsidian.Carpeta(), out int total);
            Dispatcher.UIThread.Post(() => PintarUltimas(notas, total, hayObsidian));
        });
    }

    private void PintarUltimas(IReadOnlyList<(string Titulo, DateTime Fecha)> notas, int total, bool hayObsidian)
    {
        if (!HistorialDeObsidian.Activado(Android.App.Application.Context)) return;
        _resumen.Text = (total == 0 ? "Todavía no hay notas de eventos." : total == 1 ? "1 nota de evento." : $"{total} notas de eventos.")
                        + " Carpeta: Documents/Nexo." + (hayObsidian ? "" : " Obsidian no está instalado en este teléfono: las notas se pueden copiar a otro equipo.");
        _ultimas.Children.Clear();
        if (notas.Count == 0) return;
        var lista = new StackPanel { Spacing = 10 };
        foreach (var (titulo, fecha) in notas)
        {
            var p = new StackPanel { Spacing = 2, Margin = new Thickness(12, 8) };
            p.Children.Add(Retro.Texto(fecha.ToString("dd-MM-yyyy HH:mm"), Retro.Secundario, true, Retro.Gris));
            p.Children.Add(Retro.Texto(titulo, Retro.Cuerpo));
            lista.Children.Add(Retro.Tarjeta(Retro.GrisClaro, p));
        }
        _ultimas.Children.Add(Retro.SeccionPlegable($"Últimas notas ({notas.Count})", lista, abierta: true));
    }

    /// <summary>Las notas mas recientes de «02 Eventos» (titulo = primera linea «# ...»). Nunca lanza: si no se puede leer, no hay lista.</summary>
    private static IReadOnlyList<(string Titulo, DateTime Fecha)> LeerUltimas(string vault, out int total)
    {
        total = 0;
        try
        {
            var carpeta = Path.Combine(vault, "02 Eventos");
            if (!Directory.Exists(carpeta)) return Array.Empty<(string, DateTime)>();
            var archivos = new DirectoryInfo(carpeta).EnumerateFiles("*.md", SearchOption.AllDirectories).ToList();
            total = archivos.Count;
            return archivos.OrderByDescending(f => f.LastWriteTime).Take(UltimasAMostrar)
                .Select(f => (Titulo(f.FullName) ?? Path.GetFileNameWithoutExtension(f.Name), f.LastWriteTime)).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Android.Util.Log.Warn("NEXO", "HISTORIAL no se pudieron leer las notas: " + ex.Message);
            return Array.Empty<(string, DateTime)>();
        }
    }

    private static string? Titulo(string ruta)
    {
        foreach (var linea in File.ReadLines(ruta).Take(40))
            if (linea.StartsWith("# ", StringComparison.Ordinal)) return linea[2..].Trim();
        return null;
    }
}
