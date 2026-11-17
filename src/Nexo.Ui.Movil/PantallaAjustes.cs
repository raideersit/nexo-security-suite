using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Android.Content;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Ajustes con el estilo «Classic tactil v2»: tarjetas para las apps de confianza, las listas de huellas (cuantas y donde dejarlas),
/// el sonido de los avisos y «Acerca de». Nada de lo que hay aqui envia datos fuera del telefono.
/// </summary>
public sealed class PantallaAjustes : UserControl
{
    private readonly TextBlock _confianza = Retro.Texto("Contando...", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _listas = Retro.Texto("Leyendo...", Retro.Secundario, false, Retro.Gris);

    public PantallaAjustes(Action irApps)
    {
        var contexto = Android.App.Application.Context;
        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };

        // Apps de confianza: se administran en «Apps», donde se ven sus motivos.
        var confianza = new StackPanel { Spacing = 6, Margin = new Thickness(12, 8) };
        confianza.Children.Add(Retro.Texto("Apps de confianza", Retro.Titulo, true));
        confianza.Children.Add(_confianza);
        confianza.Children.Add(Retro.BotonGrande("Ver en «Apps»", irApps));
        raiz.Children.Add(Retro.Tarjeta(Retro.Verde, confianza));

        // Listas de huellas (§3.2): Nexo compara contra listas locales; todavia no las descarga solo.
        var listas = new StackPanel { Spacing = 6, Margin = new Thickness(12, 8) };
        listas.Children.Add(Retro.Texto("Listas de huellas conocidas", Retro.Titulo, true));
        listas.Children.Add(_listas);
        listas.Children.Add(Retro.Texto("Archivos .txt (una huella SHA-256 por línea) o .csv. Se dejan en:\n" + RutasDeNexo.CarpetaDeListas(contexto), Retro.Secundario, false, Retro.Gris));
        listas.Children.Add(Retro.Texto("La descarga automática desde MalwareBazaar está pendiente.", Retro.Secundario, false, Retro.Gris));
        raiz.Children.Add(Retro.Tarjeta(Retro.GrisClaro, listas));

        raiz.Children.Add(Retro.FilaQueNavega("Sonido de cada aviso", "Ajustes de notificaciones de Android, canal por canal.", () =>
        {
            var i = new Intent(Android.Provider.Settings.ActionAppNotificationSettings);
            i.PutExtra(Android.Provider.Settings.ExtraAppPackage, contexto.PackageName);
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        }));

        var info = new StackPanel { Spacing = 4 };
        info.Children.Add(Retro.Texto("Acerca de Nexo", Retro.Cuerpo, true));
        info.Children.Add(Retro.Texto($"Nexo móvil {Version(contexto)} · Android {Android.OS.Build.VERSION.Release} (API {(int)Android.OS.Build.VERSION.SdkInt})", Retro.Secundario, false, Retro.Gris));
        info.Children.Add(Retro.Texto("Revisa apps y ajustes y avisa de lo que se ve mal; no bloquea nada antes de que ocurra. Complementa a Google Play Protect, no lo reemplaza.", Retro.Secundario, false, Retro.Gris));
        info.Children.Add(Retro.Texto("Todo se calcula en el teléfono: Nexo no envía tus apps ni tus datos a ningún servidor.", Retro.Secundario, false, Retro.Gris));
        raiz.Children.Add(Retro.Hundido(info, 12));

        Content = new ScrollViewer { Content = raiz };
        _ = Task.Run(Contar);
    }

    private static string Version(Context c)
    {
        try { return c.PackageManager!.GetPackageInfo(c.PackageName!, 0)!.VersionName ?? "?"; }
        catch (Exception) { return "?"; }
    }

    /// <summary>Cuenta las apps de confianza y las listas fuera del hilo de la pantalla (leer las apps toma ~1 s).</summary>
    private void Contar()
    {
        var c = Android.App.Application.Context;
        string textoConfianza, textoListas;
        try
        {
            int n = EquipoAhora.LeerApps().DeConfianza;
            textoConfianza = n == 0 ? "Ninguna. Se marcan con «Confío en esta app» en la tarjeta de cada app a revisar."
                : (n == 1 ? "1 app de confianza." : $"{n} apps de confianza.") + " No avisan por su riesgo, pero sí si coinciden con una huella conocida.";
        }
        catch (Exception ex) { textoConfianza = "No se pudieron contar: " + ex.Message; }

        var carpeta = RutasDeNexo.CarpetaDeListas(c);
        var leidas = new List<ListaDeHuellas>();
        var malas = new List<string>();
        if (Directory.Exists(carpeta))
            foreach (var f in Directory.EnumerateFiles(carpeta).Where(f => f.EndsWith(".txt") || f.EndsWith(".csv")).OrderBy(f => f))
            {
                try { leidas.Add(ListaDeHuellas.DesdeArchivo(f)); }
                catch (Exception ex) when (ex is InvalidDataException or IOException) { malas.Add(Path.GetFileName(f) + ": " + ex.Message); }
            }
        textoListas = leidas.Count == 0 ? "Ninguna lista: Nexo no compara las apps con huellas conocidas."
            : $"{leidas.Count} lista(s), {leidas.Sum(l => l.Cantidad)} huellas: " + string.Join(", ", leidas.Select(l => l.Nombre)) + ".";
        if (malas.Count > 0) textoListas += "\nNo se pudieron leer: " + string.Join("; ", malas);

        Dispatcher.UIThread.Post(() => { _confianza.Text = textoConfianza; _listas.Text = textoListas; });
    }
}
