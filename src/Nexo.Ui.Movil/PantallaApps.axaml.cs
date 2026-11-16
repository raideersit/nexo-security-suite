using System;
using System.Diagnostics;
using System.Linq;
using Android.Content.PM;
using Android.OS;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace Nexo.Ui.Movil;

/// <summary>Fase 0: lee la lista de apps con PackageManager y mide cuanto tarda.</summary>
public sealed partial class PantallaApps : UserControl
{
    public PantallaApps()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("Releer")!.Click += (_, _) => Leer();
        Leer();
    }

    private void Leer()
    {
        var resumen = this.FindControl<TextBlock>("Resumen")!;
        var lista = this.FindControl<TextBlock>("Lista")!;
        try
        {
            var contexto = Android.App.Application.Context;
            var cronometro = Stopwatch.StartNew();
            var gestor = contexto.PackageManager!;
            // La sobrecarga con PackageInfoFlags.Of existe desde Android 13 (API 33); en 11 y 12 solo esta la antigua.
#pragma warning disable CS0618
            var paquetes = (OperatingSystem.IsAndroidVersionAtLeast(33)
                ? gestor.GetInstalledPackages(PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.Permissions))
                : gestor.GetInstalledPackages(PackageInfoFlags.Permissions)) ?? [];
#pragma warning restore CS0618
            cronometro.Stop();

            var deUsuario = paquetes.Where(p => p.ApplicationInfo is { } a && (a.Flags & ApplicationInfoFlags.System) == 0).ToList();
            resumen.Text = $"Android {Build.VERSION.Release} (API {(int)Build.VERSION.SdkInt}), parche {Build.VERSION.SecurityPatch}\n"
                         + $"{paquetes.Count} paquetes, {deUsuario.Count} instalados por el usuario.\n"
                         + $"Lectura: {cronometro.ElapsedMilliseconds} ms.";
            lista.Text = string.Join("\n", deUsuario.Select(p => $"{p.PackageName}  ({p.RequestedPermissions?.Count ?? 0} permisos)").OrderBy(s => s));
        }
        catch (System.Exception ex)
        {
            resumen.Text = "No se pudo leer la lista de apps: " + ex.Message;
            lista.Text = "";
        }
    }
}
