using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.App.Admin;
using Android.Content;
using Android.Content.PM;
using Android.Net.Wifi;
using Android.OS;
using Android.Provider;

namespace Nexo.Ui.Movil.Estado;

/// <summary>
/// Fase 0: prueba en el telefono las APIs marcadas «por verificar» en la Salida 7.
/// Solo escribe cifras y nombres de paquetes de sistema/propios; nada sale del telefono.
/// </summary>
public static class SondasDeApi
{
    public static List<string> Ejecutar(Context contexto)
    {
        var r = new List<string> { $"Android {Build.VERSION.Release} (API {(int)Build.VERSION.SdkInt}), {Build.Manufacturer} {Build.Model}" };
        var gestor = contexto.PackageManager!;
#pragma warning disable CS0618, CA1422
        var paquetes = (OperatingSystem.IsAndroidVersionAtLeast(33)
            ? gestor.GetInstalledPackages(PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.Permissions))
            : gestor.GetInstalledPackages(PackageInfoFlags.Permissions)) ?? [];
#pragma warning restore CS0618, CA1422
        var deUsuario = paquetes.Where(p => p.ApplicationInfo is { } a && (a.Flags & ApplicationInfoFlags.System) == 0).ToList();

        Sonda(r, "1 APK legible y huella (3.1/3.2)", () =>
        {
            string Hashear(List<PackageInfo> lista)
            {
                int leidos = 0, fallos = 0; long bytes = 0; var t = Stopwatch.StartNew();
                foreach (var p in lista)
                {
                    try
                    {
                        using var f = File.OpenRead(p.ApplicationInfo!.SourceDir!);
                        using var sha = SHA256.Create();
                        sha.ComputeHash(f);
                        bytes += f.Length; leidos++;
                    }
                    catch { fallos++; }
                }
                return $"{leidos}/{lista.Count} leidos ({fallos} fallos), {bytes / 1048576} MiB, {t.ElapsedMilliseconds} ms";
            }
            var deSistema = paquetes.Except(deUsuario).ToList();
            return "usuario: " + Hashear(deUsuario) + " | sistema: " + Hashear(deSistema);
        });

        Sonda(r, "2 Superposicion concedida a otras apps", () => AppOpsContar(contexto, deUsuario, "android:system_alert_window", "SYSTEM_ALERT_WINDOW"));
        Sonda(r, "3 Instalar apps desconocidas concedido a otras apps", () => AppOpsContar(contexto, deUsuario, "android:request_install_packages", "REQUEST_INSTALL_PACKAGES"));

        Sonda(r, "4 Oyentes de notificaciones", () =>
        {
            var v = Settings.Secure.GetString(contexto.ContentResolver, "enabled_notification_listeners");
            return v is null ? "Settings.Secure devolvio null (no legible)" : $"legible: {(v.Length == 0 ? 0 : v.Split(':').Length)} oyente(s) activo(s)";
        });
        Sonda(r, "5 Servicios de Accesibilidad activos", () =>
        {
            var v = Settings.Secure.GetString(contexto.ContentResolver, "enabled_accessibility_services");
            return v is null ? "Settings.Secure devolvio null (no legible)" : $"legible: {(v.Length == 0 ? 0 : v.Split(':').Length)} servicio(s) activo(s)";
        });
        Sonda(r, "5b Accesibilidad por AccessibilityManager", () =>
        {
            var am = (Android.Views.Accessibility.AccessibilityManager)contexto.GetSystemService(Context.AccessibilityService)!;
            var l = am.GetEnabledAccessibilityServiceList(Android.AccessibilityServices.FeedbackFlags.AllMask);
            return $"{l?.Count ?? -1} servicio(s) activo(s)";
        });
        Sonda(r, "6 Administradores del dispositivo", () =>
        {
            var dpm = (DevicePolicyManager)contexto.GetSystemService(Context.DevicePolicyService)!;
            var l = dpm.ActiveAdmins;
            return l is null ? "ActiveAdmins devolvio null" : $"legible: {l.Count} administrador(es) activo(s)";
        });

        Sonda(r, "7 Origen de instalacion (3.1)", () =>
        {
            var por = new SortedDictionary<string, int>();
            foreach (var p in deUsuario)
            {
                var o = gestor.GetInstallSourceInfo(p.PackageName!).InstallingPackageName ?? "(ninguno: archivo suelto o adb)";
                por[o] = por.GetValueOrDefault(o) + 1;
            }
            return string.Join(", ", por.Select(k => $"{k.Key}={k.Value}"));
        });

        Sonda(r, "8 Wi-Fi sin cifrado, sin ubicacion (3.4)", () =>
        {
            var wm = (WifiManager)contexto.GetSystemService(Context.WifiService)!;
#pragma warning disable CS0618, CA1422
            var info = wm.ConnectionInfo;
#pragma warning restore CS0618, CA1422
            if (info is null || info.NetworkId == -1) return "Wi-Fi no conectado: sin dato (conecta el telefono a una red y repite)";
            var tipo = OperatingSystem.IsAndroidVersionAtLeast(31) ? info.CurrentSecurityType.ToString() : "n/d (API < 31)";
            var ssidOculto = info.SSID is null or "<unknown ssid>";
            return $"tipo de seguridad={tipo}; SSID visible sin permiso de ubicacion: {(ssidOculto ? "no" : "SI")}";
        });

        Sonda(r, "9 Escribir en Documents/Nexo sin MANAGE_EXTERNAL_STORAGE", () =>
        {
            var partes = new List<string>();
            // Via MediaStore (la ruta recomendada en Android 10+)
            try
            {
                var v = new ContentValues();
                v.Put(MediaStore.IMediaColumns.DisplayName, "prueba-nexo.md");
                v.Put(MediaStore.IMediaColumns.MimeType, "text/markdown");
                v.Put(MediaStore.IMediaColumns.RelativePath, "Documents/Nexo");
                var uri = contexto.ContentResolver!.Insert(MediaStore.Files.GetContentUri("external")!, v);
                if (uri is null) partes.Add("MediaStore: Insert devolvio null");
                else
                {
                    using (var s = contexto.ContentResolver.OpenOutputStream(uri)!) s.Write(Encoding.UTF8.GetBytes("# prueba\n"));
                    partes.Add("MediaStore: escribio OK");
                    contexto.ContentResolver.Delete(uri, null, null);
                }
            }
            catch (Exception ex) { partes.Add("MediaStore: " + ex.GetType().Name + " " + ex.Message); }
            // Via ruta directa
            try
            {
                var dir = Path.Combine(Android.OS.Environment.ExternalStorageDirectory!.AbsolutePath, "Documents", "Nexo");
                Directory.CreateDirectory(dir);
                var f = Path.Combine(dir, "prueba-nexo-directa.md");
                File.WriteAllText(f, "# prueba\n"); File.Delete(f);
                partes.Add("ruta directa: escribio OK");
            }
            catch (Exception ex) { partes.Add("ruta directa: " + ex.GetType().Name); }
            return string.Join("; ", partes);
        });
        return r;
    }

    private static string AppOpsContar(Context contexto, List<PackageInfo> apps, string op, string permiso)
    {
        var ops = (AppOpsManager)contexto.GetSystemService(Context.AppOpsService)!;
        int pidieron = 0, concedido = 0, errores = 0; string? error = null;
        foreach (var p in apps)
        {
            if (p.RequestedPermissions?.Contains("android.permission." + permiso) != true) continue;
            pidieron++;
            try
            {
#pragma warning disable CA1416, CS0618
                if (ops.CheckOpNoThrow(op, p.ApplicationInfo!.Uid, p.PackageName!) == AppOpsManagerMode.Allowed) concedido++;
#pragma warning restore CA1416, CS0618
            }
            catch (Exception ex) { errores++; error ??= ex.GetType().Name + ": " + ex.Message; }
        }
        return errores > 0 && concedido == 0 ? $"{pidieron} app(s) lo piden; consulta FALLA ({errores} errores, ej. {error})"
                                              : $"{pidieron} app(s) lo piden, {concedido} lo tienen concedido; consulta OK ({errores} errores)";
    }

    private static void Sonda(List<string> r, string nombre, Func<string> f)
    {
        try { r.Add($"{nombre}: {f()}"); }
        catch (Exception ex) { r.Add($"{nombre}: EXCEPCION {ex.GetType().Name}: {ex.Message}"); }
    }
}
