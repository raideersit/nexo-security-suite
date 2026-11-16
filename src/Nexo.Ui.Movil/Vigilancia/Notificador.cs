using System;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics.Drawables;
using Android.OS;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Ui.Movil.Vigilancia;

public static class Notificador
{
    public const string Canal = "revision_de_apps";

    /// <summary>En Android 13+ hay que tener concedido POST_NOTIFICATIONS; antes no se pide.</summary>
    public static bool PuedeNotificar(Context c) =>
        !OperatingSystem.IsAndroidVersionAtLeast(33) || c.CheckSelfPermission("android.permission.POST_NOTIFICATIONS") == Permission.Granted;

    public static void Mostrar(Context c, AlertaDeInstalacion a)
    {
        var gestor = (NotificationManager)c.GetSystemService(Context.NotificationService)!;
        gestor.CreateNotificationChannel(new NotificationChannel(Canal, "Avisos de apps nuevas", NotificationImportance.Default)
        { Description = "Avisa cuando se instala o actualiza una app que conviene revisar." });

        var abrir = c.PackageManager!.GetLaunchIntentForPackage(c.PackageName!);
        abrir?.AddFlags(ActivityFlags.NewTask | ActivityFlags.ClearTop);
        var pi = PendingIntent.GetActivity(c, a.Paquete.GetHashCode(), abrir, PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);

        var n = new Notification.Builder(c, Canal)
            .SetSmallIcon(Android.Resource.Drawable.IcDialogInfo)
            .SetContentTitle(a.Titulo)
            .SetContentText(a.Texto)
            .SetStyle(new Notification.BigTextStyle().BigText(a.Texto))
            .SetContentIntent(pi)
            .SetAutoCancel(true)
            .AddAction(new Notification.Action.Builder(Icon.CreateWithResource(c, Android.Resource.Drawable.IcMenuView), "Ver", pi).Build())
            .Build();
        gestor.Notify(a.Paquete.GetHashCode(), n);
    }
}
