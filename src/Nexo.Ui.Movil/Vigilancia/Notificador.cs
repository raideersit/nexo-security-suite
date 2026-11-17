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

        // «Ver» abre la pantalla Apps en la tarjeta de ESTA app (no solo el inicio de Nexo). Intent explicito: solo lo recibe MainActivity.
        var abrir = new Intent(c, typeof(MainActivity));
        abrir.PutExtra(MainActivity.ExtraPaquete, a.Paquete);
        abrir.AddFlags(ActivityFlags.NewTask | ActivityFlags.SingleTop | ActivityFlags.ClearTop);
        // Un requestCode por paquete: con UpdateCurrent, cada notificacion conserva su propio paquete en el extra.
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
