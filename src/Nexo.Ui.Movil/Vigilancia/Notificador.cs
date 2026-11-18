using System;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics.Drawables;
using Android.OS;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Todas las notificaciones de Nexo. Un canal por tipo, para que el usuario pueda silenciar uno desde los ajustes de Android sin tocar los demas.
/// Tocar una notificacion abre la pantalla que corresponde (ver <see cref="Destino"/>).
/// </summary>
public static class Notificador
{
    public const string Canal = "revision_de_apps";
    public const string CanalEquipo = "estado_del_equipo";
    public const string CanalResumen = "resumen_semanal";

    // Ids estables (ver IdDeNotificacion): el mismo en la app abierta y en el trabajo periodico, asi un aviso nuevo REEMPLAZA al anterior.
    private static readonly int IdResumen = IdDeNotificacion.De("resumen");

    /// <summary>En Android 13+ hay que tener concedido POST_NOTIFICATIONS; antes no se pide.</summary>
    public static bool PuedeNotificar(Context c) =>
        !OperatingSystem.IsAndroidVersionAtLeast(33) || c.CheckSelfPermission("android.permission.POST_NOTIFICATIONS") == Permission.Granted;

    /// <summary>Crea (o deja como estan) los tres canales. Se llama al abrir la app, asi aparecen en los ajustes aunque todavia no haya llegado ningun aviso.</summary>
    public static void CrearCanales(Context c)
    {
        var gestor = Gestor(c);
        gestor.CreateNotificationChannel(new NotificationChannel(Canal, "Avisos de apps nuevas", NotificationImportance.Default)
        { Description = "Avisa cuando se instala o actualiza una app que conviene revisar." });
        gestor.CreateNotificationChannel(new NotificationChannel(CanalEquipo, "Estado del equipo", NotificationImportance.Default)
        { Description = "Avisa cuando algo del chequeo del equipo empeora: bloqueo de pantalla, depuración USB, Wi-Fi sin cifrado, parche antiguo..." });
        gestor.CreateNotificationChannel(new NotificationChannel(CanalResumen, "Resumen semanal", NotificationImportance.Low)
        { Description = "Una vez por semana, sin sonido: cuántas apps hay a revisar y cómo está el equipo." });
    }

    public static void Mostrar(Context c, AlertaDeInstalacion a)
    {
        CrearCanales(c);
        // «Ver» abre la pantalla Apps en la tarjeta de ESTA app (no solo el inicio de Nexo).
        int id = IdDeNotificacion.De(Destino.App(a.Paquete));
        var pi = Abrir(c, Destino.App(a.Paquete), id);
        var n = new Notification.Builder(c, Canal)
            .SetSmallIcon(Android.Resource.Drawable.IcDialogInfo)
            .SetContentTitle(a.Titulo)
            .SetContentText(a.Texto)
            .SetStyle(new Notification.BigTextStyle().BigText(a.Texto))
            .SetContentIntent(pi)
            .SetAutoCancel(true)
            .AddAction(new Notification.Action.Builder(Icon.CreateWithResource(c, Android.Resource.Drawable.IcMenuView), "Ver", pi).Build())
            .Build();
        Gestor(c).Notify(id, n);
    }

    /// <summary>Una notificacion por fila del chequeo (con su propio id): si empeoran dos cosas, se ven las dos.</summary>
    public static void MostrarEquipo(Context c, AvisoDelEquipo a)
    {
        CrearCanales(c);
        int id = IdDeNotificacion.De("equipo:" + a.Fila);
        var pi = Abrir(c, Destino.Estado, id);
        var n = new Notification.Builder(c, CanalEquipo)
            .SetSmallIcon(Android.Resource.Drawable.IcDialogAlert)
            .SetContentTitle(a.Titulo)
            .SetContentText(a.Texto)
            .SetStyle(new Notification.BigTextStyle().BigText(a.Texto))
            .SetContentIntent(pi)
            .SetAutoCancel(true)
            .AddAction(new Notification.Action.Builder(Icon.CreateWithResource(c, Android.Resource.Drawable.IcMenuView), "Ver", pi).Build())
            .Build();
        Gestor(c).Notify(id, n);
    }

    /// <summary>Siempre el mismo id: el resumen nuevo reemplaza al de la semana anterior si el usuario no lo descarto.</summary>
    public static void MostrarResumen(Context c, string titulo, string texto)
    {
        CrearCanales(c);
        var n = new Notification.Builder(c, CanalResumen)
            .SetSmallIcon(Android.Resource.Drawable.IcDialogInfo)
            .SetContentTitle(titulo)
            .SetContentText(texto)
            .SetStyle(new Notification.BigTextStyle().BigText(texto))
            .SetContentIntent(Abrir(c, Destino.Inicio, IdResumen))
            .SetAutoCancel(true)
            .Build();
        Gestor(c).Notify(IdResumen, n);
    }

    private static NotificationManager Gestor(Context c) => (NotificationManager)c.GetSystemService(Context.NotificationService)!;

    /// <summary>Intent explicito: solo lo recibe MainActivity. Un requestCode por notificacion para que, con UpdateCurrent, cada una conserve su destino.</summary>
    private static PendingIntent Abrir(Context c, string destino, int requestCode)
    {
        var abrir = new Intent(c, typeof(MainActivity));
        abrir.PutExtra(MainActivity.ExtraDestino, destino);
        // El boton «Ver» no borra la notificacion (SetAutoCancel solo vale para tocar el cuerpo): MainActivity la borra con este id.
        abrir.PutExtra(MainActivity.ExtraNotificacion, requestCode);
        abrir.AddFlags(ActivityFlags.NewTask | ActivityFlags.SingleTop | ActivityFlags.ClearTop);
        return PendingIntent.GetActivity(c, requestCode, abrir, PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent)!;
    }
}

/// <summary>A donde lleva tocar una notificacion. Se pasa como texto en el extra del intent.</summary>
public static class Destino
{
    public const string Estado = "estado";
    public const string Inicio = "inicio";
    /// <summary>Pantalla «Revisar» con lo que llego por «Compartir» (ver Revisar/Compartido.cs).</summary>
    public const string Revisar = "revisar";
    private const string PrefijoApp = "app:";

    public static string App(string paquete) => PrefijoApp + paquete;

    /// <summary>El paquete si el destino es una app; null si es otra pantalla.</summary>
    public static string? PaqueteDe(string destino) => destino.StartsWith(PrefijoApp, StringComparison.Ordinal) ? destino[PrefijoApp.Length..] : null;
}
