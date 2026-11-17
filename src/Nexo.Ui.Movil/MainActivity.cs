using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Nexo.Ui.Movil.Vigilancia;
using Avalonia;
using Avalonia.Android;
using System;

namespace Nexo.Ui.Movil;

[Activity(
    Label = "Nexo",
    Theme = "@style/NexoTema",
    MainLauncher = true,
    // SingleTop: si Nexo ya esta abierto, el «Ver» de una notificacion llega por OnNewIntent en vez de crear otra actividad encima.
    LaunchMode = LaunchMode.SingleTop,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public sealed class MainActivity : AvaloniaMainActivity<App>
{
    private ReceptorDeInstalacion? _receptor;

    /// <summary>Para que la pantalla «Estado» pueda pedir el permiso de notificaciones.</summary>
    public static MainActivity? Actual { get; private set; }

    /// <summary>Se dispara cada vez que la app vuelve al primer plano (por ejemplo al cerrarse el dialogo de un permiso): las pantallas refrescan lo que dependia de el.</summary>
    public static event Action? Reanudada;

    /// <summary>Extra del intent de una notificacion: a donde llevar (ver <see cref="Destino"/>: una app, «estado» o «inicio»).</summary>
    public const string ExtraDestino = "io.github.raideersit.nexo.DESTINO";

    /// <summary>Destino pedido por una notificacion que la interfaz todavia no mostro (la app arrancaba en frio). Se consume una vez.</summary>
    public static string? DestinoPendiente { get; private set; }

    /// <summary>Se dispara cuando se toca una notificacion con la app ya abierta.</summary>
    public static event Action<string>? DestinoPedido;

    public static string? TomarDestinoPendiente()
    {
        var d = DestinoPendiente;
        DestinoPendiente = null;
        return d;
    }

    /// <summary>Extra con el id de la notificacion que se toco, para borrarla (el boton «Ver» no la borra solo).</summary>
    public const string ExtraNotificacion = "io.github.raideersit.nexo.NOTIFICACION";

    private string? DestinoDe(Intent? intent)
    {
        var d = intent?.GetStringExtra(ExtraDestino);
        if (string.IsNullOrWhiteSpace(d)) return null;
        if (intent!.HasExtra(ExtraNotificacion))
            ((Android.App.NotificationManager)GetSystemService(NotificationService)!).Cancel(intent.GetIntExtra(ExtraNotificacion, 0));
        return d;
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Intent = intent;
        if (DestinoDe(intent) is not { } d) return;
        Android.Util.Log.Info("NEXO", "VER destino=" + d + " (app abierta)");
        if (DestinoPedido is null) DestinoPendiente = d; else DestinoPedido.Invoke(d);
    }

    protected override void OnResume()
    {
        base.OnResume();
        Reanudada?.Invoke();
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) => base.CustomizeAppBuilder(builder);

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        // Arranque en frio desde el «Ver». Va ANTES de base.OnCreate: Avalonia monta PantallaPrincipal ahi dentro, y esta busca el pendiente
        // al conectarse (probado en el S20 FE: puesto despues, el aviso abria el inicio). Si Android recrea la actividad (savedInstanceState),
        // el intent es el viejo: no se vuelve a navegar.
        if (savedInstanceState is null && DestinoDe(Intent) is { } destino)
        {
            Android.Util.Log.Info("NEXO", "VER destino=" + destino + " (arranque)");
            DestinoPendiente = destino;
        }
        base.OnCreate(savedInstanceState);
        Actual = this;
        // Por si la interfaz ya estaba conectada y suscrita sin haber visto el pendiente: se le entrega ahora.
        if (DestinoPedido is not null && TomarDestinoPendiente() is { } tarde) DestinoPedido.Invoke(tarde);
        // Los canales aparecen en los ajustes de Android desde el primer arranque, antes de cualquier aviso.
        Notificador.CrearCanales(this);
        // Si los avisos estan activados pero Android perdio el trabajo periodico, se reprograma al abrir la app.
        ConfiguracionDeVigilancia.Reparar(this);
        // Camino «instantaneo» de la revision al instalar: solo mientras la app esta abierta.
        _receptor = new ReceptorDeInstalacion();
        RegisterReceiver(_receptor, ReceptorDeInstalacion.Filtro());
    }

    protected override void OnDestroy()
    {
        if (_receptor != null) { UnregisterReceiver(_receptor); _receptor = null; }
        if (ReferenceEquals(Actual, this)) Actual = null;
        base.OnDestroy();
    }

    public void PedirPermisoDeNotificaciones()
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(33) || Notificador.PuedeNotificar(this)) return;
        GetSharedPreferences("nexo", FileCreationMode.Private)!.Edit()!.PutBoolean("permiso_notificaciones_pedido", true)!.Apply();
        RequestPermissions(new[] { "android.permission.POST_NOTIFICATIONS" }, 7);
    }

    /// <summary>
    /// Si Nexo ya pidio el permiso alguna vez. Android no lo dice: «no mostrar la explicacion» vale igual para «nunca se pidio» que para
    /// «se nego dos veces y ya no sale el dialogo». Con esto se distingue, y en el segundo caso se lleva al usuario a los ajustes.
    /// </summary>
    public bool YaSePidioElPermiso => GetSharedPreferences("nexo", FileCreationMode.Private)!.GetBoolean("permiso_notificaciones_pedido", false);
}
