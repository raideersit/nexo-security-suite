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

    /// <summary>Extra del intent de una notificacion: el paquete de la app que hay que mostrar.</summary>
    public const string ExtraPaquete = "io.github.raideersit.nexo.PAQUETE";

    /// <summary>Paquete pedido por una notificacion que la interfaz todavia no mostro (la app arrancaba en frio). Se consume una vez.</summary>
    public static string? PaquetePendiente { get; private set; }

    /// <summary>Se dispara cuando llega un «Ver» con la app ya abierta.</summary>
    public static event Action<string>? AppPedida;

    public static string? TomarPaquetePendiente()
    {
        var p = PaquetePendiente;
        PaquetePendiente = null;
        return p;
    }

    private static string? PaqueteDe(Intent? intent)
    {
        var p = intent?.GetStringExtra(ExtraPaquete);
        return string.IsNullOrWhiteSpace(p) ? null : p;
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Intent = intent;
        if (PaqueteDe(intent) is not { } p) return;
        Android.Util.Log.Info("NEXO", "VER paquete=" + p + " (app abierta)");
        if (AppPedida is null) PaquetePendiente = p; else AppPedida.Invoke(p);
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
        if (savedInstanceState is null && PaqueteDe(Intent) is { } paquete)
        {
            Android.Util.Log.Info("NEXO", "VER paquete=" + paquete + " (arranque)");
            PaquetePendiente = paquete;
        }
        base.OnCreate(savedInstanceState);
        Actual = this;
        // Por si la interfaz ya estaba conectada y suscrita sin haber visto el pendiente: se le entrega ahora.
        if (AppPedida is not null && TomarPaquetePendiente() is { } tarde) AppPedida.Invoke(tarde);
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
        if (OperatingSystem.IsAndroidVersionAtLeast(33) && !Notificador.PuedeNotificar(this))
            RequestPermissions(new[] { "android.permission.POST_NOTIFICATIONS" }, 7);
    }
}
