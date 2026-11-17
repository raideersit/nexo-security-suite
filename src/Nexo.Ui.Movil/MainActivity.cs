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
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public sealed class MainActivity : AvaloniaMainActivity<App>
{
    private ReceptorDeInstalacion? _receptor;

    /// <summary>Para que la pantalla «Estado» pueda pedir el permiso de notificaciones.</summary>
    public static MainActivity? Actual { get; private set; }

    /// <summary>Se dispara cada vez que la app vuelve al primer plano (por ejemplo al cerrarse el dialogo de un permiso): las pantallas refrescan lo que dependia de el.</summary>
    public static event Action? Reanudada;

    protected override void OnResume()
    {
        base.OnResume();
        Reanudada?.Invoke();
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) => base.CustomizeAppBuilder(builder);

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Actual = this;
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
