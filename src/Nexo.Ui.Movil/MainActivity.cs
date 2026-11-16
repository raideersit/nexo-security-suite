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

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) => base.CustomizeAppBuilder(builder);

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Actual = this;
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
