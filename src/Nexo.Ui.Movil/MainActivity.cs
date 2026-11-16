using Android.App;
using Android.Content.PM;
using Avalonia;
using Avalonia.Android;

namespace Nexo.Ui.Movil;

[Activity(
    Label = "Nexo",
    Theme = "@style/NexoTema",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public sealed class MainActivity : AvaloniaMainActivity<App>
{
    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) => base.CustomizeAppBuilder(builder);
}
