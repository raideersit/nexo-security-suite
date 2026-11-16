using Android.AccessibilityServices;
using Android.App;
using Android.Content;
using Android.Views.Accessibility;

namespace Nexo.Movil.Senuelo;

/// <summary>Servicio de Accesibilidad VACIO: se declara para que Nexo lo vea activo, y no procesa ningun evento.</summary>
[Service(Name = "io.github.raideersit.nexo.senuelo.SenueloAccesibilidad", Label = "Señuelo de Nexo", Exported = true, Permission = "android.permission.BIND_ACCESSIBILITY_SERVICE")]
[IntentFilter(new[] { "android.accessibilityservice.AccessibilityService" })]
[MetaData("android.accessibilityservice", Resource = "@xml/senuelo_accesibilidad")]
public sealed class SenueloAccesibilidad : AccessibilityService
{
    public override void OnAccessibilityEvent(AccessibilityEvent? e) { }
    public override void OnInterrupt() { }
}
