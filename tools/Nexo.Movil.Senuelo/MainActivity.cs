using Android.App;
using Android.OS;
using Android.Widget;

namespace Nexo.Movil.Senuelo;

[Activity(Label = "Señuelo de Nexo", MainLauncher = true)]
public sealed class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        SetContentView(new TextView(this)
        {
            Text = "Señuelo de pruebas de Nexo.\n\nPide Accesibilidad, SMS y superposición, y no hace nada con ellos. Desinstálalo al terminar la prueba.",
            TextSize = 18,
        });
    }
}
