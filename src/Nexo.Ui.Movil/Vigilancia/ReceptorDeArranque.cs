using Android.App;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>Al encender el telefono vuelve a programar el trabajo de avisos si el usuario los tiene activados (el sistema puede haberlo perdido).</summary>
[BroadcastReceiver(Name = "io.github.raideersit.nexo.ReceptorDeArranque", Enabled = true, Exported = true)]
[IntentFilter(new[] { Intent.ActionBootCompleted })]
public sealed class ReceptorDeArranque : BroadcastReceiver
{
    public override void OnReceive(Context? contexto, Intent? intent)
    {
        if (contexto is null || intent?.Action != Intent.ActionBootCompleted) return;
        bool reprogramado = ConfiguracionDeVigilancia.Reparar(contexto);
        Android.Util.Log.Info("NEXO", $"ARRANQUE recibido: avisos activados={ConfiguracionDeVigilancia.Activada(contexto)} reprogramado={reprogramado}");
    }
}
