using Android.App;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>Al encender el telefono vuelve a programar el trabajo de avisos si el usuario los tiene activados (el sistema puede haberlo perdido).</summary>
[BroadcastReceiver(Name = "io.github.raideersit.nexo.ReceptorDeArranque", Enabled = true, Exported = true)]
[IntentFilter(new[] { Intent.ActionBootCompleted })]
public sealed class ReceptorDeArranque : BroadcastReceiver
{
    /// <summary>
    /// Si el firewall estaba encendido, se vuelve a poner. Solo si el consentimiento de VPN sigue vigente: sin pantalla no se puede pedir,
    /// y en ese caso las reglas quedan apagadas (y se ve en la pantalla del firewall) en vez de prometer un bloqueo que no existe.
    /// </summary>
    private static void ReponerFirewall(Context c)
    {
        var ruta = RutasDeNexo.Firewall(c);
        var reglas = Nexo.Modules.Threats.Apps.ReglasDelFirewall.Cargar(ruta, out _);
        if (!reglas.Encendido) return;
        if (Android.Net.VpnService.Prepare(c) is null)
        {
            Android.Util.Log.Info("NEXO", "ARRANQUE firewall: se repone");
            Firewall.ServicioFirewall.Aplicar(c);
        }
        else
        {
            reglas.Encendido = false;
            reglas.Revocado = true;
            reglas.Guardar(ruta);
            Android.Util.Log.Warn("NEXO", "ARRANQUE firewall: sin consentimiento de VPN, queda apagado");
        }
    }

    public override void OnReceive(Context? contexto, Intent? intent)
    {
        if (contexto is null || intent?.Action != Intent.ActionBootCompleted) return;
        bool reprogramado = ConfiguracionDeVigilancia.Reparar(contexto);
        ReponerFirewall(contexto);
        Android.Util.Log.Info("NEXO", $"ARRANQUE recibido: apps={ConfiguracionDeVigilancia.Activada(contexto)} equipo={ConfiguracionDeVigilancia.EquipoActivado(contexto)} resumen={ConfiguracionDeVigilancia.ResumenActivado(contexto)} reprogramado={reprogramado}");
    }
}
