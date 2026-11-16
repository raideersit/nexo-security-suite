using System;
using System.Threading.Tasks;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Se registra EN EJECUCION (desde MainActivity), no en el manifiesto: desde Android 8 un receptor del manifiesto no despierta a una app
/// cerrada por «app instalada». Sirve para avisar al instante mientras Nexo esta abierto; el trabajo periodico cubre el resto.
/// </summary>
public sealed class ReceptorDeInstalacion : BroadcastReceiver
{
    public static IntentFilter Filtro()
    {
        var f = new IntentFilter();
        f.AddAction(Intent.ActionPackageAdded);
        f.AddAction(Intent.ActionPackageReplaced);
        f.AddDataScheme("package");
        return f;
    }

    public override void OnReceive(Context? contexto, Intent? intent)
    {
        if (contexto is null) return;
        var pendiente = GoAsync();
        _ = Task.Run(() =>
        {
            try { EjecutorDeRevision.Ejecutar(contexto.ApplicationContext!, "receptor"); }
            catch (Exception ex) { Android.Util.Log.Error("NEXO", "REVISION fallo en el receptor: " + ex); }
            finally { pendiente?.Finish(); }
        });
    }
}
