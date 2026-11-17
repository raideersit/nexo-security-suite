using System;
using System.Threading.Tasks;
using Android.App;
using Android.App.Job;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>El trabajo periodico (cada 15 min como minimo). Android lo ejecuta aunque la app este cerrada, salvo que el fabricante lo impida.</summary>
[Service(Name = "io.github.raideersit.nexo.TareaDeRevision", Permission = "android.permission.BIND_JOB_SERVICE", Exported = false)]
public sealed class TareaDeRevision : JobService
{
    public override bool OnStartJob(JobParameters? parametros)
    {
        var contexto = ApplicationContext!;
        _ = Task.Run(() =>
        {
            // Cada parte por separado: si falla la revision de apps, el chequeo del equipo y el resumen siguen corriendo (y al reves).
            try { EjecutorDeRevision.Ejecutar(contexto, "trabajo"); }
            catch (Exception ex) { Android.Util.Log.Error("NEXO", "REVISION fallo en el trabajo: " + ex); }
            try { EjecutorDelEquipo.Ejecutar(contexto, "trabajo"); }
            catch (Exception ex) { Android.Util.Log.Error("NEXO", "EQUIPO-REVISION fallo en el trabajo: " + ex); }
            finally { JobFinished(parametros, false); }
        });
        return true;
    }

    /// <summary>Android corta el trabajo (poca bateria, etc.): se pide reprogramarlo.</summary>
    public override bool OnStopJob(JobParameters? parametros) => true;
}
