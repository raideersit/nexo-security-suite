using System;
using Android.App.Job;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>Interruptor de «avisar al instalar» y su programacion. El trabajo periodico lo agenda JobScheduler, que es lo que usa WorkManager por debajo.</summary>
public static class ConfiguracionDeVigilancia
{
    public const int IdDelTrabajo = 4242;
    private const string Archivo = "nexo";

    private static ISharedPreferences Prefs(Context c) => c.GetSharedPreferences(Archivo, FileCreationMode.Private)!;

    public static bool Activada(Context c) => Prefs(c).GetBoolean("avisar_al_instalar", false);
    public static long ActivadaDesdeMs(Context c) => Prefs(c).GetLong("activada_desde_ms", 0);

    public static void Activar(Context c)
    {
        Prefs(c).Edit()!.PutBoolean("avisar_al_instalar", true)!.PutLong("activada_desde_ms", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())!.Apply();
        var programador = (JobScheduler)c.GetSystemService(Context.JobSchedulerService)!;
        var constructor = new JobInfo.Builder(IdDelTrabajo, new ComponentName(c, Java.Lang.Class.FromType(typeof(TareaDeRevision))));
        constructor.SetPeriodic(15 * 60 * 1000L);   // el minimo que permite Android
        constructor.SetPersisted(true);             // sobrevive a un reinicio (pide RECEIVE_BOOT_COMPLETED)
        programador.Schedule(constructor.Build()!);
    }

    public static void Desactivar(Context c)
    {
        Prefs(c).Edit()!.PutBoolean("avisar_al_instalar", false)!.Apply();
        ((JobScheduler)c.GetSystemService(Context.JobSchedulerService)!).Cancel(IdDelTrabajo);
    }

    public static bool TrabajoProgramado(Context c) =>
        ((JobScheduler)c.GetSystemService(Context.JobSchedulerService)!).GetPendingJob(IdDelTrabajo) != null;
}
