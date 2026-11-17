using System;
using Android.App.Job;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Interruptores de los avisos y la programacion del trabajo periodico (JobScheduler, lo que usa WorkManager por debajo).
/// Hay tres: «avisar al instalar» (§3.3), «avisar si el equipo empeora» y «resumen semanal» (notificaciones generales).
/// Un solo trabajo los atiende a todos: queda programado mientras AL MENOS UNO este encendido.
/// </summary>
public static class ConfiguracionDeVigilancia
{
    public const int IdDelTrabajo = 4242;
    private const string Archivo = "nexo";
    private const string ClaveApps = "avisar_al_instalar", ClaveEquipo = "avisar_equipo", ClaveResumen = "resumen_semanal";

    private static ISharedPreferences Prefs(Context c) => c.GetSharedPreferences(Archivo, FileCreationMode.Private)!;

    public static bool Activada(Context c) => Prefs(c).GetBoolean(ClaveApps, false);
    public static bool EquipoActivado(Context c) => Prefs(c).GetBoolean(ClaveEquipo, false);
    public static bool ResumenActivado(Context c) => Prefs(c).GetBoolean(ClaveResumen, false);
    public static bool AlgunaActiva(Context c) => Activada(c) || EquipoActivado(c) || ResumenActivado(c);
    public static long ActivadaDesdeMs(Context c) => Prefs(c).GetLong("activada_desde_ms", 0);

    public static void Activar(Context c)
    {
        Prefs(c).Edit()!.PutBoolean(ClaveApps, true)!.PutLong("activada_desde_ms", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())!.Apply();
        Programar(c);
    }

    public static void Desactivar(Context c) => Apagar(c, ClaveApps);

    public static void ActivarEquipo(Context c) { Prefs(c).Edit()!.PutBoolean(ClaveEquipo, true)!.Apply(); Programar(c); }
    public static void DesactivarEquipo(Context c) => Apagar(c, ClaveEquipo);

    public static void ActivarResumen(Context c) { Prefs(c).Edit()!.PutBoolean(ClaveResumen, true)!.Apply(); Programar(c); }
    public static void DesactivarResumen(Context c) => Apagar(c, ClaveResumen);

    /// <summary>Apaga un interruptor. El trabajo solo se cancela si ya no queda ninguno encendido.</summary>
    private static void Apagar(Context c, string clave)
    {
        // Commit (no Apply): AlgunaActiva tiene que leer el valor nuevo justo despues.
        Prefs(c).Edit()!.PutBoolean(clave, false)!.Commit();
        if (!AlgunaActiva(c)) ((JobScheduler)c.GetSystemService(Context.JobSchedulerService)!).Cancel(IdDelTrabajo);
    }

    /// <summary>
    /// Si hay algun aviso encendido pero Android perdio el trabajo (reinicio, «Forzar detencion», algunas marcas), lo vuelve a programar.
    /// Sin esto los avisos quedarian «activados» en pantalla y no llegarian nunca. Devuelve true si tuvo que reprogramarlo.
    /// </summary>
    public static bool Reparar(Context c)
    {
        if (!AlgunaActiva(c) || TrabajoProgramado(c)) return false;
        Programar(c);
        Android.Util.Log.Warn("NEXO", "REVISION el trabajo periodico no estaba programado y se reprogramo");
        return true;
    }

    private static void Programar(Context c)
    {
        // Si ya esta programado no se toca: volver a programarlo reiniciaria la cuenta de 15 minutos.
        if (TrabajoProgramado(c)) return;
        var programador = (JobScheduler)c.GetSystemService(Context.JobSchedulerService)!;
        var constructor = new JobInfo.Builder(IdDelTrabajo, new ComponentName(c, Java.Lang.Class.FromType(typeof(TareaDeRevision))));
        constructor.SetPeriodic(15 * 60 * 1000L);   // el minimo que permite Android
        constructor.SetPersisted(true);             // sobrevive a un reinicio (pide RECEIVE_BOOT_COMPLETED)
        programador.Schedule(constructor.Build()!);
    }

    public static bool TrabajoProgramado(Context c) =>
        ((JobScheduler)c.GetSystemService(Context.JobSchedulerService)!).GetPendingJob(IdDelTrabajo) != null;
}
