using System;
using System.Collections.Generic;
using System.Linq;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Net;
using Android.OS;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil.Firewall;

/// <summary>
/// Firewall por app (Salida 7, 3.6) con VpnService, sin root. La VPN incluye SOLO las apps bloqueadas (AddAllowedApplication) y Nexo
/// NUNCA lee el tunel: lo que esas apps envian entra y no sale. Las demas apps ni pasan por la VPN.
/// Que paquetes entran y si se crea o no lo decide PlanDeFirewallMovil (portable, probado): nunca una VPN vacia, que bloquearia a todas.
/// </summary>
[Service(Name = "io.github.raideersit.nexo.ServicioFirewall", Permission = "android.permission.BIND_VPN_SERVICE", Exported = false)]
[IntentFilter(new[] { "android.net.VpnService" })]
public sealed class ServicioFirewall : VpnService
{
    public const string AccionAplicar = "io.github.raideersit.nexo.FIREWALL_APLICAR";
    public const string AccionDetener = "io.github.raideersit.nexo.FIREWALL_DETENER";

    private static readonly object Candado = new();
    private ParcelFileDescriptor? _tunel;

    /// <summary>Paquetes que estan bloqueados AHORA (vacio si no hay tunel). Lo lee la pantalla.</summary>
    public static IReadOnlyList<string> Bloqueando { get; private set; } = Array.Empty<string>();

    /// <summary>Se dispara cuando cambia el estado (tunel creado, cerrado o revocado).</summary>
    public static event Action? Cambio;

    /// <summary>Pide al servicio que aplique las reglas guardadas (encender, apagar o cambiar la lista).</summary>
    public static void Aplicar(Context c)
    {
        var i = new Intent(c, typeof(ServicioFirewall));
        i.SetAction(AccionAplicar);
        c.StartService(i);
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (intent?.Action == AccionDetener) { Cerrar("detener"); StopSelf(); return StartCommandResult.NotSticky; }
        AplicarReglas();
        return StartCommandResult.NotSticky;
    }

    private void AplicarReglas()
    {
        lock (Candado)
        {
            var reglas = ReglasDelFirewall.Cargar(RutasDeNexo.Firewall(this), out var aviso);
            if (aviso != null) Android.Util.Log.Warn("NEXO", "FIREWALL " + aviso);
            var plan = PlanDeFirewallMovil.Calcular(reglas, Instaladas(), PackageName!);
            if (!plan.Establecer)
            {
                Cerrar(reglas.Encendido ? "sin_apps_validas" : "apagado");
                StopSelf();
                return;
            }
            // Si Android no tiene el consentimiento de VPN (o otra app lo tomo), Establish devolveria null.
            if (Prepare(this) is not null)
            {
                Android.Util.Log.Warn("NEXO", "FIREWALL sin_consentimiento: hay que encenderlo desde la pantalla");
                Cerrar("sin_consentimiento");
                StopSelf();
                return;
            }
            var b = new Builder(this);
            b.SetSession("Nexo Firewall");
            b.AddAddress("10.111.0.1", 32);
            b.AddAddress("fd00:6e65:786f::1", 128);
            b.AddRoute("0.0.0.0", 0);
            b.AddRoute("::", 0);   // IPv6 tambien: si no, una app bloqueada podria salir por IPv6
            foreach (var p in plan.Paquetes)
            {
                try { b.AddAllowedApplication(p); }
                catch (PackageManager.NameNotFoundException) { Android.Util.Log.Warn("NEXO", "FIREWALL paquete_desaparecido=" + p); }
            }
            b.SetBlocking(false);
            var nuevo = b.Establish();
            if (nuevo is null)
            {
                Android.Util.Log.Warn("NEXO", "FIREWALL establish_null");
                Cerrar("establish_null");
                StopSelf();
                return;
            }
            // El tunel nuevo ya esta activo: recien ahora se cierra el anterior (asi no hay un instante sin bloqueo).
            var anterior = _tunel;
            _tunel = nuevo;
            try { anterior?.Close(); } catch (Java.IO.IOException) { }
            Bloqueando = plan.Paquetes;
            if (reglas.Revocado) { reglas.Revocado = false; reglas.Guardar(RutasDeNexo.Firewall(this)); }
            Android.Util.Log.Info("NEXO", $"FIREWALL establecida paquetes={plan.Paquetes.Count} ignoradas={plan.Ignoradas.Count} " + string.Join(",", plan.Paquetes));
        }
        Cambio?.Invoke();
    }

    private HashSet<string> Instaladas()
    {
        var pm = PackageManager!;
        var lista = OperatingSystem.IsAndroidVersionAtLeast(33) ? pm.GetInstalledPackages(PackageManager.PackageInfoFlags.Of(0L)) : pm.GetInstalledPackages(0);
        return new HashSet<string>(lista.Select(p => p.PackageName!).Where(n => n is not null), StringComparer.Ordinal);
    }

    private void Cerrar(string motivo)
    {
        bool habia;
        lock (Candado)
        {
            habia = _tunel is not null;
            try { _tunel?.Close(); } catch (Java.IO.IOException) { }
            _tunel = null;
            Bloqueando = Array.Empty<string>();
        }
        Android.Util.Log.Info("NEXO", $"FIREWALL cerrada motivo={motivo} habia_tunel={habia}");
        Cambio?.Invoke();
    }

    /// <summary>
    /// Android quito la VPN: el usuario la apago en sus Ajustes, u otra app de VPN tomo el control. Las reglas quedan APAGADAS
    /// (si no, Nexo intentaria volver a ponerse al reiniciar) y marcadas como revocadas para explicarlo en la pantalla.
    /// </summary>
    public override void OnRevoke()
    {
        var reglas = ReglasDelFirewall.Cargar(RutasDeNexo.Firewall(this), out _);
        reglas.Encendido = false;
        reglas.Revocado = true;
        reglas.Guardar(RutasDeNexo.Firewall(this));
        Cerrar("revocado");
        StopSelf();
        base.OnRevoke();
    }

    public override void OnDestroy()
    {
        lock (Candado) { try { _tunel?.Close(); } catch (Java.IO.IOException) { } _tunel = null; Bloqueando = Array.Empty<string>(); }
        Cambio?.Invoke();
        base.OnDestroy();
    }
}
