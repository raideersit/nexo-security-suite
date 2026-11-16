using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Android.App;
using Android.App.Admin;
using Android.Content;
using Android.Content.PM;
using Android.Provider;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Modules.Threats.Movil
{
    /// <summary>
    /// Lee el telefono y llena un <see cref="ModeloDeApp"/> por app (Salida 7, 3.1). SOLO LECTURA y sin permisos peligrosos:
    /// cada consulta de aqui se probo en un telefono real (Android 13) en la fase 0. Si una consulta falla, ese dato queda en su
    /// valor neutro y se anota en <see cref="Avisos"/>: nunca se inventa un dato ni se aborta el inventario por una app.
    /// </summary>
    public sealed class LectorDeAppsAndroid
    {
        private readonly Context _contexto;
        public List<string> Avisos { get; } = new();
        /// <summary>Milisegundos por etapa de la ultima lectura (para medir, no para mostrar).</summary>
        public Dictionary<string, long> Tiempos { get; } = new();

        public LectorDeAppsAndroid(Context contexto) => _contexto = contexto;

        public IReadOnlyList<ModeloDeApp> Leer()
        {
            var gestor = _contexto.PackageManager!;
            var reloj = System.Diagnostics.Stopwatch.StartNew();
            Tiempos.Clear();
#pragma warning disable CS0618, CA1422
            var paquetes = (OperatingSystem.IsAndroidVersionAtLeast(33)
                ? gestor.GetInstalledPackages(PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.Permissions))
                : gestor.GetInstalledPackages(PackageInfoFlags.Permissions)) ?? new List<PackageInfo>();
#pragma warning restore CS0618, CA1422

            Tiempos["paquetes"] = reloj.ElapsedMilliseconds; reloj.Restart();
            var accesibilidad = Intentar("servicios de Accesibilidad", PaquetesConAccesibilidad);
            var administradores = Intentar("administradores del dispositivo", PaquetesAdministradores);
            var oyentes = Intentar("oyentes de notificaciones", PaquetesConOyente);
            var conIcono = Intentar("apps con icono", () => PaquetesConIcono(gestor));
            var ops = _contexto.GetSystemService(Context.AppOpsService) as AppOpsManager;
            Tiempos["ajustes"] = reloj.ElapsedMilliseconds; reloj.Restart();
            long msInstalador = 0, msFirma = 0;

            var lista = new List<ModeloDeApp>(paquetes.Count);
            foreach (var p in paquetes)
            {
                var nombre = p.PackageName;
                var info = p.ApplicationInfo;
                if (nombre is null || info is null) continue;
                bool sistema = (info.Flags & ApplicationInfoFlags.System) != 0;
                var pedidos = new HashSet<string>(p.RequestedPermissions ?? new List<string>());
                var concedidos = new HashSet<string>();
                if (p.RequestedPermissions is { } rp && p.RequestedPermissionsFlags is { } fl)
                    for (int i = 0; i < rp.Count && i < fl.Count; i++)
                        if ((fl[i] & (int)RequestedPermission.Granted) != 0) concedidos.Add(rp[i]);

                var t0 = System.Diagnostics.Stopwatch.GetTimestamp();
                var instalador = Instalador(gestor, nombre);
                msInstalador += (long)System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                t0 = System.Diagnostics.Stopwatch.GetTimestamp();
                var firmaDep = !sistema && TieneFirmaDeDepuracion(gestor, nombre);
                msFirma += (long)System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds;
                lista.Add(new ModeloDeApp
                {
                    Paquete = nombre,
                    Nombre = sistema ? nombre : Etiqueta(gestor, info, nombre),
                    EsDeSistema = sistema,
                    InstaladoPor = instalador,
                    PermisosPedidos = pedidos,
                    PermisosConcedidos = concedidos,
                    AccesibilidadActiva = accesibilidad.Contains(nombre),
                    AdministradorActivo = administradores.Contains(nombre),
                    OyenteDeNotificacionesActivo = oyentes.Contains(nombre),
                    SuperposicionConcedida = pedidos.Contains("android.permission.SYSTEM_ALERT_WINDOW") && PermiteOp(ops, "android:system_alert_window", info.Uid, nombre),
                    InstalaAppsConcedido = pedidos.Contains("android.permission.REQUEST_INSTALL_PACKAGES") && PermiteOp(ops, "android:request_install_packages", info.Uid, nombre),
                    SinIconoEnLanzador = !sistema && !conIcono.Contains(nombre),
                    FirmaDeDepuracion = firmaDep,
                    VersionCode = p.LongVersionCode,
                    UltimaActualizacionMs = p.LastUpdateTime,
                });
            }
            Tiempos["por_app"] = reloj.ElapsedMilliseconds; Tiempos["instalador"] = msInstalador; Tiempos["firma"] = msFirma;
            return lista;
        }

        private HashSet<string> Intentar(string que, Func<HashSet<string>> f)
        {
            try { return f(); }
            catch (Exception ex) { Avisos.Add($"No se pudo leer {que}: {ex.GetType().Name}"); return new HashSet<string>(); }
        }

        private HashSet<string> PaquetesConAccesibilidad()
        {
            var am = (Android.Views.Accessibility.AccessibilityManager)_contexto.GetSystemService(Context.AccessibilityService)!;
            var lista = am.GetEnabledAccessibilityServiceList(Android.AccessibilityServices.FeedbackFlags.AllMask);
            return new HashSet<string>((lista ?? new List<Android.AccessibilityServices.AccessibilityServiceInfo>())
                .Select(s => s.ResolveInfo?.ServiceInfo?.PackageName).Where(n => n != null)!);
        }

        private HashSet<string> PaquetesAdministradores()
        {
            var dpm = (DevicePolicyManager)_contexto.GetSystemService(Context.DevicePolicyService)!;
            return new HashSet<string>((dpm.ActiveAdmins ?? new List<ComponentName>()).Select(c => c.PackageName).Where(n => n != null)!);
        }

        private HashSet<string> PaquetesConOyente()
        {
            var crudo = Settings.Secure.GetString(_contexto.ContentResolver, "enabled_notification_listeners");
            var r = new HashSet<string>();
            if (string.IsNullOrEmpty(crudo)) return r;
            foreach (var parte in crudo.Split(':'))
                if (ComponentName.UnflattenFromString(parte)?.PackageName is { } n) r.Add(n);
            return r;
        }

        private static HashSet<string> PaquetesConIcono(PackageManager gestor)
        {
            var intent = new Intent(Intent.ActionMain).AddCategory(Intent.CategoryLauncher);
#pragma warning disable CS0618, CA1422
            var lista = OperatingSystem.IsAndroidVersionAtLeast(33)
                ? gestor.QueryIntentActivities(intent, PackageManager.ResolveInfoFlags.Of(0))
                : gestor.QueryIntentActivities(intent, 0);
#pragma warning restore CS0618, CA1422
            return new HashSet<string>(lista.Select(r => r.ActivityInfo?.PackageName).Where(n => n != null)!);
        }

        private static bool PermiteOp(AppOpsManager? ops, string op, int uid, string paquete)
        {
            if (ops is null) return false;
            try
            {
#pragma warning disable CA1416, CS0618, CA1422
                return ops.CheckOpNoThrow(op, uid, paquete) == AppOpsManagerMode.Allowed;
#pragma warning restore CA1416, CS0618, CA1422
            }
            catch (Exception) { return false; }
        }

        private static string? Instalador(PackageManager gestor, string paquete)
        {
            try { return gestor.GetInstallSourceInfo(paquete).InstallingPackageName; }
            catch (Exception) { return null; }
        }

        private static string Etiqueta(PackageManager gestor, ApplicationInfo info, string respaldo)
        {
            try { return gestor.GetApplicationLabel(info) ?? respaldo; }
            catch (Exception) { return respaldo; }
        }

        /// <summary>El certificado de depuracion de Android tiene «CN=Android Debug» (lo genera el SDK). Una app publicada no lo usa.</summary>
        private static bool TieneFirmaDeDepuracion(PackageManager gestor, string paquete)
        {
            try
            {
#pragma warning disable CS0618, CA1422
                var pi = OperatingSystem.IsAndroidVersionAtLeast(33)
                    ? gestor.GetPackageInfo(paquete, PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.SigningCertificates))
                    : gestor.GetPackageInfo(paquete, PackageInfoFlags.SigningCertificates);
#pragma warning restore CS0618, CA1422
                var firmas = pi?.SigningInfo?.GetApkContentsSigners();
                if (firmas is null) return false;
                foreach (var f in firmas)
                {
                    var bytes = f.ToByteArray();
                    if (bytes is null) continue;
#pragma warning disable SYSLIB0057
                    using var cert = new X509Certificate2(bytes);
#pragma warning restore SYSLIB0057
                    if (cert.Subject.Contains("CN=Android Debug", StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            }
            catch (Exception) { return false; }
        }
    }
}
