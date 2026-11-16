using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Android.App;
using Android.Content;
using Android.Net.Wifi;
using Android.OS;
using Android.Provider;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Modules.Threats.Movil
{
    /// <summary>
    /// Lee los ajustes del telefono para el chequeo del equipo (Salida 7, 3.4). SOLO LECTURA y sin permisos peligrosos.
    /// Un dato que falla queda en null («sin evaluar»); nunca se rellena con un valor que parezca bueno.
    /// Del Wi-Fi solo se lee el TIPO de seguridad: no se pide el nombre de la red, asi que no hace falta el permiso de ubicacion.
    /// </summary>
    public sealed class LectorDelEquipoAndroid
    {
        private readonly Context _contexto;

        /// <summary>Texto para registrar lo que paso con el Wi-Fi (estado y codigos, NUNCA el nombre de la red).</summary>
        public string DiagnosticoDeWifi { get; private set; } = "";

        public LectorDelEquipoAndroid(Context contexto) => _contexto = contexto;

        public DatosDelEquipo Leer() => new()
        {
            BloqueoDePantalla = Intentar<bool?>(() => (_contexto.GetSystemService(Context.KeyguardService) as KeyguardManager)?.IsDeviceSecure),
            ParcheDeSeguridad = Intentar<DateTime?>(() => DateTime.TryParse(Build.VERSION.SecurityPatch, CultureInfo.InvariantCulture, DateTimeStyles.None, out var f) ? f : null),
            Api = (int)Build.VERSION.SdkInt,
            Release = Build.VERSION.Release ?? "",
            OpcionesDeDesarrollo = Intentar<bool?>(() => Settings.Global.GetInt(_contexto.ContentResolver, "development_settings_enabled", 0) != 0),
            DepuracionUsb = Intentar<bool?>(() => Settings.Global.GetInt(_contexto.ContentResolver, "adb_enabled", 0) != 0),
            PistasDeRoot = PistasDeRoot(),
            Wifi = LeerWifi(),
        };

        private static T? Intentar<T>(Func<T?> f)
        {
            try { return f(); } catch (Exception) { return default; }
        }

        private static IReadOnlyList<string> PistasDeRoot()
        {
            var l = new List<string>();
            try
            {
                if (Build.Tags?.Contains("test-keys") == true) l.Add("compilación test-keys");
                foreach (var ruta in new[] { "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk" })
                    if (File.Exists(ruta)) l.Add(ruta);
            }
            catch (Exception) { /* sin dato */ }
            return l;
        }

        private SeguridadDeWifi LeerWifi()
        {
            try
            {
                var wm = _contexto.GetSystemService(Context.WifiService) as WifiManager;
                if (wm is null) { DiagnosticoDeWifi = "sin WifiManager"; return SeguridadDeWifi.NoEvaluable; }
#pragma warning disable CS0618, CA1422
                var info = wm.ConnectionInfo;
#pragma warning restore CS0618, CA1422
                if (!wm.IsWifiEnabled) { DiagnosticoDeWifi = "wifi apagado"; return SeguridadDeWifi.NoConectado; }
                bool conectado = info != null && (info.NetworkId != -1 || info.SupplicantState == SupplicantState.Completed);
                DiagnosticoDeWifi = $"activo=si estado={info?.SupplicantState} idDeRed={info?.NetworkId}";
                if (!conectado) return SeguridadDeWifi.NoConectado;
                if (!OperatingSystem.IsAndroidVersionAtLeast(31)) { DiagnosticoDeWifi += " api<31"; return SeguridadDeWifi.NoEvaluable; }
                int tipo = info!.CurrentSecurityType;
                DiagnosticoDeWifi += $" tipoDeSeguridad={tipo}";
                return Traducir(tipo);
            }
            catch (Exception ex)
            {
                DiagnosticoDeWifi = "fallo " + ex.GetType().Name;
                return SeguridadDeWifi.NoEvaluable;
            }
        }

        /// <summary>
        /// Traduce WifiSecurityType (WifiInfo.SECURITY_TYPE_*). Solo Open, Wep y Unknown existen en todas las versiones desde Android 12; todos los demas
        /// tipos que define Android (PSK, EAP, SAE, OWE, WAPI, DPP, Passpoint, WPA3 empresarial) son cifrados. Un codigo que no se conoce
        /// como cifrado ni como abierto NO se da por bueno: queda «desconocida».
        /// </summary>
        [System.Runtime.Versioning.SupportedOSPlatform("android31.0")]
        internal static SeguridadDeWifi Traducir(int tipo) => (WifiSecurityType)tipo switch
        {
            WifiSecurityType.Open => SeguridadDeWifi.Abierta,
            WifiSecurityType.Wep => SeguridadDeWifi.Wep,
            WifiSecurityType.Unknown => SeguridadDeWifi.Desconocida,
            _ when tipo > 0 && tipo <= 20 => SeguridadDeWifi.Cifrada,
            _ => SeguridadDeWifi.Desconocida,
        };
    }
}
