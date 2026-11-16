using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Android.App;
using Android.Content;
using Android.OS;
using Android.Provider;

namespace Nexo.Ui.Movil.Estado;

public enum Nivel { Bien, Aviso, Info }

public sealed record Comprobacion(string Nombre, Nivel Nivel, string Detalle);

/// <summary>Chequeo del equipo (Salida 7, 3.4): solo lectura, sin permisos peligrosos.</summary>
public static class ChequeoEquipo
{
    /// <summary>Tabla PROVISIONAL de versiones con soporte: la definitiva vive en el catalogo (fase 1).</summary>
    private const int ApiMinimaConSoporte = 34;
    private const int DiasMaximosDeParche = 90;

    public static IReadOnlyList<Comprobacion> Ejecutar(Context contexto, DateTime hoy)
    {
        var r = new List<Comprobacion>();
        Intentar(r, "Bloqueo de pantalla", () =>
        {
            var seguro = (contexto.GetSystemService(Context.KeyguardService) as KeyguardManager)?.IsDeviceSecure ?? false;
            return seguro ? new("Bloqueo de pantalla", Nivel.Bien, "Hay PIN, patron o clave.")
                          : new("Bloqueo de pantalla", Nivel.Aviso, "Sin bloqueo: cualquiera con el telefono entra a todo.");
        });
        Intentar(r, "Parche de seguridad", () =>
        {
            var texto = Build.VERSION.SecurityPatch;
            if (!DateTime.TryParse(texto, CultureInfo.InvariantCulture, DateTimeStyles.None, out var fecha))
                return new("Parche de seguridad", Nivel.Info, "No se pudo leer la fecha.");
            var dias = (int)(hoy - fecha).TotalDays;
            return dias > DiasMaximosDeParche
                ? new("Parche de seguridad", Nivel.Aviso, $"{texto}: hace {dias} dias (mas de {DiasMaximosDeParche}).")
                : new("Parche de seguridad", Nivel.Bien, $"{texto}: hace {dias} dias.");
        });
        Intentar(r, "Version de Android", () =>
        {
            var api = (int)Build.VERSION.SdkInt;
            return api >= ApiMinimaConSoporte
                ? new("Version de Android", Nivel.Bien, $"Android {Build.VERSION.Release} (API {api}).")
                : new("Version de Android", Nivel.Aviso, $"Android {Build.VERSION.Release} (API {api}) puede haber dejado de recibir parches.");
        });
        Intentar(r, "Opciones de desarrollador", () =>
            Ajuste(contexto, "development_settings_enabled", "Opciones de desarrollador", "apagadas", "encendidas: normal si programas, riesgoso si no."));
        Intentar(r, "Depuracion USB", () =>
            Ajuste(contexto, "adb_enabled", "Depuracion USB", "apagada", "encendida: un cable con PC autorizado controla el telefono."));
        Intentar(r, "Indicios de root", () =>
        {
            var pistas = new List<string>();
            if (Build.Tags?.Contains("test-keys") == true) pistas.Add("compilacion test-keys");
            foreach (var ruta in new[] { "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk" })
                if (File.Exists(ruta)) pistas.Add(ruta);
            return pistas.Count == 0 ? new("Indicios de root", Nivel.Bien, "Ninguno (solo informativo).")
                                     : new("Indicios de root", Nivel.Info, string.Join(", ", pistas));
        });
        r.Add(new("Wi-Fi actual", Nivel.Info, "Sin evaluar todavia (fase 1)."));
        r.Add(new("Instalar apps desconocidas", Nivel.Info, "Sin evaluar todavia (fase 1)."));
        r.Add(new("Play Protect", Nivel.Info, "Android no permite leerlo; se revisa a mano en Play Store."));
        return r;
    }

    private static Comprobacion Ajuste(Context contexto, string clave, string nombre, string bien, string aviso)
    {
        var valor = Settings.Global.GetInt(contexto.ContentResolver, clave, 0);
        return valor == 0 ? new(nombre, Nivel.Bien, char.ToUpper(nombre[0]) + nombre[1..] + " " + bien + ".")
                          : new(nombre, Nivel.Aviso, aviso);
    }

    private static void Intentar(List<Comprobacion> lista, string nombre, Func<Comprobacion> f)
    {
        try { lista.Add(f()); }
        catch (Exception ex) { lista.Add(new(nombre, Nivel.Info, "No se pudo leer: " + ex.Message)); }
    }
}
