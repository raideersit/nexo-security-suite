using System;
using System.IO;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil.Revisar;

/// <summary>Lo que llego por «Compartir»: un texto (SMS, mensaje, enlace) o una imagen ya copiada a la cache de Nexo (una captura con un QR).</summary>
public sealed record Compartido(string? Texto, string? RutaDeImagen, string? NombreDeImagen)
{
    /// <summary>El ultimo compartido que la pantalla «Revisar» todavia no tomo. Se consume una vez.</summary>
    public static Compartido? Pendiente { get; set; }

    public static Compartido? Tomar()
    {
        var c = Pendiente;
        Pendiente = null;
        return c;
    }
}

/// <summary>
/// Destino de «Compartir» de Android (Salida 7, 3.5). Es una actividad INVISIBLE e intermedia: copia lo compartido y abre Nexo en SU propia
/// tarea. Si el intent llegara directo a MainActivity, Android la abriria dentro de la app que comparte, como una segunda copia de Nexo,
/// y Avalonia no esta pensado para dos ventanas a la vez.
/// La imagen se copia aqui, mientras dura el permiso de lectura que Android da con el intent; despues ya no se podria abrir.
/// Nada de esto sale del telefono.
/// </summary>
[Activity(Name = "io.github.raideersit.nexo.ActividadCompartir", Label = "Revisar con Nexo", Exported = true, NoHistory = true, ExcludeFromRecents = true,
    Theme = "@android:style/Theme.Translucent.NoTitleBar")]
[IntentFilter(new[] { Intent.ActionSend }, Categories = new[] { Intent.CategoryDefault }, DataMimeType = "text/plain")]
[IntentFilter(new[] { Intent.ActionSend }, Categories = new[] { Intent.CategoryDefault }, DataMimeType = "image/*")]
public sealed class ActividadCompartir : Activity
{
    /// <summary>Tope de la imagen copiada (25 MB): una captura o foto normal cabe; un archivo enorme no se copia.</summary>
    private const long MaximoDeBytes = 25L * 1024 * 1024;
    /// <summary>Tope del texto (como el pegado en el escritorio, el analizador recorta igual).</summary>
    private const int MaximoDeCaracteres = 20_000;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        try { Compartido.Pendiente = Leer(Intent); }
        catch (Exception ex) { Android.Util.Log.Warn("NEXO", "COMPARTIR no se pudo leer: " + ex.GetType().Name); Compartido.Pendiente = new Compartido(null, null, null); }

        var abrir = new Intent(this, typeof(MainActivity));
        abrir.PutExtra(MainActivity.ExtraDestino, Destino.Revisar);
        abrir.AddFlags(ActivityFlags.NewTask | ActivityFlags.SingleTop | ActivityFlags.ClearTop);
        StartActivity(abrir);
        Finish();
    }

    private Compartido Leer(Intent? intent)
    {
        if (intent?.Action != Intent.ActionSend) return new Compartido(null, null, null);
        var tipo = intent.Type ?? "";
        if (tipo.StartsWith("image/", StringComparison.Ordinal))
        {
            var uri = OperatingSystem.IsAndroidVersionAtLeast(33)
                ? intent.GetParcelableExtra(Intent.ExtraStream, Java.Lang.Class.FromType(typeof(Android.Net.Uri))) as Android.Net.Uri
                : (Android.Net.Uri?)intent.GetParcelableExtra(Intent.ExtraStream);
            var (ruta, motivo) = CopiarImagen(uri);
            Android.Util.Log.Info("NEXO", "COMPARTIR imagen tipo=" + tipo + (ruta is null ? " no_copiada=" + motivo : " copiada"));
            return new Compartido(null, ruta, ruta is null ? motivo : NombreDe(uri));
        }
        // Texto: el asunto (si lo hay, p. ej. de un correo) va delante, porque tambien puede traer el engaño.
        var asunto = intent.GetStringExtra(Intent.ExtraSubject);
        var texto = intent.GetStringExtra(Intent.ExtraText) ?? "";
        if (!string.IsNullOrWhiteSpace(asunto) && !texto.Contains(asunto, StringComparison.Ordinal)) texto = asunto + "\n" + texto;
        if (texto.Length > MaximoDeCaracteres) texto = texto[..MaximoDeCaracteres];
        Android.Util.Log.Info("NEXO", "COMPARTIR texto caracteres=" + texto.Length);   // nunca el contenido: es del usuario
        return new Compartido(texto, null, null);
    }

    /// <summary>Copia la imagen a la cache de Nexo (un solo archivo, se reemplaza cada vez). Devuelve la ruta o el motivo por el que no.</summary>
    private (string? Ruta, string Motivo) CopiarImagen(Android.Net.Uri? uri)
    {
        if (uri is null) return (null, "no llegó ninguna imagen");
        var destino = Path.Combine(CacheDir!.AbsolutePath, "compartida.img");
        using var entrada = ContentResolver?.OpenInputStream(uri);
        if (entrada is null) return (null, "no se pudo abrir la imagen");
        using (var salida = File.Create(destino))
        {
            var buf = new byte[81920];
            long total = 0;
            int n;
            while ((n = entrada.Read(buf, 0, buf.Length)) > 0)
            {
                total += n;
                if (total > MaximoDeBytes) { salida.Close(); File.Delete(destino); return (null, "la imagen pesa más de 25 MB"); }
                salida.Write(buf, 0, n);
            }
        }
        return (destino, "");
    }

    private string? NombreDe(Android.Net.Uri? uri)
    {
        try
        {
            using var c = uri is null ? null : ContentResolver?.Query(uri, new[] { Android.Provider.IOpenableColumns.DisplayName }, null, null, null);
            return c is not null && c.MoveToFirst() ? c.GetString(0) : null;
        }
        catch (Exception) { return null; }
    }
}
