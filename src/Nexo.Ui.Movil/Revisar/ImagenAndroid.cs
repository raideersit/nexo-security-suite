using System;
using Android.Graphics;
using Nexo.Modules.Threats.Enlaces;

namespace Nexo.Ui.Movil.Revisar;

/// <summary>
/// Decodifica una imagen con el decodificador de Android y le pasa los pixeles a <see cref="LectorDeQr"/> (portable, ZXing).
/// Mira el tamaño ANTES de decodificar y la reduce si hace falta, para que una imagen trampa enorme no agote la memoria.
/// Nunca lanza: un problema vuelve como <see cref="LecturaDeQr.Mal"/>.
/// </summary>
public static class ImagenAndroid
{
    public static LecturaDeQr LeerQr(string ruta)
    {
        try
        {
            var tam = new BitmapFactory.Options { InJustDecodeBounds = true };
            BitmapFactory.DecodeFile(ruta, tam);
            if (tam.OutWidth <= 0 || tam.OutHeight <= 0) return LecturaDeQr.Mal("no es una imagen que Android sepa abrir");

            // Reducir a la mitad (potencias de 2, lo que admite InSampleSize) hasta quedar bajo el tope de pixeles del lector.
            int muestra = 1;
            while ((long)(tam.OutWidth / muestra) * (tam.OutHeight / muestra) > LectorDeQr.MaximoDePixeles) muestra *= 2;

            using var bmp = BitmapFactory.DecodeFile(ruta, new BitmapFactory.Options { InSampleSize = muestra, InPreferredConfig = Bitmap.Config.Argb8888 });
            if (bmp is null) return LecturaDeQr.Mal("no se pudo decodificar la imagen");
            int ancho = bmp.Width, alto = bmp.Height;
            var argb = new int[ancho * alto];
            bmp.GetPixels(argb, 0, ancho, 0, 0, ancho, alto);
            // Un int ARGB (0xAARRGGBB) en memoria little-endian queda como B,G,R,A: justo el BGRA32 que espera el lector.
            var bgra = new byte[argb.Length * 4];
            if (!BitConverter.IsLittleEndian) return LecturaDeQr.Mal("formato de memoria no admitido");
            Buffer.BlockCopy(argb, 0, bgra, 0, bgra.Length);
            Android.Util.Log.Info("NEXO", $"QR imagen {tam.OutWidth}x{tam.OutHeight} muestra={muestra} -> {ancho}x{alto}");
            return LectorDeQr.Leer(bgra, ancho, alto);
        }
        // Java.Lang.Throwable cubre tambien OutOfMemoryError, que en Java es un Error y no una Exception.
        catch (Exception ex) when (ex is Java.Lang.Throwable or OutOfMemoryException or System.IO.IOException)
        {
            return LecturaDeQr.Mal("no se pudo leer la imagen (" + ex.GetType().Name + ")");
        }
    }
}
