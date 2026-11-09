using System;
using System.IO;
using Nexo.Modules.Threats.Enlaces;
using SkiaSharp;

namespace Nexo.Ui.Desktop
{
    /// <summary>
    /// Abre una imagen (PNG, JPG, BMP, GIF, WEBP) y lee sus codigos QR. SkiaSharp viene con Avalonia (no es una dependencia nueva).
    /// Defensas ante una imagen hecha para dañar: tope de tamaño del archivo, y el tamaño en pixeles se mira ANTES de decodificar
    /// (una imagen pequeña en disco puede pedir gigabytes al abrirla).
    /// </summary>
    public static class ImagenDeQr
    {
        public const long MaximoDeBytes = 25L * 1024 * 1024;

        public static LecturaDeQr Leer(Stream imagen)
        {
            if (imagen is null) throw new ArgumentNullException(nameof(imagen));
            byte[] datos;
            try
            {
                using var ms = new MemoryStream();
                byte[] buf = new byte[81920];
                int n;
                while ((n = imagen.Read(buf, 0, buf.Length)) > 0)
                {
                    if (ms.Length + n > MaximoDeBytes) return LecturaDeQr.Mal("el archivo es demasiado grande (más de 25 MB)");
                    ms.Write(buf, 0, n);
                }
                datos = ms.ToArray();
            }
            catch (IOException e) { return LecturaDeQr.Mal("no se pudo leer el archivo (" + e.GetType().Name + ")"); }

            using var data = SKData.CreateCopy(datos);
            using SKCodec? codec = SKCodec.Create(data);
            if (codec is null) return LecturaDeQr.Mal("no es una imagen que Nexo sepa abrir (PNG, JPG, BMP, GIF o WEBP)");
            SKImageInfo info = codec.Info;
            if (info.Width <= 0 || info.Height <= 0) return LecturaDeQr.Mal("la imagen está vacía");
            if ((long)info.Width * info.Height > LectorDeQr.MaximoDePixeles) return LecturaDeQr.Mal("la imagen es demasiado grande (" + info.Width + " × " + info.Height + " píxeles)");

            var destino = new SKImageInfo(info.Width, info.Height, SKColorType.Bgra8888, SKAlphaType.Unpremul);
            using var bmp = new SKBitmap(destino);
            SKCodecResult r = codec.GetPixels(destino, bmp.GetPixels());
            if (r is not (SKCodecResult.Success or SKCodecResult.IncompleteInput))
                return LecturaDeQr.Mal("no se pudo decodificar la imagen (" + r + ")");

            byte[] bgra = bmp.Bytes;
            LecturaDeQr lectura = LectorDeQr.Leer(bgra, info.Width, info.Height);
            // Una imagen cortada que aun asi dio un QR vale; si no dio nada, se dice que estaba cortada.
            if (r == SKCodecResult.IncompleteInput && lectura.Contenidos.Count == 0)
                return LecturaDeQr.Mal("la imagen está incompleta o dañada y no se encontró ningún código QR");
            return lectura;
        }
    }
}
