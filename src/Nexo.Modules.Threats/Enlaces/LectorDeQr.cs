using System;
using System.Collections.Generic;
using System.Linq;
using ZXing;
using ZXing.Common;

namespace Nexo.Modules.Threats.Enlaces
{
    /// <summary>Lo que se leyo de una imagen: los contenidos de sus codigos QR (puede haber varios), o el motivo por el que no.</summary>
    public sealed record LecturaDeQr(IReadOnlyList<string> Contenidos, string? Motivo)
    {
        public static LecturaDeQr Mal(string motivo) => new(Array.Empty<string>(), motivo);
    }

    /// <summary>
    /// Lee los codigos QR de una imagen ya decodificada (pixeles BGRA de 32 bits). Todo local, con ZXing.Net. Abrir el archivo de imagen
    /// NO se hace aqui (lo hace la ventana con SkiaSharp, mirando el tamaño antes de decodificar), asi este modulo sigue sin depender de
    /// ninguna libreria grafica. Nexo nunca abre lo que dice el QR: solo lo lee y lo pasa a las mismas reglas que un mensaje pegado.
    /// </summary>
    public static class LectorDeQr
    {
        /// <summary>Tope de pixeles (40 MP): una foto de celular normal cabe; una imagen trampa enorme no.</summary>
        public const long MaximoDePixeles = 40_000_000;
        public const int MaximoDeCodigos = 5;
        public const int MaximoDeCaracteresPorCodigo = 4_000;

        public static LecturaDeQr Leer(byte[] bgra, int ancho, int alto)
        {
            if (bgra is null) throw new ArgumentNullException(nameof(bgra));
            if (ancho <= 0 || alto <= 0) return LecturaDeQr.Mal("la imagen está vacía");
            if ((long)ancho * alto > MaximoDePixeles) return LecturaDeQr.Mal("la imagen es demasiado grande");
            if (bgra.LongLength < (long)ancho * alto * 4) return LecturaDeQr.Mal("los datos de la imagen están incompletos");

            var lector = new BarcodeReaderGeneric
            {
                AutoRotate = true,
                Options = new DecodingOptions
                {
                    PossibleFormats = new[] { BarcodeFormat.QR_CODE },
                    TryHarder = true,
                    TryInverted = true
                }
            };
            Result[]? r;
            try
            {
                var fuente = new RGBLuminanceSource(bgra, ancho, alto, RGBLuminanceSource.BitmapFormat.BGRA32);
                r = lector.DecodeMultiple(fuente);
                // «TryInverted» no se aplica al leer varios codigos (comprobado: un QR blanco sobre negro no salia). Segundo intento, invertida.
                if (r is null || r.Length == 0) r = lector.DecodeMultiple(fuente.invert());
            }
            catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException or InvalidOperationException or System.FormatException or ZXing.ReaderException)
            {
                return LecturaDeQr.Mal("no se pudo analizar la imagen (" + e.GetType().Name + ")");
            }

            List<string> contenidos = (r ?? Array.Empty<Result>())
                .Select(x => x.Text ?? "")
                .Where(t => t.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .Take(MaximoDeCodigos)
                .Select(t => t.Length > MaximoDeCaracteresPorCodigo ? t.Substring(0, MaximoDeCaracteresPorCodigo) : t)
                .ToList();
            return contenidos.Count == 0 ? LecturaDeQr.Mal("no se encontró ningún código QR en la imagen") : new LecturaDeQr(contenidos, null);
        }
    }
}
