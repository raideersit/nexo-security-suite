using System;
using System.IO;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Ui.Desktop;
using SkiaSharp;
using ZXing;
using ZXing.QrCode;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        /// <summary>Un QR guardado como archivo de imagen de verdad (PNG o JPG), como una captura o una foto.</summary>
        private static byte[] ImagenConQr(string contenido, SKEncodedImageFormat formato, int lado = 300)
        {
            var w = new BarcodeWriterPixelData { Format = BarcodeFormat.QR_CODE, Options = new QrCodeEncodingOptions { Width = lado, Height = lado, Margin = 2, CharacterSet = "UTF-8" } };
            var p = w.Write(contenido);
            var info = new SKImageInfo(p.Width, p.Height, SKColorType.Bgra8888, SKAlphaType.Unpremul);
            using var bmp = new SKBitmap(info);
            System.Runtime.InteropServices.Marshal.Copy(p.Pixels, 0, bmp.GetPixels(), p.Pixels.Length);
            using SKData d = bmp.Encode(formato, 90);
            return d.ToArray();
        }

        /// <summary>Un PNG minimo que DECLARA un tamaño en su cabecera (IHDR) sin traer los pixeles: la trampa de «pequeño en disco, enorme al abrir».</summary>
        private static byte[] PngQueDeclara(int ancho, int alto)
        {
            var ms = new MemoryStream();
            ms.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
            void Trozo(string tipo, byte[] datos)
            {
                byte[] largo = BitConverter.GetBytes(datos.Length); Array.Reverse(largo);
                ms.Write(largo);
                byte[] td = Encoding.ASCII.GetBytes(tipo).Concat(datos).ToArray();
                ms.Write(td);
                byte[] crc = BitConverter.GetBytes(Crc32(td)); Array.Reverse(crc);
                ms.Write(crc);
            }
            byte[] Be(int v) { byte[] b = BitConverter.GetBytes(v); Array.Reverse(b); return b; }
            Trozo("IHDR", Be(ancho).Concat(Be(alto)).Concat(new byte[] { 8, 6, 0, 0, 0 }).ToArray());
            // Un bloque de datos minimo (zlib vacio): sin IDAT, Skia ni siquiera lo reconoce como PNG y la prueba no probaria el tope.
            Trozo("IDAT", new byte[] { 0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01 });
            Trozo("IEND", Array.Empty<byte>());
            return ms.ToArray();
        }

        private static uint Crc32(byte[] d)
        {
            uint c = 0xFFFFFFFF;
            foreach (byte b in d)
            {
                c ^= b;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            }
            return ~c;
        }

        public static void ProbarQrEnLaVentana()
        {
            Console.WriteLine("Pestaña Enlaces: códigos QR en imágenes");
            const string estafa = "https://www.roblox.com.ml/users/364354365772/profile";
            LecturaDeQr png = ImagenDeQr.Leer(new MemoryStream(ImagenConQr(estafa, SKEncodedImageFormat.Png)));
            Check(png.Contenidos.SingleOrDefault() == estafa, "un PNG con un QR se abre y se lee", png.Motivo);
            LecturaDeQr jpg = ImagenDeQr.Leer(new MemoryStream(ImagenConQr(estafa, SKEncodedImageFormat.Jpeg)));
            Check(jpg.Contenidos.SingleOrDefault() == estafa, "un JPG (con compresión con pérdida) también", jpg.Motivo);
            System.Reflection.Assembly yo = typeof(Program).Assembly;
            LecturaDeQr externo = ImagenDeQr.Leer(yo.GetManifestResourceStream("qr-bancoestado.png")!);
            Check(externo.Contenidos.SingleOrDefault() == "https://www.bancoestado.cl/", "un QR REAL de otro generador (PNG de 1 bit con paleta) se lee", externo.Motivo ?? string.Join("|", externo.Contenidos));
            LecturaDeQr externoJpg = ImagenDeQr.Leer(yo.GetManifestResourceStream("qr-wifi.jpg")!);
            Check(externoJpg.Contenidos.SingleOrDefault() == "WIFI:S:Cafe Libre;T:nopass;;", "y uno de Wi-Fi en JPG del mismo generador", externoJpg.Motivo ?? string.Join("|", externoJpg.Contenidos));
            LecturaDeQr basura = ImagenDeQr.Leer(new MemoryStream(Encoding.UTF8.GetBytes("esto no es una imagen")));
            Check(basura.Contenidos.Count == 0 && basura.Motivo!.Contains("no es una imagen"), "un archivo que no es imagen: lo dice", basura.Motivo);
            byte[] trampa = PngQueDeclara(20_000, 20_000);
            LecturaDeQr enorme = ImagenDeQr.Leer(new MemoryStream(trampa));
            Check(trampa.Length < 100 && enorme.Motivo!.Contains("demasiado grande") && enorme.Motivo.Contains("20000"),
                "un PNG de " + trampa.Length + " bytes que declara 20 000 × 20 000: se rechaza ANTES de decodificar", enorme.Motivo);
            byte[] cortado = ImagenConQr(estafa, SKEncodedImageFormat.Png);
            LecturaDeQr mitad = ImagenDeQr.Leer(new MemoryStream(cortado.Take(cortado.Length / 3).ToArray()));
            Check(mitad.Contenidos.Count == 0 && mitad.Motivo is not null, "un PNG cortado a un tercio: no inventa nada y dice por qué", mitad.Motivo);
            var grande = new LimiteStream(ImagenDeQr.MaximoDeBytes + 10);
            Check(ImagenDeQr.Leer(grande).Motivo!.Contains("25 MB") && grande.Leidos <= ImagenDeQr.MaximoDeBytes + 81920, "un archivo de más de 25 MB se corta al pasar el tope (no se lee entero)");

            // El modelo: el contenido del QR pasa a ser el texto y se revisa.
            string carpeta = Path.Combine(Path.GetTempPath(), "nexo-ventana-qr-" + Guid.NewGuid().ToString("N"));
            try
            {
                var d = new DescargaDeListasFalsa();
                EnlacesModelo m = ModeloDeEnlaces(carpeta, d);
                m.Texto = "texto anterior";
                Esperar(m.RevisarQrAsync(new MemoryStream(Encoding.UTF8.GetBytes("no soy imagen")), "nota.txt"));
                Check(m.Texto == "texto anterior" && m.OrigenDelTexto!.Contains("«nota.txt»") && m.OrigenDelTexto.Contains("no es una imagen"),
                    "sin QR: el texto que había NO se toca y se dice por qué", m.OrigenDelTexto);
                Esperar(m.RevisarQrAsync(new MemoryStream(ImagenConQr(estafa, SKEncodedImageFormat.Png)), "estacionamiento.png"));
                Check(m.Texto == estafa && m.OrigenDelTexto!.Contains("código QR de «estacionamiento.png»") && m.OrigenDelTexto.Contains("Nexo no lo abrió") && m.Titulo.StartsWith("Peligroso"),
                    "con QR: el contenido pasa a la caja, se dice de dónde salió y se revisa (Peligroso: imita a Roblox)", m.OrigenDelTexto + " / " + m.Titulo);
                Check(d.Llamadas == 0, "leer un QR no descarga nada ni abre el enlace");
                m.Texto = estafa + " ";
                Check(!m.HayOrigen && m.Titulo == "Sin revisar", "si el usuario edita el texto, ya no se presenta como «lo que decía el QR»");
                Esperar(m.RevisarQrAsync(new MemoryStream(ImagenConQr("WIFI:S:Cafe Libre;T:nopass;;", SKEncodedImageFormat.Png)), "mesa.jpg"));
                Check(m.HallazgosDelMensaje.Any(h => h.Titulo.Contains("red Wi-Fi abierta")) && m.Titulo.StartsWith("Sospechoso"), "un QR de Wi-Fi abierta: Sospechoso, con el aviso de la red", m.Titulo);
                m.Borrar();
                Check(!m.HayOrigen && m.Texto == "", "«Borrar» también quita el origen");
            }
            finally
            {
                try { Directory.Delete(carpeta, true); } catch (IOException) { }
            }
        }

        /// <summary>Un flujo que entrega ceros hasta un largo dado, y cuenta lo que se leyo.</summary>
        private sealed class LimiteStream : Stream
        {
            private readonly long _largo;
            public long Leidos;
            public LimiteStream(long largo) => _largo = largo;
            public override int Read(byte[] buffer, int offset, int count)
            {
                int n = (int)Math.Min(count, _largo - Leidos);
                if (n <= 0) return 0;
                Array.Clear(buffer, offset, n);
                Leidos += n;
                return n;
            }
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => _largo;
            public override long Position { get => Leidos; set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
