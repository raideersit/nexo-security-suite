using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Classic.CommonControls;

namespace Nexo.Ui.Desktop
{
    /// <summary>
    /// Los iconos estan dibujados en vectores en App.axaml (24x24), pero ToolBarButton solo acepta Bitmap. Se pasan a
    /// mapa de bits una vez al abrir la ventana: no hay archivos de imagen que distribuir.
    /// </summary>
    internal static class Iconos
    {
        private const double Lado = 24;

        public static void Poner(ToolBarButton boton, string clave)
        {
            if (Application.Current?.TryFindResource(clave, out object? r) != true || r is not DrawingImage dibujo) return;
            boton.LargeIcon = Rasterizar(dibujo, 24);
            boton.SmallIcon = Rasterizar(dibujo, 16);
        }

        private static Bitmap Rasterizar(DrawingImage dibujo, int lado)
        {
            var bmp = new RenderTargetBitmap(new PixelSize(lado, lado));
            using (DrawingContext ctx = bmp.CreateDrawingContext())
            using (ctx.PushTransform(Matrix.CreateScale(lado / Lado, lado / Lado)))
            {
                dibujo.Drawing?.Draw(ctx);
            }
            return bmp;
        }
    }
}
