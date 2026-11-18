using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Revisar;

namespace Nexo.Ui.Movil;

/// <summary>
/// Revisar un mensaje, un enlace o un QR (Salida 7, 3.5) con el estilo «Classic tactil v2». Llega desde el mosaico o desde «Compartir».
/// Todo es local: Nexo NUNCA abre el enlace ni lo envia a ningun servidor. Internet solo se usa para bajar las listas cuando el usuario lo pide.
/// Reglas de honestidad (las del escritorio): «sin señales» nunca es verde ni «seguro»; sin listas la revision es incompleta y se dice.
/// </summary>
public sealed class PantallaRevisar : UserControl
{
    private static readonly IBrush Ambar = new SolidColorBrush(Color.Parse("#8A5A00"));

    private readonly TextBlock _titular = Retro.Texto("Pega o comparte un mensaje", 24, true);
    private readonly TextBlock _explicacion = Retro.Texto("Un SMS, un mensaje de WhatsApp o un correo con un enlace. También puedes compartir con Nexo una captura que tenga un código QR.", Retro.Cuerpo);
    private readonly TextBlock _origen = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly TextBox _texto = new() { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 120, MaxHeight = 260, FontSize = Retro.Cuerpo, Watermark = "Pega aquí el mensaje o el enlace" };
    private readonly TextBox _remitente = new() { FontSize = Retro.Cuerpo, Watermark = "Remitente (opcional): número o nombre que aparece" };
    private readonly Button _revisar, _actualizar;
    private readonly StackPanel _resultado = new() { Spacing = 10 };
    private readonly TextBlock _estadoListas = Retro.Texto("Listas de phishing: leyendo...", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _mensajeListas = Retro.Texto("", Retro.Secundario, false, Retro.Gris);

    private readonly AlmacenDeListas _almacen = new(Path.Combine(Android.App.Application.Context.FilesDir!.AbsolutePath, "listas-phishing"));
    private ListasDePhishing _listas = ListasDePhishing.Vacias;
    private IReadOnlyList<string> _avisosListas = Array.Empty<string>();
    private readonly Task _cargaDeListas;
    private bool _ocupado;

    public PantallaRevisar(Compartido? compartido = null)
    {
        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_explicacion);
        cabecera.Children.Add(_origen);
        _origen.IsVisible = false;

        _revisar = Retro.BotonGrande("Revisar", () => _ = RevisarAsync(), destacado: true);
        var pegar = Retro.BotonGrande("Pegar", () => _ = PegarAsync());
        var qr = Retro.BotonGrande("Elegir una imagen con QR", () => _ = ElegirImagenAsync());
        var borrar = Retro.BotonGrande("Borrar", Borrar);
        var fila = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*"), ColumnSpacing = 8 };
        fila.Children.Add(pegar);
        Grid.SetColumn(borrar, 1);
        fila.Children.Add(borrar);

        _actualizar = Retro.BotonGrande("Actualizar listas", () => _ = ActualizarListasAsync());
        var listas = new StackPanel { Spacing = 6, Margin = new Thickness(12, 8) };
        listas.Children.Add(Retro.Texto("Listas de phishing", Retro.Cuerpo, true));
        listas.Children.Add(_estadoListas);
        listas.Children.Add(_mensajeListas);
        listas.Children.Add(Retro.Texto("Al actualizar, Nexo descarga las listas públicas completas de Phishing Army y OpenPhish. No envía tus mensajes ni tus enlaces.", Retro.Secundario, false, Retro.Gris));
        listas.Children.Add(_actualizar);
        _mensajeListas.IsVisible = false;

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));
        raiz.Children.Add(_texto);
        raiz.Children.Add(_remitente);
        raiz.Children.Add(_revisar);
        raiz.Children.Add(fila);
        raiz.Children.Add(qr);
        raiz.Children.Add(_resultado);
        raiz.Children.Add(Retro.Tarjeta(Retro.GrisClaro, listas));
        raiz.Children.Add(Retro.Texto("Nexo nunca abre el enlace: lo compara en el teléfono. No analiza audio ni video.", Retro.Secundario, false, Retro.Gris));
        Content = new ScrollViewer { Content = raiz };

        _cargaDeListas = Task.Run(() =>
        {
            var c = _almacen.Cargar();
            Dispatcher.UIThread.Post(() => { _listas = c.Listas; _avisosListas = c.Avisos; PintarListas(); });
        });

        if (compartido is not null) _ = RecibirAsync(compartido);
    }

    /// <summary>Lo que llego por «Compartir»: el texto va a la caja y se revisa; la imagen se lee como QR.</summary>
    public async Task RecibirAsync(Compartido c)
    {
        if (c.RutaDeImagen is not null) { await RevisarImagenAsync(c.RutaDeImagen, c.NombreDeImagen ?? "imagen compartida"); return; }
        if (c.Texto is null) { MostrarOrigen("No se pudo leer lo que compartiste" + (c.NombreDeImagen is { } m ? ": " + m : "") + "."); return; }
        _texto.Text = c.Texto;
        _remitente.Text = "";
        MostrarOrigen("Llegó por «Compartir».");
        await RevisarAsync();
    }

    private void MostrarOrigen(string? texto)
    {
        _origen.Text = texto ?? "";
        _origen.IsVisible = texto is not null;
    }

    private void Borrar()
    {
        _texto.Text = "";
        _remitente.Text = "";
        _resultado.Children.Clear();
        MostrarOrigen(null);
        _titular.Text = "Pega o comparte un mensaje"; _titular.Foreground = Brushes.Black;
        _explicacion.Text = "Un SMS, un mensaje de WhatsApp o un correo con un enlace. También puedes compartir con Nexo una captura que tenga un código QR.";
    }

    private async Task PegarAsync()
    {
        try
        {
            var portapapeles = TopLevel.GetTopLevel(this)?.Clipboard;
            var t = portapapeles is null ? null : await portapapeles.GetTextAsync();
            if (string.IsNullOrEmpty(t)) { MostrarOrigen("El portapapeles no tiene texto."); return; }
            _texto.Text = t;
            MostrarOrigen("Pegado del portapapeles.");
            await RevisarAsync();
        }
        catch (Exception ex) { MostrarOrigen("No se pudo leer el portapapeles (" + ex.GetType().Name + ")."); }
    }

    private async Task ElegirImagenAsync()
    {
        var almacen = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (almacen is null || !almacen.CanOpen) { MostrarOrigen("Este teléfono no deja elegir archivos desde Nexo."); return; }
        var elegidos = await almacen.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Imagen con un código QR",
            AllowMultiple = false,
            FileTypeFilter = new[] { FilePickerFileTypes.ImageAll },
        });
        var archivo = elegidos.FirstOrDefault();
        if (archivo is null) return;
        // Se copia a la cache (con tope) y se decodifica desde ahi, igual que lo compartido.
        var ruta = Path.Combine(Android.App.Application.Context.CacheDir!.AbsolutePath, "elegida.img");
        try
        {
            await using var entrada = await archivo.OpenReadAsync();
            await using var salida = File.Create(ruta);
            await CopiarConTopeAsync(entrada, salida, 25L * 1024 * 1024);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        { MostrarOrigen("No se pudo abrir la imagen: " + ex.Message); return; }
        await RevisarImagenAsync(ruta, archivo.Name);
    }

    private static async Task CopiarConTopeAsync(Stream entrada, Stream salida, long tope)
    {
        var buf = new byte[81920];
        long total = 0;
        int n;
        while ((n = await entrada.ReadAsync(buf)) > 0)
        {
            total += n;
            if (total > tope) throw new InvalidOperationException("la imagen pesa más de 25 MB");
            await salida.WriteAsync(buf.AsMemory(0, n));
        }
    }

    /// <summary>Lee los QR de la imagen, pone su contenido en la caja y lo revisa. Nexo NUNCA abre lo que dice el QR.</summary>
    private async Task RevisarImagenAsync(string ruta, string nombre)
    {
        if (_ocupado) return;
        _titular.Text = "Leyendo la imagen..."; _titular.Foreground = Brushes.Black;
        var l = await Task.Run(() => ImagenAndroid.LeerQr(ruta));
        try { File.Delete(ruta); } catch (IOException) { }
        string archivo = "«" + (nombre.Length > 60 ? nombre[..60] + "…" : nombre) + "»";
        if (l.Contenidos.Count == 0)
        {
            _titular.Text = "No se encontró ningún código QR"; _titular.Foreground = Brushes.Black;
            _explicacion.Text = archivo + ": " + l.Motivo + ". Prueba con una captura donde el código se vea entero y nítido.";
            _resultado.Children.Clear();
            Android.Util.Log.Info("NEXO", "QR sin_codigo motivo=" + l.Motivo);
            return;
        }
        _texto.Text = string.Join("\n", l.Contenidos);
        _remitente.Text = "";
        MostrarOrigen(l.Contenidos.Count == 1
            ? "Arriba está lo que contiene el código QR de " + archivo + " (Nexo no lo abrió)."
            : "La imagen " + archivo + " tiene " + l.Contenidos.Count + " códigos QR; arriba están todos y se revisan todos (Nexo no abrió ninguno).");
        Android.Util.Log.Info("NEXO", "QR codigos=" + l.Contenidos.Count);
        await RevisarAsync();
    }

    private async Task RevisarAsync()
    {
        if (_ocupado) return;
        _ocupado = true;
        _revisar.IsEnabled = false;
        try
        {
            await _cargaDeListas;   // la primera revision espera a que las listas guardadas esten leidas
            string texto = _texto.Text ?? "", remitente = _remitente.Text ?? "";
            if (string.IsNullOrWhiteSpace(texto)) { _titular.Text = "No hay nada que revisar"; _titular.Foreground = Brushes.Black; _explicacion.Text = "Pega o comparte un mensaje primero."; return; }
            _titular.Text = "Revisando..."; _titular.Foreground = Brushes.Black;
            var listas = _listas;
            var ahora = DateTimeOffset.UtcNow;
            var r = await Task.Run(() => AnalizadorDeMensajes.Analizar(texto, listas, ahora, string.IsNullOrWhiteSpace(remitente) ? null : remitente));
            Pintar(r);
            // Al registro solo van cantidades y el veredicto: nunca el texto ni los enlaces del usuario.
            Android.Util.Log.Info("NEXO", $"REVISAR veredicto={r.Veredicto} enlaces={r.Enlaces.Count} ilegibles={r.EnlacesIlegibles} hallazgos={r.Analisis.Hallazgos.Count} completo={r.Analisis.Completo}");
        }
        catch (Exception ex) { _titular.Text = "No se pudo revisar"; _titular.Foreground = Brushes.Black; _explicacion.Text = ex.Message; }
        finally { _ocupado = false; _revisar.IsEnabled = true; }
    }

    private static IBrush ColorDe(Veredicto v) => v switch { Veredicto.Peligroso => Retro.Rojo, Veredicto.Sospechoso => Ambar, _ => Retro.GrisClaro };

    private void Pintar(RevisionDeMensaje r)
    {
        var (titulo, explicacion) = TextosDeEnlaces.General(r);
        _titular.Text = titulo;
        _titular.Foreground = r.Veredicto == Veredicto.SinSenales ? Brushes.Black : ColorDe(r.Veredicto);   // nunca verde
        _explicacion.Text = explicacion;

        _resultado.Children.Clear();
        foreach (var e in r.Enlaces) _resultado.Children.Add(TarjetaDeEnlace(e));
        if (r.EnlacesIlegibles > 0)
            _resultado.Children.Add(Retro.Texto(r.EnlacesIlegibles == 1 ? "1 enlace no se pudo interpretar." : $"{r.EnlacesIlegibles} enlaces no se pudieron interpretar.", Retro.Secundario, false, Retro.Gris));

        if (r.Analisis.Hallazgos.Count > 0)
        {
            var p = new StackPanel { Spacing = 8, Margin = new Thickness(12) };
            p.Children.Add(Retro.Texto("EN EL MENSAJE", Retro.Secundario, true, Retro.Gris));
            p.Children.Add(Hallazgos(r.Analisis.Hallazgos));
            _resultado.Children.Add(Retro.Tarjeta(ColorDe(AnalizadorDeMensajes.VeredictoDe(r.Analisis.Hallazgos)), p));
        }
        if (r.Analisis.NoEvaluado.Count > 0)
        {
            var p = new StackPanel { Spacing = 4, Margin = new Thickness(12) };
            foreach (var n in r.Analisis.NoEvaluado) p.Children.Add(Retro.Texto("• " + n, Retro.Secundario, false, Retro.Gris));
            _resultado.Children.Add(Retro.SeccionPlegable($"No se pudo comprobar ({r.Analisis.NoEvaluado.Count})", Retro.Tarjeta(Retro.GrisClaro, p)));
        }
    }

    private static Control TarjetaDeEnlace(EnlaceRevisado e)
    {
        var p = new StackPanel { Spacing = 6, Margin = new Thickness(12) };
        p.Children.Add(Retro.Texto("ENLACE · " + TextosDeEnlaces.Veredicto(e.Veredicto), Retro.Secundario, true, e.Veredicto == Veredicto.SinSenales ? Retro.Gris : ColorDe(e.Veredicto)));
        p.Children.Add(Retro.Texto(e.SitioLegible, Retro.Titulo, true));
        if (!string.Equals(e.Original, e.SitioLegible, StringComparison.OrdinalIgnoreCase))
            p.Children.Add(Retro.Texto(e.Original, Retro.Secundario, false, Retro.Gris));
        if (e.MarcaOficial is { } marca) p.Children.Add(Retro.Texto("Es un sitio oficial de " + marca + ".", Retro.Cuerpo));
        if (e.Hallazgos.Count > 0) p.Children.Add(Hallazgos(e.Hallazgos));
        return Retro.Tarjeta(ColorDe(e.Veredicto), p);
    }

    /// <summary>El hallazgo mas grave a la vista; el resto plegado. Cada uno con su detalle y recomendacion.</summary>
    private static Control Hallazgos(IReadOnlyList<HallazgoDeSistema> hs)
    {
        var orden = hs.OrderByDescending(h => h.Severidad).ToList();
        var p = new StackPanel { Spacing = 8 };
        p.Children.Add(Hallazgo(orden[0]));
        if (orden.Count == 1) return p;
        var resto = new StackPanel { Spacing = 8 };
        foreach (var h in orden.Skip(1)) resto.Children.Add(Hallazgo(h));
        p.Children.Add(Retro.SeccionPlegable($"Ver los {orden.Count} motivos", resto));
        return p;
    }

    private static Control Hallazgo(HallazgoDeSistema h)
    {
        var p = new StackPanel { Spacing = 2 };
        p.Children.Add(Retro.Texto(TextosDeEnlaces.Gravedad(h.Severidad) + " · " + h.Titulo, Retro.Cuerpo, true));
        p.Children.Add(Retro.Texto(h.Detalle, Retro.Secundario, false, Retro.Gris));
        if (!string.IsNullOrWhiteSpace(h.Recomendacion)) p.Children.Add(Retro.Texto("→ " + h.Recomendacion, Retro.Secundario));
        return p;
    }

    private void PintarListas() => _estadoListas.Text = TextosDeEnlaces.EstadoDeListas(_listas, _avisosListas, DateTimeOffset.UtcNow);

    private async Task ActualizarListasAsync()
    {
        _actualizar.IsEnabled = false;
        _mensajeListas.Text = "Descargando las listas...";
        _mensajeListas.IsVisible = true;
        try
        {
            await _cargaDeListas;
            using var descarga = new DescargaDeListasHttp();
            var r = await Task.Run(() => _almacen.ActualizarAsync(descarga, _listas, DateTimeOffset.UtcNow));
            _listas = r.Listas;
            _mensajeListas.Text = string.Join("\n", r.Fuentes.Select(f => f.Mensaje));
            Android.Util.Log.Info("NEXO", "LISTAS " + string.Join(" ", r.Fuentes.Select(f => f.Fuente + "=" + (f.Actualizada ? "ok" : "no"))));
            PintarListas();
        }
        catch (Exception ex)
        {
            _mensajeListas.Text = "No se pudieron actualizar: " + ex.Message;
            Android.Util.Log.Warn("NEXO", "LISTAS fallo: " + ex.GetType().Name + " " + ex.Message);
        }
        finally { _actualizar.IsEnabled = true; }
    }
}
