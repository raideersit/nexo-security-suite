using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Modules.Threats.Movil;
using Nexo.Ui.Movil.Firewall;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Firewall por app (Salida 7, 3.6) con el estilo «Classic tactil v2»: titular con lo que se bloquea AHORA (lo que dice el servicio, no lo
/// que dicen las reglas), interruptor general con las limitaciones a la vista, buscador y una fila por app que pide internet.
/// </summary>
public sealed class PantallaFirewall : UserControl
{
    private sealed record AppDeLista(string Paquete, string Nombre, bool EsDeSistema);

    private readonly TextBlock _titular = Retro.Texto("", 24, true);
    private readonly TextBlock _resumen = Retro.Texto("", Retro.Cuerpo);
    private readonly TextBox _buscar = new() { FontSize = Retro.Cuerpo, Watermark = "Buscar una app" };
    private readonly StackPanel _filas = new() { Spacing = 0 };
    private readonly TextBlock _cargando = Retro.Texto("Leyendo las apps...", Retro.Secundario, false, Retro.Gris);
    private readonly Retro.InterruptorRetro _general;
    private bool _mostrarSistema, _reponiendo;
    private List<AppDeLista> _apps = new();

    private static string Ruta => RutasDeNexo.Firewall(Android.App.Application.Context);

    public PantallaFirewall()
    {
        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_resumen);

        var reglas = ReglasDelFirewall.Cargar(Ruta, out _);
        var tarjeta = new StackPanel { Spacing = 6, Margin = new Thickness(12, 8) };
        tarjeta.Children.Add(Retro.FilaConInterruptor("Firewall", "Bloquea internet a las apps que marques abajo.", reglas.Encendido, CambiarGeneral, out _general));
        tarjeta.Children.Add(Retro.Texto("Cómo funciona: Nexo crea una VPN que solo incluye las apps bloqueadas y no deja salir nada de ellas. Las demás apps no pasan por la VPN. Nexo no lee ni guarda tu tráfico.", Retro.Secundario, false, Retro.Gris));
        tarjeta.Children.Add(Retro.Texto("Límites: Android permite una sola VPN a la vez (con el firewall encendido no puedes usar otra, como WireGuard, y al revés). Bloquea todo el internet de la app: no se puede «solo datos móviles» ni por sitio. La app bloqueada verá «sin conexión».", Retro.Secundario, false, Retro.Gris));

        var sistema = Retro.FilaConInterruptor("Mostrar apps del sistema", "Como el navegador de Samsung. Bloquear una app del sistema puede romper funciones del teléfono: hazlo solo si sabes para qué sirve.", false, v => { _mostrarSistema = v; Pintar(); }, out _);

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));
        raiz.Children.Add(Retro.Tarjeta(Retro.GrisClaro, tarjeta));
        raiz.Children.Add(_buscar);
        raiz.Children.Add(Retro.Hundido(sistema, 8));
        raiz.Children.Add(_cargando);
        raiz.Children.Add(Retro.Hundido(_filas, 8));
        Content = new ScrollViewer { Content = raiz };

        _buscar.TextChanged += (_, _) => Pintar();
        Action refrescar = () => Dispatcher.UIThread.Post(Refrescar);
        Action rechazada = () => Dispatcher.UIThread.Post(() => { Refrescar(); _resumen.Text = "Android no dio permiso para crear la VPN: el firewall sigue apagado."; });
        AttachedToVisualTree += (_, _) => { ServicioFirewall.Cambio += refrescar; MainActivity.VpnRechazada += rechazada; MainActivity.Reanudada += refrescar; Refrescar(); };
        DetachedFromVisualTree += (_, _) => { ServicioFirewall.Cambio -= refrescar; MainActivity.VpnRechazada -= rechazada; MainActivity.Reanudada -= refrescar; };

        _ = Task.Run(() =>
        {
            var apps = LeerApps();
            Dispatcher.UIThread.Post(() => { _apps = apps; _cargando.IsVisible = false; Pintar(); });
        });
        Refrescar();
    }

    /// <summary>Apps que piden internet. Los nombres de las del sistema se cargan aqui (el lector general no los lee, para ir mas rapido).</summary>
    private static List<AppDeLista> LeerApps()
    {
        var c = Android.App.Application.Context;
        var pm = c.PackageManager!;
        var lista = new List<AppDeLista>();
        foreach (var a in new LectorDeAppsAndroid(c).Leer().Where(a => PlanDeFirewallMovil.EsBloqueable(a, c.PackageName!)))
        {
            var nombre = a.Nombre;
            if (a.EsDeSistema)
            {
                try { nombre = pm.GetApplicationInfo(a.Paquete, 0).LoadLabel(pm)?.ToString() ?? a.Paquete; }
                catch (Android.Content.PM.PackageManager.NameNotFoundException) { }
            }
            lista.Add(new AppDeLista(a.Paquete, string.IsNullOrEmpty(nombre) ? a.Paquete : nombre, a.EsDeSistema));
        }
        return lista.OrderBy(x => x.Nombre, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    /// <summary>El titular dice lo que el SERVICIO esta bloqueando, no lo que dicen las reglas: si no hay tunel, no se promete bloqueo.</summary>
    private void Refrescar()
    {
        var reglas = ReglasDelFirewall.Cargar(Ruta, out _);
        _reponiendo = true; _general.Activado = reglas.Encendido; _reponiendo = false;
        int activas = ServicioFirewall.Bloqueando.Count;
        if (activas > 0)
        {
            _titular.Text = activas == 1 ? "Bloqueando 1 app" : $"Bloqueando {activas} apps"; _titular.Foreground = Retro.Verde;
            _resumen.Text = "Android muestra un aviso de «VPN activada» (en algunos Samsung, solo en la cortina) mientras el firewall está activo.";
        }
        else if (reglas.Revocado)
        {
            _titular.Text = "El firewall se apagó"; _titular.Foreground = Retro.Rojo;
            _resumen.Text = "Android quitó la VPN de Nexo: la apagaste en Ajustes, otra app de VPN tomó el control o el teléfono se reinició sin permiso. Ninguna app está bloqueada. Enciéndelo otra vez si quieres.";
        }
        else if (reglas.Encendido)
        {
            _titular.Text = reglas.Bloqueadas.Count == 0 ? "Marca al menos una app" : "Encendiendo..."; _titular.Foreground = Brushes.Black;
            _resumen.Text = "Mientras no haya apps marcadas no se crea ninguna VPN: nada se bloquea.";
        }
        else
        {
            _titular.Text = "Firewall apagado"; _titular.Foreground = Brushes.Black;
            _resumen.Text = reglas.Bloqueadas.Count == 0 ? "Ninguna app bloqueada." : $"{reglas.Bloqueadas.Count} app(s) marcadas: se bloquearán al encenderlo.";
        }
        Pintar();
    }

    private void CambiarGeneral(bool encender)
    {
        if (_reponiendo) return;
        var reglas = ReglasDelFirewall.Cargar(Ruta, out _);
        reglas.Encendido = encender;
        reglas.Revocado = false;
        reglas.Guardar(Ruta);
        Android.Util.Log.Info("NEXO", "FIREWALL interruptor=" + encender + " marcadas=" + reglas.Bloqueadas.Count);
        Aplicar(reglas);
        Refrescar();
    }

    private void CambiarApp(string paquete, bool bloquear)
    {
        var reglas = ReglasDelFirewall.Cargar(Ruta, out _);
        if (bloquear) reglas.Bloqueadas.Add(paquete); else reglas.Bloqueadas.Remove(paquete);
        reglas.Guardar(Ruta);
        Android.Util.Log.Info("NEXO", $"FIREWALL marcar paquete={paquete} bloquear={bloquear}");
        if (reglas.Encendido) Aplicar(reglas);
        Refrescar();
    }

    /// <summary>Encendido con alguna app marcada: pasa por MainActivity (pide el consentimiento si falta). Si no: el servicio cierra lo que haya.</summary>
    private static void Aplicar(ReglasDelFirewall reglas)
    {
        var c = Android.App.Application.Context;
        if (reglas.Encendido && reglas.Bloqueadas.Count > 0 && MainActivity.Actual is { } a) a.EncenderFirewall();
        else ServicioFirewall.Aplicar(c);
    }

    private void Pintar()
    {
        if (_apps.Count == 0) return;
        var reglas = ReglasDelFirewall.Cargar(Ruta, out _);
        var filtro = (_buscar.Text ?? "").Trim();
        var visibles = _apps
            .Where(a => _mostrarSistema || !a.EsDeSistema || reglas.Bloqueadas.Contains(a.Paquete))   // una del sistema ya bloqueada se ve siempre
            .Where(a => filtro.Length == 0 || a.Nombre.Contains(filtro, StringComparison.CurrentCultureIgnoreCase) || a.Paquete.Contains(filtro, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(a => reglas.Bloqueadas.Contains(a.Paquete))
            .ToList();
        _filas.Children.Clear();
        if (visibles.Count == 0) { _filas.Children.Add(Retro.Texto("Ninguna app coincide.", Retro.Secundario, false, Retro.Gris)); return; }
        foreach (var a in visibles)
        {
            var paquete = a.Paquete;
            var detalle = a.EsDeSistema ? "App del sistema · " + paquete : paquete;
            _filas.Children.Add(Retro.FilaConInterruptor(a.Nombre, detalle, reglas.Bloqueadas.Contains(paquete), v => CambiarApp(paquete, v), out _));
        }
    }
}
