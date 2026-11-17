using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Android.Content;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>
/// Los tres avisos de Nexo (§3.3 y notificaciones generales) con el estilo «Classic tactil v2»: un titular que dice si Nexo esta vigilando
/// (o que lo impide, con el boton para arreglarlo), una tarjeta por aviso con su interruptor y su estado, y el acceso a los canales de Android.
/// </summary>
public sealed class PantallaAvisos : UserControl
{
    private readonly TextBlock _titular = Retro.Texto("", 24, true);
    private readonly TextBlock _resumen = Retro.Texto("", Retro.Cuerpo);
    private readonly Button _permiso, _bateria;
    private readonly TextBlock _estadoApps = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _estadoEquipo = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _estadoResumen = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly Border _franjaApps = new(), _franjaEquipo = new(), _franjaResumen = new();

    public PantallaAvisos()
    {
        var contexto = Android.App.Application.Context;

        _permiso = Retro.BotonGrande("Dar permiso de notificaciones", PedirPermiso, destacado: true);
        _bateria = Retro.BotonGrande("Excluir a Nexo del ahorro de batería", () => Abrir(new Intent(Android.Provider.Settings.ActionIgnoreBatteryOptimizationSettings)), destacado: true);
        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_resumen);
        cabecera.Children.Add(_permiso);
        cabecera.Children.Add(_bateria);

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));

        raiz.Children.Add(TarjetaDeAviso(_franjaApps, "Avisar al instalar una app", "Cuando se instala una app con señales de riesgo o que coincide con una huella conocida. También si una app se actualiza y empeora.",
            ConfiguracionDeVigilancia.Activada(contexto), _estadoApps, activado =>
            {
                if (activado)
                {
                    MainActivity.Actual?.PedirPermisoDeNotificaciones();
                    ConfiguracionDeVigilancia.Activar(contexto);
                    // La linea base se toma AHORA: lo que ya esta instalado no genera avisos, lo que llegue despues si.
                    EnSegundoPlano("activacion", () => EjecutorDeRevision.Ejecutar(contexto, "activacion"));
                }
                else ConfiguracionDeVigilancia.Desactivar(contexto);
            }));

        raiz.Children.Add(TarjetaDeAviso(_franjaEquipo, "Avisar si el equipo empeora", "Si se quita el bloqueo de pantalla, se enciende la depuración USB, te conectas a una Wi-Fi sin cifrado o el parche se queda antiguo. Lo que ya está mal hoy no avisa: se ve en «Estado».",
            ConfiguracionDeVigilancia.EquipoActivado(contexto), _estadoEquipo, activado =>
            {
                if (activado)
                {
                    MainActivity.Actual?.PedirPermisoDeNotificaciones();
                    ConfiguracionDeVigilancia.ActivarEquipo(contexto);
                    EnSegundoPlano("activacion-equipo", () => EjecutorDelEquipo.Ejecutar(contexto, "activacion-equipo", lineaBaseEquipo: true));
                }
                else ConfiguracionDeVigilancia.DesactivarEquipo(contexto);
            }));

        raiz.Children.Add(TarjetaDeAviso(_franjaResumen, "Resumen semanal", "Una notificación sin sonido cada 7 días: cuántas apps hay a revisar y cuántos avisos tiene el equipo. Sin nombres de apps.",
            ConfiguracionDeVigilancia.ResumenActivado(contexto), _estadoResumen, activado =>
            {
                if (activado)
                {
                    MainActivity.Actual?.PedirPermisoDeNotificaciones();
                    ConfiguracionDeVigilancia.ActivarResumen(contexto);
                    EnSegundoPlano("activacion-resumen", () => EjecutorDelEquipo.Ejecutar(contexto, "activacion-resumen", reiniciarResumen: true));
                }
                else ConfiguracionDeVigilancia.DesactivarResumen(contexto);
            }));

        raiz.Children.Add(Retro.Texto("Con Nexo cerrado, un aviso puede tardar unos 15 a 20 minutos: Android decide cuándo corre la revisión.", Retro.Secundario, false, Retro.Gris));
        // Sonido, vibracion o silencio de cada tipo de aviso: lo decide el usuario en Android, canal por canal.
        raiz.Children.Add(Retro.FilaQueNavega("Sonido de cada aviso", "Ajustes de notificaciones de Android: cada tipo de aviso se puede silenciar o hacer sonar por separado.", () =>
        {
            var i = new Intent(Android.Provider.Settings.ActionAppNotificationSettings);
            i.PutExtra(Android.Provider.Settings.ExtraAppPackage, contexto.PackageName);
            Abrir(i);
        }));

        Content = new ScrollViewer { Content = raiz };
        Mostrar();
        // Al volver de otra pantalla o del dialogo del permiso, todo se actualiza (antes seguia diciendo «falta el permiso» aunque ya estuviera concedido).
        Action alReanudar = () => Dispatcher.UIThread.Post(Mostrar);
        AttachedToVisualTree += (_, _) => { MainActivity.Reanudada += alReanudar; Mostrar(); };
        DetachedFromVisualTree += (_, _) => MainActivity.Reanudada -= alReanudar;
    }

    /// <summary>Tarjeta con franja (verde encendido, gris apagado), el interruptor y una linea de estado debajo.</summary>
    private Control TarjetaDeAviso(Border franja, string titulo, string detalle, bool activado, TextBlock estado, Action<bool> alCambiar)
    {
        var p = new StackPanel { Spacing = 4, Margin = new Thickness(12, 8) };
        p.Children.Add(Retro.FilaConInterruptor(titulo, detalle, activado, a => { alCambiar(a); Mostrar(); }, out _));
        p.Children.Add(estado);
        var rejilla = new Grid { ColumnDefinitions = new ColumnDefinitions("10,*") };
        rejilla.Children.Add(franja);
        Grid.SetColumn(p, 1);
        rejilla.Children.Add(p);
        return new Border { Background = Brushes.White, BorderBrush = Retro.GrisClaro, BorderThickness = new Thickness(2), Child = rejilla };
    }

    private void EnSegundoPlano(string origen, Action trabajo) => _ = Task.Run(() =>
    {
        try { trabajo(); }
        catch (Exception ex) { Android.Util.Log.Error("NEXO", $"AVISOS fallo al activar ({origen}): " + ex); }
        finally { Dispatcher.UIThread.Post(Mostrar); }
    });

    private void Mostrar()
    {
        var c = Android.App.Application.Context;
        bool apps = ConfiguracionDeVigilancia.Activada(c), equipo = ConfiguracionDeVigilancia.EquipoActivado(c), resumen = ConfiguracionDeVigilancia.ResumenActivado(c);
        var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var vigilancia = EstadoDeVigilancia.Cargar(RutasDeNexo.Vigilancia(c), out _);
        var delEquipo = EstadoDelEquipo.Cargar(RutasDeNexo.Equipo(c), out _);

        _franjaApps.Background = apps ? Retro.Verde : Retro.GrisClaro;
        _franjaEquipo.Background = equipo ? Retro.Verde : Retro.GrisClaro;
        _franjaResumen.Background = resumen ? Retro.Verde : Retro.GrisClaro;

        _estadoApps.Text = apps ? Retro.HaceCuanto(vigilancia.UltimaRevisionMs, ahora) : "Apagado: Nexo solo revisa las apps cuando abres «Apps».";
        _estadoEquipo.Text = !equipo ? "Apagado."
            : Retro.HaceCuanto(delEquipo.UltimaRevisionMs, ahora) + (delEquipo.EnAviso.Count > 0 ? $" Ya avisado: {string.Join(", ", delEquipo.EnAviso)}." : "");
        _estadoResumen.Text = !resumen ? "Apagado."
            : delEquipo.UltimoResumenMs is { } ultimo
                ? "Próximo resumen: desde el " + DateTimeOffset.FromUnixTimeMilliseconds(ultimo + (long)VigilanteDelEquipo.Semana.TotalMilliseconds).ToLocalTime().ToString("dd-MM-yyyy") + "."
                : "La semana empieza a contar en la próxima revisión.";

        int encendidos = new[] { apps, equipo, resumen }.Count(x => x);
        bool permiso = Notificador.PuedeNotificar(c);
        // Atrasada: la revision mas reciente de lo que este encendido lleva mas de 24 h sin correr.
        long? ultima = new[] { apps ? vigilancia.UltimaRevisionMs : null, equipo || resumen ? delEquipo.UltimaRevisionMs : null }.Max();
        bool atrasada = encendidos > 0 && VigilanteDeInstalaciones.EstaAtrasada(ultima, apps ? ConfiguracionDeVigilancia.ActivadaDesdeMs(c) : 0, ahora, TimeSpan.FromHours(24));

        _permiso.IsVisible = encendidos > 0 && !permiso;
        _bateria.IsVisible = atrasada && permiso;
        if (encendidos == 0)
        {
            _titular.Text = "Avisos apagados"; _titular.Foreground = Brushes.Black;
            _resumen.Text = "Nexo solo revisa cuando abres «Apps» o «Estado». Enciende abajo lo que quieras que vigile.";
        }
        else if (!permiso)
        {
            _titular.Text = "No puede avisarte"; _titular.Foreground = Retro.Rojo;
            _resumen.Text = "Falta el permiso de notificaciones: Nexo revisa, pero ningún aviso llegará a la pantalla.";
        }
        else if (atrasada)
        {
            _titular.Text = "La revisión está atrasada"; _titular.Foreground = Retro.Rojo;
            _resumen.Text = "Hace más de 24 h que no se revisa: el sistema o el fabricante puede estar deteniendo a Nexo en segundo plano.";
        }
        else
        {
            _titular.Text = "Nexo está vigilando"; _titular.Foreground = Retro.Verde;
            _resumen.Text = $"{encendidos} de 3 avisos encendidos. " + Retro.HaceCuanto(ultima, ahora);
        }
    }

    /// <summary>
    /// Pide el permiso. Si Android ya no muestra el dialogo (el usuario lo nego dos veces), lleva a los ajustes de notificaciones de Nexo,
    /// que es el unico sitio donde se puede conceder a mano.
    /// </summary>
    private static void PedirPermiso()
    {
        var actividad = MainActivity.Actual;
        // Sale el dialogo si nunca se pidio, o si se nego una sola vez (Android pide entonces «explicar» y deja volver a preguntar).
        if (actividad is not null && OperatingSystem.IsAndroidVersionAtLeast(33)
            && (!actividad.YaSePidioElPermiso || actividad.ShouldShowRequestPermissionRationale("android.permission.POST_NOTIFICATIONS")))
        {
            Android.Util.Log.Info("NEXO", "AVISOS permiso: dialogo");
            actividad.PedirPermisoDeNotificaciones();
            return;
        }
        Android.Util.Log.Info("NEXO", "AVISOS permiso: ajustes (el dialogo ya no sale)");
        var c = Android.App.Application.Context;
        var i = new Intent(Android.Provider.Settings.ActionAppNotificationSettings);
        i.PutExtra(Android.Provider.Settings.ExtraAppPackage, c.PackageName);
        Abrir(i);
    }

    private static void Abrir(Intent i)
    {
        i.AddFlags(ActivityFlags.NewTask);
        Android.App.Application.Context.StartActivity(i);
    }
}
