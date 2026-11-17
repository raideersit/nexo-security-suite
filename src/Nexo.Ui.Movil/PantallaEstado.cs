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

namespace Nexo.Ui.Movil;

/// <summary>
/// Chequeo del equipo (§3.4) con el estilo «Classic tactil v2», igual que «Apps»: un titular claro arriba, una tarjeta con franja roja por
/// cada aviso (con un boton al ajuste de Android donde se arregla) y lo que esta bien o no se pudo evaluar, plegado abajo.
/// </summary>
public sealed class PantallaEstado : UserControl
{
    private readonly TextBlock _titular = Retro.Texto("", 24, true);
    private readonly TextBlock _resumen = Retro.Texto("", Retro.Cuerpo);
    private readonly TextBlock _cuando = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly StackPanel _tarjetas = new() { Spacing = 10 };
    private DatosDelEquipo? _datos;
    private DateTime _revisado;
    // Las secciones plegadas se repintan al llegar las apps (0,9 s despues): se recuerda si el usuario las habia abierto.
    private bool _infoAbierta, _bienAbierta;

    /// <summary>
    /// A donde lleva el boton de cada fila. Se prueban las acciones en orden y se usa la primera que el telefono sabe abrir:
    /// «Actualizacion de software» no es una accion publica en todas las marcas, por eso cae a «Informacion del telefono».
    /// </summary>
    private static readonly Dictionary<string, (string Boton, string[] Acciones)> Arreglos = new()
    {
        ["Bloqueo de pantalla"] = ("Abrir ajustes de seguridad", new[] { Android.Provider.Settings.ActionSecuritySettings }),
        ["Parche de seguridad"] = ("Buscar actualizaciones", new[] { "android.settings.SYSTEM_UPDATE_SETTINGS", Android.Provider.Settings.ActionDeviceInfoSettings }),
        ["Versión de Android"] = ("Buscar actualizaciones", new[] { "android.settings.SYSTEM_UPDATE_SETTINGS", Android.Provider.Settings.ActionDeviceInfoSettings }),
        ["Opciones de desarrollador"] = ("Abrir opciones de desarrollador", new[] { Android.Provider.Settings.ActionApplicationDevelopmentSettings }),
        ["Depuración USB"] = ("Abrir opciones de desarrollador", new[] { Android.Provider.Settings.ActionApplicationDevelopmentSettings }),
        ["Wi-Fi actual"] = ("Abrir ajustes de Wi-Fi", new[] { Android.Provider.Settings.ActionWifiSettings }),
        ["Apps que pueden instalar otras apps"] = ("Ver qué apps pueden instalar", new[] { Android.Provider.Settings.ActionManageUnknownAppSources }),
    };

    public PantallaEstado()
    {
        var cabecera = new StackPanel { Spacing = 8 };
        cabecera.Children.Add(_titular);
        cabecera.Children.Add(_resumen);
        cabecera.Children.Add(_cuando);

        var raiz = new StackPanel { Margin = new Thickness(12), Spacing = 12 };
        raiz.Children.Add(Retro.Hundido(cabecera, 14));
        raiz.Children.Add(Retro.BotonGrande("Revisar de nuevo", Revisar, destacado: true));
        raiz.Children.Add(_tarjetas);
        Content = new ScrollViewer { Content = raiz };
        Revisar();
    }

    private void Revisar()
    {
        _datos = EquipoAhora.Leer();
        _revisado = DateTime.Now;
        Pintar();
        // Lo que necesita leer todas las apps se calcula aparte, sin frenar la pantalla.
        _ = Task.Run(() =>
        {
            var apps = EquipoAhora.LeerApps();
            Dispatcher.UIThread.Post(() => { _datos = _datos! with { AppsQueInstalan = apps.Instalan }; Pintar(); });
        });
    }

    private void Pintar()
    {
        var lista = EquipoAhora.Evaluar(_datos!);
        var avisos = lista.Where(c => c.Nivel == NivelDeComprobacion.Aviso).ToList();
        var info = lista.Where(c => c.Nivel == NivelDeComprobacion.Info).ToList();
        var bien = lista.Where(c => c.Nivel == NivelDeComprobacion.Bien).ToList();

        if (avisos.Count == 0) { _titular.Text = "Todo en orden"; _titular.Foreground = Retro.Verde; }
        else { _titular.Text = avisos.Count == 1 ? "1 cosa que mirar" : $"{avisos.Count} cosas que mirar"; _titular.Foreground = Retro.Rojo; }
        _resumen.Text = $"{bien.Count} bien · {info.Count} sin evaluar o informativas.";
        _cuando.Text = "Revisado a las " + _revisado.ToString("HH:mm") + ". Solo lectura: Nexo no cambia ningún ajuste.";

        _tarjetas.Children.Clear();
        foreach (var c in avisos) _tarjetas.Children.Add(TarjetaDeAviso(c));
        if (avisos.Count == 0)
            _tarjetas.Children.Add(Retro.Texto("Nada que arreglar. Si algo cambia y tienes encendido «Avisar si el equipo empeora», Nexo te avisará.", Retro.Cuerpo));
        if (info.Count > 0)
            _tarjetas.Children.Add(Plegada($"Sin evaluar o informativas ({info.Count})", info, Retro.GrisClaro, () => _infoAbierta, v => _infoAbierta = v));
        if (bien.Count > 0)
            _tarjetas.Children.Add(Plegada($"Está bien ({bien.Count})", bien, Retro.Verde, () => _bienAbierta, v => _bienAbierta = v));
    }

    private Control TarjetaDeAviso(Comprobacion c)
    {
        var p = new StackPanel { Spacing = 6, Margin = new Thickness(12) };
        p.Children.Add(Retro.Texto("AVISO", Retro.Secundario, true, Retro.Rojo));
        p.Children.Add(Retro.Texto(c.Nombre, Retro.Titulo, true));
        p.Children.Add(Retro.Texto(c.Detalle, Retro.Cuerpo));
        if (BotonDeArreglo(c) is { } boton) p.Children.Add(boton);
        return Retro.Tarjeta(Retro.Rojo, p);
    }

    private Control Plegada(string titulo, IReadOnlyList<Comprobacion> filas, IBrush franja, Func<bool> abierta, Action<bool> recordar)
    {
        var contenido = new StackPanel { Spacing = 10 };
        foreach (var c in filas)
        {
            var p = new StackPanel { Spacing = 4, Margin = new Thickness(12) };
            p.Children.Add(Retro.Texto(c.Nombre, Retro.Cuerpo, true));
            p.Children.Add(Retro.Texto(c.Detalle, Retro.Secundario, false, Retro.Gris));
            // Lo que esta bien no lleva boton; lo informativo si, cuando hay un sitio util al que ir (Play Protect, apps que instalan).
            if (c.Nivel != NivelDeComprobacion.Bien && BotonDeArreglo(c) is { } boton) p.Children.Add(boton);
            contenido.Children.Add(Retro.Tarjeta(franja, p));
        }
        var seccion = Retro.SeccionPlegable(titulo, contenido, abierta());
        // Recordar si se abrio, para el repintado de cuando llegan las apps.
        contenido.PropertyChanged += (_, e) => { if (e.Property == IsVisibleProperty) recordar(contenido.IsVisible); };
        return seccion;
    }

    private static Button? BotonDeArreglo(Comprobacion c)
    {
        if (c.Nombre == "Play Protect")
            return Retro.BotonGrande("Abrir Play Store (Perfil > Play Protect)", () => AbrirApp("com.android.vending"));
        return Arreglos.TryGetValue(c.Nombre, out var a) ? Retro.BotonGrande(a.Boton, () => AbrirAjuste(c.Nombre, a.Acciones)) : null;
    }

    private static void AbrirAjuste(string fila, string[] acciones)
    {
        var contexto = Android.App.Application.Context;
        foreach (var accion in acciones)
        {
            var i = new Intent(accion);
            i.AddFlags(ActivityFlags.NewTask);
            if (i.ResolveActivity(contexto.PackageManager!) is null) continue;
            Android.Util.Log.Info("NEXO", $"ESTADO abrir fila={fila.Replace(' ', '_')} accion={accion}");
            contexto.StartActivity(i);
            return;
        }
        Android.Util.Log.Warn("NEXO", $"ESTADO sin_ajuste fila={fila.Replace(' ', '_')}");
        AbrirApp(null);
    }

    /// <summary>Abre una app por su paquete; si no esta (o es null), abre los Ajustes generales.</summary>
    private static void AbrirApp(string? paquete)
    {
        var contexto = Android.App.Application.Context;
        var i = paquete is null ? null : contexto.PackageManager?.GetLaunchIntentForPackage(paquete);
        i ??= new Intent(Android.Provider.Settings.ActionSettings);
        i.AddFlags(ActivityFlags.NewTask);
        contexto.StartActivity(i);
    }
}
