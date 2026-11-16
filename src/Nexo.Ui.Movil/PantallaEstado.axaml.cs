using System;
using System.Linq;
using System.Threading.Tasks;
using Android.Content;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Vigilancia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Nexo.Modules.Threats.Movil;

namespace Nexo.Ui.Movil;

/// <summary>Pantalla de inicio: chequeo del equipo y lista de secciones.</summary>
public sealed partial class PantallaEstado : UserControl
{
    public PantallaEstado(Action irApps, Action irPruebas)
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("IrApps")!.Click += (_, _) => irApps();
        this.FindControl<Button>("IrPruebas")!.Click += (_, _) => irPruebas();
        Mostrar();
        PrepararAvisos();
        PrepararHistorial();
    }

    private void PrepararAvisos()
    {
        var caja = this.FindControl<CheckBox>("AvisarAlInstalar")!;
        var contexto = Android.App.Application.Context;
        caja.IsChecked = ConfiguracionDeVigilancia.Activada(contexto);
        caja.IsCheckedChanged += (_, _) =>
        {
            if (caja.IsChecked == true)
            {
                MainActivity.Actual?.PedirPermisoDeNotificaciones();
                ConfiguracionDeVigilancia.Activar(contexto);
                // La linea base se toma AHORA: lo que ya esta instalado no genera avisos, lo que llegue despues si.
                _ = Task.Run(() =>
                {
                    try { EjecutorDeRevision.Ejecutar(contexto, "activacion"); }
                    finally { Avalonia.Threading.Dispatcher.UIThread.Post(MostrarEstadoDeVigilancia); }
                });
            }
            else ConfiguracionDeVigilancia.Desactivar(contexto);
            MostrarEstadoDeVigilancia();
        };
        this.FindControl<Button>("AhorroDeBateria")!.Click += (_, _) =>
        {
            var i = new Intent(Android.Provider.Settings.ActionIgnoreBatteryOptimizationSettings);
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        };
        MostrarEstadoDeVigilancia();
        // Al volver a esta pantalla (por ejemplo desde «Apps») el texto se actualiza.
        AttachedToVisualTree += (_, _) => MostrarEstadoDeVigilancia();
    }

    private void PrepararHistorial()
    {
        var contexto = Android.App.Application.Context;
        var caja = this.FindControl<CheckBox>("HistorialObsidian")!;
        var texto = this.FindControl<TextBlock>("EstadoHistorial")!;
        var guardar = this.FindControl<Button>("GuardarChequeo")!;
        void Refrescar()
        {
            bool on = HistorialDeObsidian.Activado(contexto);
            guardar.IsVisible = on;
            texto.Text = on ? "Activado. Las notas van a " + HistorialDeObsidian.Carpeta() + ". Solo se guardan las apps que salen «a revisar», nunca la lista completa."
                            : "Apagado. Si usas Obsidian, actívalo para guardar ahí los avisos y el chequeo.";
        }
        caja.IsChecked = HistorialDeObsidian.Activado(contexto);
        Refrescar();
        caja.IsCheckedChanged += (_, _) =>
        {
            try
            {
                if (caja.IsChecked == true) HistorialDeObsidian.Activar(contexto); else HistorialDeObsidian.Desactivar(contexto);
                Refrescar();
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                caja.IsChecked = false;
                HistorialDeObsidian.Desactivar(contexto);
                texto.Text = "No se pudo escribir en " + HistorialDeObsidian.Carpeta() + ": " + ex.Message;
            }
        };
        guardar.Click += async (_, _) =>
        {
            if (_datos is null) return;
            var filas = ChequeoDelEquipo.Evaluar(_datos, DateTime.Today, Catalogo.Value);
            try
            {
                await Task.Run(() => HistorialDeObsidian.Escribir(new[] { EventosDeApps.DelChequeo(filas) }));
                texto.Text = "Chequeo guardado en " + HistorialDeObsidian.Carpeta() + ".";
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException)
            { texto.Text = "No se pudo guardar el chequeo: " + ex.Message; }
        };
    }

    private void MostrarEstadoDeVigilancia()
    {
        var contexto = Android.App.Application.Context;
        var texto = this.FindControl<TextBlock>("EstadoVigilancia")!;
        var boton = this.FindControl<Button>("AhorroDeBateria")!;
        if (!ConfiguracionDeVigilancia.Activada(contexto)) { texto.Text = "Apagado: Nexo solo revisa cuando abres «Apps instaladas»."; boton.IsVisible = false; return; }
        var estado = EstadoDeVigilancia.Cargar(RutasDeNexo.Vigilancia(contexto), out _);
        var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var lineas = new System.Collections.Generic.List<string>();
        if (estado.UltimaRevisionMs is { } ult)
        {
            var min = (ahora - ult) / 60000;
            lineas.Add(min < 1 ? "Última revisión: hace menos de 1 minuto." : min < 120 ? $"Última revisión: hace {min} min." : $"Última revisión: hace {min / 60} h.");
        }
        else lineas.Add("Aún no hay ninguna revisión.");
        bool atrasada = VigilanteDeInstalaciones.EstaAtrasada(estado.UltimaRevisionMs, ConfiguracionDeVigilancia.ActivadaDesdeMs(contexto), ahora, TimeSpan.FromHours(24));
        if (atrasada) lineas.Add("⚠ Hace más de 24 h que no se revisa: el sistema o el fabricante puede estar deteniendo a Nexo en segundo plano. Excluye a Nexo del ahorro de batería.");
        if (!Notificador.PuedeNotificar(contexto)) lineas.Add("⚠ Falta el permiso de notificaciones: no se podrá mostrar ningún aviso.");
        texto.Text = string.Join("\n", lineas);
        boton.IsVisible = atrasada;
    }

    private static readonly Lazy<CatalogoDeSenales> Catalogo = new(CatalogoDeSenales.Embebido);
    private DatosDelEquipo? _datos;

    private void Mostrar()
    {
        var contexto = Android.App.Application.Context;
        var lector = new LectorDelEquipoAndroid(contexto);
        _datos = lector.Leer();
        Android.Util.Log.Info("NEXO", "EQUIPO wifi=" + _datos.Wifi + " (" + lector.DiagnosticoDeWifi + ")");
        Pintar();
        this.FindControl<Button>("AbrirPlayStore")!.Click += (_, _) =>
        {
            var i = contexto.PackageManager?.GetLaunchIntentForPackage("com.android.vending");
            if (i is null) return;
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        };
        // Lo que depende de leer todas las apps (0,9 s en un S20 FE) se calcula aparte, sin frenar la pantalla.
        _ = Task.Run(() =>
        {
            var apps = new LectorDeAppsAndroid(contexto).Leer();
            var puntuador = new PuntuadorDeRiesgo(Catalogo.Value);
            var instalan = apps.Where(a => !a.EsDeSistema && a.InstalaAppsConcedido)
                .Select(a => new AppQueInstala(a.Nombre, a.Paquete, puntuador.Evaluar(a).Nivel)).ToList();
            Avalonia.Threading.Dispatcher.UIThread.Post(() => { _datos = _datos! with { AppsQueInstalan = instalan }; Pintar(); });
        });
    }

    private void Pintar()
    {
        var filas = this.FindControl<StackPanel>("Filas")!;
        var resumen = this.FindControl<TextBlock>("Resumen")!;
        var lista = ChequeoDelEquipo.Evaluar(_datos!, DateTime.Today, Catalogo.Value);
        var avisos = ChequeoDelEquipo.Avisos(lista);
        resumen.Text = avisos == 0 ? "Estado del equipo: sin avisos" : $"Estado del equipo: {avisos} aviso(s)";
        filas.Children.Clear();
        foreach (var c in lista)
        {
            var (marca, color) = c.Nivel switch
            {
                NivelDeComprobacion.Bien => ("[OK]", Brushes.DarkGreen),
                NivelDeComprobacion.Aviso => ("[!]", Brushes.Firebrick),
                _ => ("[i]", Brushes.DimGray),
            };
            var fila = new Grid { ColumnDefinitions = new ColumnDefinitions("40,*"), MinHeight = 48 };
            fila.Children.Add(new TextBlock { Text = marca, Foreground = color, FontWeight = FontWeight.Bold, VerticalAlignment = VerticalAlignment.Center });
            var texto = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(texto, 1);
            texto.Children.Add(new TextBlock { Text = c.Nombre, FontWeight = FontWeight.Bold, TextWrapping = TextWrapping.Wrap });
            texto.Children.Add(new TextBlock { Text = c.Detalle, TextWrapping = TextWrapping.Wrap });
            fila.Children.Add(texto);
            filas.Children.Add(fila);
        }
    }

}
