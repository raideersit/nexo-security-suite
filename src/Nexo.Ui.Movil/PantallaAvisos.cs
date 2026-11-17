using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Android.Content;
using Avalonia.Controls;
using Avalonia.Threading;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>Avisos al instalar o actualizar una app (§3.3): un interruptor grande, la ultima revision y la ayuda para el ahorro de bateria.</summary>
public sealed class PantallaAvisos : UserControl
{
    private readonly TextBlock _estado = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly TextBlock _estadoGeneral = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly Button _bateria;

    public PantallaAvisos()
    {
        var contexto = Android.App.Application.Context;
        var raiz = new StackPanel { Margin = new Avalonia.Thickness(12), Spacing = 12 };

        var fila = Retro.FilaConInterruptor("Avisar al instalar una app", "También avisa si una app se actualiza y empeora.", ConfiguracionDeVigilancia.Activada(contexto), activado =>
        {
            if (activado)
            {
                MainActivity.Actual?.PedirPermisoDeNotificaciones();
                ConfiguracionDeVigilancia.Activar(contexto);
                // La linea base se toma AHORA: lo que ya esta instalado no genera avisos, lo que llegue despues si.
                _ = Task.Run(() =>
                {
                    try { EjecutorDeRevision.Ejecutar(contexto, "activacion"); }
                    finally { Dispatcher.UIThread.Post(Mostrar); }
                });
            }
            else ConfiguracionDeVigilancia.Desactivar(contexto);
            Mostrar();
        }, out _);
        raiz.Children.Add(Retro.Hundido(fila, 8));
        raiz.Children.Add(_estado);

        // Notificaciones generales: cada una con su canal en los ajustes de Android.
        var filaEquipo = Retro.FilaConInterruptor("Avisar si el equipo empeora",
            "Si se quita el bloqueo de pantalla, se enciende la depuración USB, te conectas a una Wi-Fi sin cifrado o el parche se queda antiguo. Lo que ya está mal hoy no avisa: se ve en «Estado».",
            ConfiguracionDeVigilancia.EquipoActivado(contexto), activado =>
            {
                if (activado)
                {
                    MainActivity.Actual?.PedirPermisoDeNotificaciones();
                    ConfiguracionDeVigilancia.ActivarEquipo(contexto);
                    _ = Task.Run(() =>
                    {
                        try { EjecutorDelEquipo.Ejecutar(contexto, "activacion-equipo", lineaBaseEquipo: true); }
                        catch (Exception ex) { Android.Util.Log.Error("NEXO", "EQUIPO-REVISION fallo al activar: " + ex); }
                        finally { Dispatcher.UIThread.Post(Mostrar); }
                    });
                }
                else ConfiguracionDeVigilancia.DesactivarEquipo(contexto);
                Mostrar();
            }, out _);
        raiz.Children.Add(Retro.Hundido(filaEquipo, 8));

        var filaResumen = Retro.FilaConInterruptor("Resumen semanal",
            "Una notificación sin sonido cada 7 días: cuántas apps hay a revisar y cuántos avisos tiene el equipo. Sin nombres de apps.",
            ConfiguracionDeVigilancia.ResumenActivado(contexto), activado =>
            {
                if (activado)
                {
                    MainActivity.Actual?.PedirPermisoDeNotificaciones();
                    ConfiguracionDeVigilancia.ActivarResumen(contexto);
                    _ = Task.Run(() =>
                    {
                        try { EjecutorDelEquipo.Ejecutar(contexto, "activacion-resumen", reiniciarResumen: true); }
                        catch (Exception ex) { Android.Util.Log.Error("NEXO", "EQUIPO-REVISION fallo al activar el resumen: " + ex); }
                        finally { Dispatcher.UIThread.Post(Mostrar); }
                    });
                }
                else ConfiguracionDeVigilancia.DesactivarResumen(contexto);
                Mostrar();
            }, out _);
        raiz.Children.Add(Retro.Hundido(filaResumen, 8));
        raiz.Children.Add(_estadoGeneral);

        _bateria = Retro.BotonGrande("Abrir ajustes de ahorro de batería", () =>
        {
            var i = new Intent(Android.Provider.Settings.ActionIgnoreBatteryOptimizationSettings);
            i.AddFlags(ActivityFlags.NewTask);
            contexto.StartActivity(i);
        });
        _bateria.IsVisible = false;
        raiz.Children.Add(_bateria);

        Content = new ScrollViewer { Content = raiz };
        Mostrar();
        // Al volver de otra pantalla o del dialogo del permiso, el texto se actualiza (antes seguia diciendo «falta el permiso» aunque ya estuviera concedido).
        Action alReanudar = () => Dispatcher.UIThread.Post(Mostrar);
        AttachedToVisualTree += (_, _) => { MainActivity.Reanudada += alReanudar; Mostrar(); };
        DetachedFromVisualTree += (_, _) => MainActivity.Reanudada -= alReanudar;
    }

    private void Mostrar()
    {
        MostrarGeneral();
        MostrarApps();
    }

    /// <summary>Estado de las notificaciones generales: cuando se reviso el equipo, cuando toca el proximo resumen y si falta el permiso.</summary>
    private void MostrarGeneral()
    {
        var contexto = Android.App.Application.Context;
        bool equipo = ConfiguracionDeVigilancia.EquipoActivado(contexto), resumen = ConfiguracionDeVigilancia.ResumenActivado(contexto);
        if (!equipo && !resumen) { _estadoGeneral.Text = ""; _estadoGeneral.IsVisible = false; return; }
        var estado = EstadoDelEquipo.Cargar(RutasDeNexo.Equipo(contexto), out _);
        var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var lineas = new List<string>();
        if (equipo) lineas.Add("Equipo: " + Retro.HaceCuanto(estado.UltimaRevisionMs, ahora).ToLowerInvariant());
        if (resumen && estado.UltimoResumenMs is { } ultimo)
        {
            var proximo = DateTimeOffset.FromUnixTimeMilliseconds(ultimo + (long)VigilanteDelEquipo.Semana.TotalMilliseconds).ToLocalTime();
            lineas.Add("Próximo resumen: desde el " + proximo.ToString("dd-MM-yyyy") + " (cuando corra la revisión periódica).");
        }
        // Si «avisar al instalar» esta encendido, esa seccion ya muestra la falta del permiso: no se repite.
        if (!Notificador.PuedeNotificar(contexto) && !ConfiguracionDeVigilancia.Activada(contexto)) lineas.Add("⚠ Falta el permiso de notificaciones: no se podrá mostrar ningún aviso.");
        _estadoGeneral.Text = string.Join("\n", lineas);
        _estadoGeneral.IsVisible = true;
    }

    private void MostrarApps()
    {
        var contexto = Android.App.Application.Context;
        if (!ConfiguracionDeVigilancia.Activada(contexto)) { _estado.Text = "Apagado: Nexo solo revisa cuando abres «Apps»."; _bateria.IsVisible = false; return; }
        var estado = EstadoDeVigilancia.Cargar(RutasDeNexo.Vigilancia(contexto), out _);
        var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var lineas = new List<string> { Retro.HaceCuanto(estado.UltimaRevisionMs, ahora) };
        bool atrasada = VigilanteDeInstalaciones.EstaAtrasada(estado.UltimaRevisionMs, ConfiguracionDeVigilancia.ActivadaDesdeMs(contexto), ahora, TimeSpan.FromHours(24));
        if (atrasada) lineas.Add("⚠ Hace más de 24 h que no se revisa: el sistema o el fabricante puede estar deteniendo a Nexo en segundo plano. Excluye a Nexo del ahorro de batería.");
        if (!Notificador.PuedeNotificar(contexto)) lineas.Add("⚠ Falta el permiso de notificaciones: no se podrá mostrar ningún aviso.");
        _estado.Text = string.Join("\n", lineas);
        _bateria.IsVisible = atrasada;
    }
}
