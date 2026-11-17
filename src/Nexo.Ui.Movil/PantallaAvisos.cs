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
        AttachedToVisualTree += (_, _) => Mostrar();
    }

    private void Mostrar()
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
