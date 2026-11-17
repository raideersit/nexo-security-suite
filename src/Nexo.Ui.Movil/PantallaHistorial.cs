using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;
using Nexo.Ui.Movil.Vigilancia;

namespace Nexo.Ui.Movil;

/// <summary>Historial opcional en Obsidian (§3.9): apagado por omision, con su interruptor y el boton para guardar el chequeo.</summary>
public sealed class PantallaHistorial : UserControl
{
    private readonly TextBlock _estado = Retro.Texto("", Retro.Secundario, false, Retro.Gris);
    private readonly Button _guardar;

    public PantallaHistorial()
    {
        var contexto = Android.App.Application.Context;
        var raiz = new StackPanel { Margin = new Avalonia.Thickness(12), Spacing = 12 };
        Control fila = null!;
        Retro.InterruptorRetro interruptor = null!;
        bool reponiendo = false;
        fila = Retro.FilaConInterruptor("Guardar un historial en Obsidian", "Carpeta Documents/Nexo", HistorialDeObsidian.Activado(contexto), activado =>
        {
            if (reponiendo) return;
            try
            {
                if (activado) HistorialDeObsidian.Activar(contexto); else HistorialDeObsidian.Desactivar(contexto);
                Refrescar();
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                HistorialDeObsidian.Desactivar(contexto);
                reponiendo = true; interruptor.Activado = false; reponiendo = false;
                _estado.Text = "No se pudo escribir en " + HistorialDeObsidian.Carpeta() + ": " + ex.Message;
            }
        }, out interruptor);
        raiz.Children.Add(Retro.Hundido(fila, 8));
        raiz.Children.Add(_estado);

        _guardar = Retro.BotonGrande("Guardar el chequeo del equipo ahora", async () =>
        {
            var lista = EquipoAhora.Evaluar(EquipoAhora.Leer());
            try
            {
                await Task.Run(() => HistorialDeObsidian.Escribir(new[] { EventosDeApps.DelChequeo(lista) }));
                _estado.Text = "Chequeo guardado en " + HistorialDeObsidian.Carpeta() + ".";
            }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException)
            { _estado.Text = "No se pudo guardar el chequeo: " + ex.Message; }
        });
        raiz.Children.Add(_guardar);
        Content = new ScrollViewer { Content = raiz };
        Refrescar();
    }

    private void Refrescar()
    {
        bool on = HistorialDeObsidian.Activado(Android.App.Application.Context);
        _guardar.IsVisible = on;
        _estado.Text = on ? "Activado. Las notas van a " + HistorialDeObsidian.Carpeta() + ". Solo se guardan las apps que salen «a revisar», nunca la lista completa."
                          : "Apagado. Si usas Obsidian, actívalo para guardar ahí los avisos y el chequeo.";
    }
}
