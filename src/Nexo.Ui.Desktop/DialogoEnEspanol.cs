using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Classic.Avalonia.Theme;

namespace Nexo.Ui.Desktop
{
    public enum IconoDeDialogo
    {
        Informacion,
        Advertencia,
        Pregunta
    }

    /// <summary>
    /// Cuadros de dialogo propios, EN ESPANOL. El de la libreria del tema (<c>MessageBox</c>) tiene los botones fijos en ingles («Yes», «No», «Ok») y
    /// no permite cambiarlos; para quien solo usa español eso esta mal en una confirmacion que puede borrar o bloquear algo.
    ///
    /// Decision de seguridad: en las PREGUNTAS el boton por omision es «No» (pulsar Enter no confirma una accion destructiva), y cerrar la ventana
    /// o pulsar Esc equivale a «No».
    /// </summary>
    public static class DialogoEnEspanol
    {
        /// <summary>true = el usuario eligio «Sí». Cerrar o Esc = false.</summary>
        public static async Task<bool> PreguntarAsync(Window duenio, string texto, string titulo, IconoDeDialogo icono = IconoDeDialogo.Advertencia)
        {
            var v = new VentanaDeDialogo(texto, titulo, icono, pregunta: true);
            return await v.ShowDialog<bool>(duenio);
        }

        public static async Task InformarAsync(Window duenio, string texto, string titulo, IconoDeDialogo icono = IconoDeDialogo.Informacion)
        {
            var v = new VentanaDeDialogo(texto, titulo, icono, pregunta: false);
            await v.ShowDialog<bool>(duenio);
        }

        /// <summary>La ventana en si. Los botones tienen nombre para poder probarlos sin pantalla.</summary>
        internal sealed class VentanaDeDialogo : ClassicWindow
        {
            public Button? BotonSi { get; }
            public Button? BotonNo { get; }
            public Button? BotonAceptar { get; }
            public TextBlock Texto { get; }

            public VentanaDeDialogo(string texto, string titulo, IconoDeDialogo icono, bool pregunta)
            {
                Title = titulo;
                SizeToContent = SizeToContent.WidthAndHeight;
                MinWidth = 360;
                MaxWidth = 620;
                CanResize = false;
                ShowInTaskbar = false;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;

                Texto = new TextBlock { Text = texto, TextWrapping = TextWrapping.Wrap, MaxWidth = 480, VerticalAlignment = VerticalAlignment.Center };

                var marca = new Border
                {
                    Width = 34, Height = 34, Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Top,
                    BorderBrush = Brushes.Black, BorderThickness = new Thickness(1),
                    CornerRadius = icono == IconoDeDialogo.Advertencia ? new CornerRadius(0) : new CornerRadius(17),
                    Background = icono switch
                    {
                        IconoDeDialogo.Advertencia => new SolidColorBrush(Color.Parse("#FFFF00")),
                        IconoDeDialogo.Pregunta => new SolidColorBrush(Color.Parse("#FFFFFF")),
                        _ => new SolidColorBrush(Color.Parse("#0000FF"))
                    },
                    Child = new TextBlock
                    {
                        Text = icono switch { IconoDeDialogo.Advertencia => "!", IconoDeDialogo.Pregunta => "?", _ => "i" },
                        FontWeight = FontWeight.Bold, FontSize = 20,
                        Foreground = icono == IconoDeDialogo.Informacion ? Brushes.White : Brushes.Black,
                        HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
                    }
                };

                var botones = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 18, 0, 0) };
                if (pregunta)
                {
                    BotonSi = new Button { Name = "BotonSi", Content = "Sí", MinWidth = 84, HorizontalContentAlignment = HorizontalAlignment.Center };
                    BotonNo = new Button { Name = "BotonNo", Content = "No", MinWidth = 84, IsDefault = true, IsCancel = true, HorizontalContentAlignment = HorizontalAlignment.Center };
                    BotonSi.Click += (_, _) => Close(true);
                    BotonNo.Click += (_, _) => Close(false);
                    botones.Children.Add(BotonSi);
                    botones.Children.Add(BotonNo);
                }
                else
                {
                    BotonAceptar = new Button { Name = "BotonAceptar", Content = "Aceptar", MinWidth = 84, IsDefault = true, IsCancel = true, HorizontalContentAlignment = HorizontalAlignment.Center };
                    BotonAceptar.Click += (_, _) => Close(true);
                    botones.Children.Add(BotonAceptar);
                }

                var fila = new DockPanel();
                DockPanel.SetDock(marca, Dock.Left);
                fila.Children.Add(marca);
                fila.Children.Add(Texto);

                Content = new StackPanel { Margin = new Thickness(18), Children = { fila, botones } };

                // Esc = «No» (o cerrar, en un aviso). No depende de la libreria: se maneja aqui.
                KeyDown += (_, e) =>
                {
                    if (e.Key != Key.Escape) return;
                    e.Handled = true;
                    Close(false);
                };
                Opened += (_, _) => (BotonNo ?? BotonAceptar)?.Focus();
            }

            // Cerrar con la «X» devuelve false (no confirma nada): Window.ShowDialog<bool> ya devuelve default(bool) = false.
        }
    }
}
