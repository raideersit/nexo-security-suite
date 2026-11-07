using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Nexo.Ui.Desktop;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static DialogoEnEspanol.VentanaDeDialogo? DialogoAbierto(Window duenio)
        {
            Dispatcher.UIThread.RunJobs();
            return duenio.OwnedWindows.OfType<DialogoEnEspanol.VentanaDeDialogo>().FirstOrDefault();
        }

        private static void Pulsar(Button b) { b.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Dispatcher.UIThread.RunJobs(); }

        private static void ProbarDialogos(string? captura)
        {
            Console.WriteLine("Cuadros de diálogo en español");
            var duenio = new Window { Width = 520, Height = 360, Title = "dueño de prueba" };
            duenio.Show();
            try
            {
                // ---- pregunta
                Task<bool> t = DialogoEnEspanol.PreguntarAsync(duenio, "¿Eliminar la entrada «tienda»?\n\nNo se puede deshacer.", "Eliminar entrada");
                DialogoEnEspanol.VentanaDeDialogo? d = DialogoAbierto(duenio);
                Check(d is not null && !t.IsCompleted, "la pregunta se abre como diálogo del dueño y espera una respuesta");
                if (d is null) return;
                Check(d.Title == "Eliminar entrada" && d.Texto.Text!.Contains("No se puede deshacer"), "lleva el título y el texto pedidos");
                Check(d.BotonSi?.Content as string == "Sí" && d.BotonNo?.Content as string == "No" && d.BotonAceptar is null, "los botones dicen «Sí» y «No» (no «Yes»)");
                Check(d.BotonNo!.IsDefault && !d.BotonSi!.IsDefault, "el botón por omisión es «No»: Enter no confirma una acción destructiva");
                string[] ingles = { "Yes", "Ok", "OK", "Cancel", "Abort", "Retry" };
                // Los botones del marco de la ventana (minimizar, maximizar, cerrar) no tienen texto: solo cuentan los de Nexo.
                var contenidos = d.GetVisualDescendants().OfType<Button>().Select(b => b.Content as string ?? "").Where(c => c.Length > 0).ToList();
                Check(!contenidos.Any(c => ingles.Contains(c)) && contenidos.Count == 2, "ningún botón está en inglés", string.Join(",", contenidos));
                if (captura is not null) { d.UpdateLayout(); Dispatcher.UIThread.RunJobs(); AvaloniaHeadlessPlatform.ForceRenderTimerTick(); d.CaptureRenderedFrame()?.Save(Path.ChangeExtension(captura, null) + "-dialogo.png"); }
                Pulsar(d.BotonSi);
                Check(t.IsCompleted && t.Result, "«Sí» devuelve verdadero y cierra");

                // «No»
                Task<bool> t2 = DialogoEnEspanol.PreguntarAsync(duenio, "¿Seguro?", "Pregunta");
                DialogoEnEspanol.VentanaDeDialogo d2 = DialogoAbierto(duenio)!;
                Pulsar(d2.BotonNo!);
                Check(t2.IsCompleted && !t2.Result, "«No» devuelve falso");

                // cerrar con la «X»
                Task<bool> t3 = DialogoEnEspanol.PreguntarAsync(duenio, "¿Seguro?", "Pregunta");
                DialogoEnEspanol.VentanaDeDialogo d3 = DialogoAbierto(duenio)!;
                d3.Close();
                Dispatcher.UIThread.RunJobs();
                Check(t3.IsCompleted && !t3.Result, "cerrar el diálogo con la «X» equivale a «No» (no confirma nada)");

                // Esc
                Task<bool> t4 = DialogoEnEspanol.PreguntarAsync(duenio, "¿Seguro?", "Pregunta");
                DialogoEnEspanol.VentanaDeDialogo d4 = DialogoAbierto(duenio)!;
                d4.RaiseEvent(new KeyEventArgs { RoutedEvent = InputElement.KeyDownEvent, Key = Key.Escape });
                Dispatcher.UIThread.RunJobs();
                Check(t4.IsCompleted && !t4.Result, "Esc equivale a «No»");

                // ---- aviso
                Task t5 = DialogoEnEspanol.InformarAsync(duenio, "Todo listo.", "Resultado");
                DialogoEnEspanol.VentanaDeDialogo d5 = DialogoAbierto(duenio)!;
                Check(d5.BotonAceptar?.Content as string == "Aceptar" && d5.BotonSi is null && d5.BotonNo is null, "un aviso tiene un solo botón, «Aceptar» (no «Ok»)");
                Pulsar(d5.BotonAceptar!);
                Check(t5.IsCompleted, "«Aceptar» cierra el aviso");

                // un texto muy largo se parte en lineas y el cuadro no se ensancha sin limite
                string largo = string.Join(" ", Enumerable.Repeat("palabra", 400));
                Task t6 = DialogoEnEspanol.InformarAsync(duenio, largo, "Largo", IconoDeDialogo.Advertencia);
                DialogoEnEspanol.VentanaDeDialogo d6 = DialogoAbierto(duenio)!;
                d6.UpdateLayout(); Dispatcher.UIThread.RunJobs();
                Check(d6.Bounds.Width > 0 && d6.Bounds.Width <= 640, "un texto larguísimo no ensancha el cuadro más allá del máximo", d6.Bounds.Width.ToString());
                Pulsar(d6.BotonAceptar!);

                // ---- guarda: la ventana ya no usa el cuadro en inglés de la libreria del tema
                string? fuente = BuscarArchivoHaciaArriba(Path.Combine("src", "Nexo.Ui.Desktop", "MainWindow.axaml.cs"));
                Check(fuente is not null && !File.ReadAllText(fuente).Contains("MessageBox"), "MainWindow ya no usa MessageBox (botones en inglés): toda confirmación pasa por DialogoEnEspanol", fuente ?? "no se encontró el archivo");
            }
            finally
            {
                duenio.Close();
            }
        }

        private static string? BuscarArchivoHaciaArriba(string relativo)
        {
            string? dir = AppContext.BaseDirectory;
            for (int i = 0; i < 10 && dir is not null; i++, dir = Path.GetDirectoryName(dir))
            {
                string candidato = Path.Combine(dir, relativo);
                if (File.Exists(candidato)) return candidato;
            }
            return null;
        }
    }
}
