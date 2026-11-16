using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Nexo.Ui.Movil;

/// <summary>Mediciones de la fase 0 (se quitara antes de la v1).</summary>
public sealed partial class PantallaPruebas : UserControl
{
    public PantallaPruebas()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("MedirArgon")!.Click += async (_, _) => await MedirArgonAsync();
        this.FindControl<Button>("Verificar")!.Click += async (_, _) =>
        {
            var salida = this.FindControl<TextBlock>("ResultadoSondas")!;
            salida.Text = "Verificando...";
            var lineas = await System.Threading.Tasks.Task.Run(() => Estado.SondasDeApi.Ejecutar(Android.App.Application.Context));
            foreach (var l in lineas) Android.Util.Log.Info("NEXO", "SONDA " + l);
            salida.Text = string.Join("\n\n", lineas);
        };
    }

    /// <summary>Mide Argon2id con los perfiles de la boveda (Nexo.Modules.Identity.ParametrosDeClave): el normal y el minimo de OWASP.</summary>
    private async System.Threading.Tasks.Task MedirArgonAsync()
    {
        var salida = this.FindControl<TextBlock>("ResultadoArgon")!;
        var boton = this.FindControl<Button>("MedirArgon")!;
        boton.IsEnabled = false;
        salida.Text = "Midiendo...";
        var texto = await System.Threading.Tasks.Task.Run(() =>
        {
            var sb = new System.Text.StringBuilder();
            foreach (var (nombre, memoria, iter, hilos) in new[] { ("Normal 64 MiB t=3 p=2", 64 * 1024, 3, 2), ("Minimo 19 MiB t=2 p=1", 19 * 1024, 2, 1) })
            {
                try
                {
                    var tiempos = new System.Collections.Generic.List<long>();
                    for (int i = 0; i < 3; i++)
                    {
                        var sw = Stopwatch.StartNew();
                        using var a = new Konscious.Security.Cryptography.Argon2id(System.Text.Encoding.UTF8.GetBytes("contrasena de prueba"))
                        { Salt = new byte[16], DegreeOfParallelism = hilos, Iterations = iter, MemorySize = memoria };
                        a.GetBytes(32);
                        tiempos.Add(sw.ElapsedMilliseconds);
                    }
                    sb.AppendLine($"{nombre}: {string.Join(" / ", tiempos)} ms");
                }
                catch (System.Exception ex) { sb.AppendLine($"{nombre}: fallo {ex.GetType().Name}: {ex.Message}"); }
            }
            return sb.ToString();
        });
        Android.Util.Log.Info("NEXO", "ARGON2 " + texto.Replace("\n", " | "));
        salida.Text = texto;
        boton.IsEnabled = true;
    }
}
