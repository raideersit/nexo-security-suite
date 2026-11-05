using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Headless;
using Avalonia.Threading;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static class Program
    {
        private static int _fallos;

        public static int Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            int i = Array.IndexOf(args, "--captura");
            string? captura = i >= 0 && i + 1 < args.Length ? args[i + 1] : null;

            // Avalonia sin pantalla, pero dibujando de verdad con Skia (para poder capturar la ventana).
            AppBuilder.Configure<App>()
                .UseSkia()
                .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
                .SetupWithoutStarting();

            ProbarResumen();
            ProbarModeloDeLaVentana();
            ProbarFuentePorDefecto();
            ProbarVentana(captura);

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static InstantaneaDelServicio Conectada(bool tr = true, bool cobertura = true, bool motorCaido = false,
                                                         string[]? porRevisar = null, params DeteccionVista[] det)
            => new InstantaneaDelServicio(true, "1.0", tr, cobertura, motorCaido, 0, 0, det, null, null, porRevisar);

        private static ResumenDeEstado Resumen(InstantaneaDelServicio i)
        {
            var m = new ModeloDeBandeja();
            m.Actualizar(i);
            return Resumir.Desde(m);
        }

        private static FilaDeModulo Fila(ResumenDeEstado r, string modulo) => r.Modulos.Single(f => f.Modulo == modulo);

        /// <summary>Espera una tarea dejando correr el despachador de Avalonia (las continuaciones vuelven a este hilo).</summary>
        private static void Esperar(Task t)
        {
            while (!t.IsCompleted) Dispatcher.UIThread.RunJobs();
            t.GetAwaiter().GetResult();
        }

        // ============================================================
        private static void ProbarResumen()
        {
            Console.WriteLine("== Resumen de estado (sin pantalla)");

            ResumenDeEstado r = Resumen(InstantaneaDelServicio.SinConexion("el servicio no esta en marcha"));
            Check(r.Estado == EstadoDeBandeja.Desconectado && r.Indicador == Indicador.SinDatos, "sin conexion: estado desconectado, indicador gris");
            Check(r.Detalle.Contains("el servicio no esta en marcha"), "sin conexion: el detalle dice el motivo", r.Detalle);
            Check(r.Modulos.All(f => f.Indicador == Indicador.SinDatos), "sin conexion: ningun modulo aparece con color");
            Check(r.BarraServicio == "Servicio: sin conexión" && r.BarraTiempoReal.EndsWith("sin datos") && r.BarraMotor.EndsWith("sin datos"),
                "sin conexion: la barra de estado no afirma nada");

            r = Resumen(Conectada(tr: false));
            Check(r.Estado == EstadoDeBandeja.Atencion && r.Indicador == Indicador.Atencion, "tiempo real apagado: atencion (amarillo)");
            Check(r.Titulo.Contains("apagado") && r.Detalle.Contains("Defender"), "tiempo real apagado: lo dice y recuerda a Defender", r.Titulo);
            Check(Fila(r, "Tiempo real").Estado == "Apagado" && Fila(r, "Tiempo real").Indicador == Indicador.Atencion, "tiempo real apagado: la fila lo dice");
            Check(r.BarraMotor == "Motor clamd: sin datos", "tiempo real apagado: no se afirma que el motor este listo", r.BarraMotor);

            r = Resumen(Conectada());
            Check(r.Estado == EstadoDeBandeja.Normal && r.Indicador == Indicador.Correcto, "todo bien en tiempo real: correcto (verde)");
            Check(!r.Titulo.Contains("todo en orden", StringComparison.OrdinalIgnoreCase), "todo bien: el titulo solo habla del tiempo real", r.Titulo);
            Check(r.Modulos.Count == 6, "hay 6 filas de modulos", r.Modulos.Count.ToString());
            Check(r.Modulos.Where(f => f.Modulo != "Tiempo real").All(f => f.Indicador == Indicador.SinDatos && f.Estado == "Sin consultar"),
                "los modulos que la ventana no consulta figuran «sin consultar», nunca correctos");
            Check(r.BarraServicio == "Servicio: conectado (versión 1.0)" && r.BarraMotor == "Motor clamd: listo", "todo bien: barra con version y motor listo", r.BarraServicio);

            r = Resumen(Conectada(motorCaido: true));
            Check(r.Estado == EstadoDeBandeja.Atencion && r.Titulo.Contains("motor"), "motor caido: atencion y lo dice", r.Titulo);
            Check(r.BarraMotor == "Motor clamd: no responde", "motor caido: la barra lo dice");

            r = Resumen(Conectada(cobertura: false, porRevisar: new[] { @"C:\a", @"C:\b" }));
            Check(r.Titulo.Contains("cobertura incompleta") && r.Detalle.Contains("2 carpetas"), "cobertura incompleta: cuenta las carpetas", r.Detalle);
            r = Resumen(Conectada(cobertura: false));
            Check(r.Titulo.Contains("cobertura incompleta") && !r.Detalle.Contains("carpeta"), "cobertura incompleta sin carpetas: no inventa una cifra", r.Detalle);

            var d = new DeteccionVista(@"C:\Users\u\Downloads\x.exe", "Win.Test.EICAR_HDB-1", 68, "abc");
            var m = new ModeloDeBandeja();
            m.Actualizar(Conectada(det: d));
            r = Resumir.Desde(m);
            Check(r.Estado == EstadoDeBandeja.Alerta && r.Indicador == Indicador.Alerta && r.Titulo == "Hay 1 detección sin revisar.", "una deteccion: alerta (rojo), en singular", r.Titulo);
            Check(Fila(r, "Tiempo real").Detalle.Contains("EICAR"), "una deteccion: la fila nombra la firma");
            m.MarcarRevisadas();
            r = Resumir.Desde(m);
            Check(r.Estado == EstadoDeBandeja.Atencion && r.Titulo.Contains("sin resolver"), "revisada pero sin resolver: atencion, no «todo bien»", r.Titulo);
        }

        // ============================================================
        private sealed class FuenteFija : IFuenteDeEstado
        {
            public InstantaneaDelServicio Valor = InstantaneaDelServicio.SinConexion("sin valor");
            public int Llamadas;
            public Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct) { Llamadas++; return Task.FromResult(Valor); }
        }

        private sealed class FuenteQueFalla : IFuenteDeEstado
        {
            public Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct) => throw new InvalidCastException("roto");
        }

        private sealed class FuenteLenta : IFuenteDeEstado
        {
            public readonly TaskCompletionSource<InstantaneaDelServicio> Pendiente = new TaskCompletionSource<InstantaneaDelServicio>();
            public int Llamadas;
            public Task<InstantaneaDelServicio> ConsultarAsync(CancellationToken ct) { Llamadas++; return Pendiente.Task; }
        }

        private static void ProbarModeloDeLaVentana()
        {
            Console.WriteLine("== Modelo de la ventana (fuentes falsas)");

            var fija = new FuenteFija { Valor = Conectada(tr: false) };
            var vm = new VentanaPrincipalModelo(fija, () => new DateTime(2026, 11, 5, 9, 12, 30));
            Check(vm.Titulo.StartsWith("Consultando"), "antes de consultar no muestra ningun estado", vm.Titulo);
            int avisos = 0;
            vm.PropertyChanged += (_, _) => avisos++;
            Esperar(vm.ActualizarAsync());
            Check(vm.Titulo.Contains("apagado") && avisos > 0, "tras consultar muestra el estado y avisa a la ventana", vm.Titulo);
            Check(vm.BarraConsulta == "Última consulta: 09:12:30", "la hora de la ultima consulta sale del reloj", vm.BarraConsulta);
            Check(vm.Modulos.Count == 6, "la ventana recibe las 6 filas");

            fija.Valor = InstantaneaDelServicio.SinConexion("el servicio no esta en marcha");
            Esperar(vm.ActualizarAsync());
            Check(vm.Resumen!.Estado == EstadoDeBandeja.Desconectado && vm.BarraServicio == "Servicio: sin conexión",
                "si el servicio se cae, la ventana pasa a «sin conexion»");

            var rota = new VentanaPrincipalModelo(new FuenteQueFalla());
            Esperar(rota.ActualizarAsync());
            Check(rota.Resumen!.Estado == EstadoDeBandeja.Desconectado && rota.Detalle.Contains("InvalidCastException"),
                "una excepcion de la fuente no tumba la ventana: se muestra como sin conexion con el motivo", rota.Detalle);

            var lenta = new FuenteLenta();
            var vl = new VentanaPrincipalModelo(lenta);
            Task primera = vl.ActualizarAsync();
            Task segunda = vl.ActualizarAsync();
            Check(segunda.IsCompleted && lenta.Llamadas == 1, "con una consulta en curso no se lanza otra", lenta.Llamadas.ToString());
            lenta.Pendiente.SetResult(Conectada());
            Esperar(primera);
            Check(vl.Resumen!.Estado == EstadoDeBandeja.Normal, "la consulta lenta termina y se aplica");
            Esperar(vl.ActualizarAsync());
            Check(lenta.Llamadas == 2, "terminada la anterior, se puede volver a consultar");
        }

        private static void ProbarFuentePorDefecto()
        {
            Console.WriteLine("== Fuente por defecto en esta compilacion (net8.0)");
            InstantaneaDelServicio i = Fuentes.PorDefecto("NexoIpc").ConsultarAsync(CancellationToken.None).GetAwaiter().GetResult();
            Check(!i.Conectado, "sin el pipe de Windows la fuente dice «sin conexion»");
            Check(i.Error is not null && (OperatingSystem.IsWindows() ? i.Error.Contains("Windows") : i.Error.Contains("Linux")),
                "y explica por que", i.Error);
        }

        // ============================================================
        private static void ProbarVentana(string? captura)
        {
            Console.WriteLine("== La ventana de verdad, sin pantalla");

            var fija = new FuenteFija { Valor = Conectada(tr: false) };
            var vm = new VentanaPrincipalModelo(fija, () => new DateTime(2026, 11, 5, 9, 12, 30));
            MainWindow? w = null;
            try
            {
                w = new MainWindow(vm);
                Check(true, "el XAML de la ventana carga (tema Classic incluido)");
                w.Show();
                Dispatcher.UIThread.RunJobs();
                Check(fija.Llamadas == 1, "al abrirse consulta al servicio una vez", fija.Llamadas.ToString());
                Check(w.TituloDeEstado.Text == vm.Titulo && vm.Titulo.Contains("apagado"), "el titulo enlazado muestra el estado", w.TituloDeEstado.Text);
                Check(w.ListaDeModulos.ItemCount == 6, "la tabla de modulos tiene 6 filas", w.ListaDeModulos.ItemCount.ToString());
                Check(w.Pestanas.ItemCount == 7 && w.Pestanas.SelectedIndex == 0, "7 pestañas y se abre en «Estado»");
                Check(new[] { w.BotonEscanear, w.BotonLimpiar, w.BotonFirewall, w.BotonCuarentena, w.BotonActualizar }
                        .All(b => b.LargeIcon?.PixelSize.Width == 24 && b.SmallIcon?.PixelSize.Width == 16),
                    "los 5 botones de la barra tienen icono grande (24) y pequeño (16)");

                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    var imagen = w.CaptureRenderedFrame();
                    Check(imagen is not null && imagen.PixelSize.Width > 0, "se pudo capturar la ventana");
                    imagen?.Save(captura);
                    Console.WriteLine("           captura: " + captura);
                }
            }
            catch (Exception ex)
            {
                Check(false, "la ventana se crea y se muestra sin errores", ex.ToString());
            }
            finally
            {
                w?.Close();
            }
        }
    }
}
