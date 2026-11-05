using System;
using System.Linq;
using System.Text;
using System.Text.Json;
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
        private static readonly DateTimeOffset Ayer = new DateTimeOffset(2026, 11, 4, 21, 5, 0, TimeSpan.Zero);

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

            ProbarLector();
            ProbarResumen();
            ProbarResumenDeModulos();
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

        // ============================================================ datos de prueba
        private static InstantaneaDelServicio Conectada(bool tr = true, bool cobertura = true, bool motorCaido = false,
                                                         string[]? porRevisar = null, params DeteccionVista[] det)
            => new InstantaneaDelServicio(true, "1.0", tr, cobertura, motorCaido, 0, 0, det, null, null, porRevisar);

        private static EstadoDeEscaneoProgramado ProgramadoAlDia
            => new EstadoDeEscaneoProgramado(true, "limpio", Ayer, null, false, false, 0, null);

        private static EstadoCompleto Completo(InstantaneaDelServicio s,
            EstadoDelMotor? motor = null, EstadoDeEscaneoProgramado? programado = null,
            EstadoDeFirewall? firewall = null, EstadoDeCuarentena? cuarentena = null)
            => new EstadoCompleto(s,
                Consulta<EstadoDelMotor>.Bien(motor ?? new EstadoDelMotor(true, "clamd", "ClamAV 1.5.4")),
                Consulta<EstadoDeEscaneoProgramado>.Bien(programado ?? ProgramadoAlDia),
                Consulta<EstadoDeFirewall>.Bien(firewall ?? new EstadoDeFirewall(3, true, new[]
                {
                    new PerfilDeFirewall("Dominio", true), new PerfilDeFirewall("Privado", true), new PerfilDeFirewall("Publico", true)
                })),
                Consulta<EstadoDeCuarentena>.Bien(cuarentena ?? new EstadoDeCuarentena(0, null)));

        private static ResumenDeEstado Resumen(EstadoCompleto e)
        {
            var m = new ModeloDeBandeja();
            m.Actualizar(e.Servicio);
            return Resumir.Desde(m, e);
        }

        private static ResumenDeEstado Resumen(InstantaneaDelServicio s) => Resumen(s.Conectado ? Completo(s) : EstadoCompleto.SinConexion(s));

        private static FilaDeModulo Fila(ResumenDeEstado r, string modulo) => r.Modulos.Single(f => f.Modulo == modulo);

        private static RespuestaCruda Json(string json) => new RespuestaCruda(true, null, JsonDocument.Parse(json).RootElement.Clone());

        /// <summary>Espera una tarea dejando correr el despachador de Avalonia (las continuaciones vuelven a este hilo).</summary>
        private static void Esperar(Task t)
        {
            while (!t.IsCompleted) Dispatcher.UIThread.RunJobs();
            t.GetAwaiter().GetResult();
        }

        // ============================================================
        private static void ProbarLector()
        {
            Console.WriteLine("== Lector de respuestas del servicio (con la forma que da cada metodo)");

            var m = LectorDeModulos.Motor(Json("{\"motor_disponible\":true,\"motor\":\"clamd\",\"version\":\"ClamAV 1.5.4/27800\"}"));
            Check(m.Valor is { Disponible: true, Version: "ClamAV 1.5.4/27800" } && m.Error is null, "escaneo.estado con motor disponible");
            m = LectorDeModulos.Motor(Json("{\"motor_disponible\":false,\"motor\":\"clamd\"}"));
            Check(m.Valor is { Disponible: false, Version: null }, "escaneo.estado sin motor (sin version, que el servicio omite)");
            m = LectorDeModulos.Motor(new RespuestaCruda(false, "metodo desconocido", null));
            Check(m.Valor is null && m.Error!.Contains("metodo desconocido"), "un error del servicio queda como error, con su mensaje", m.Error);
            m = LectorDeModulos.Motor(new RespuestaCruda(true, null, null));
            Check(m.Valor is null && m.Error is not null, "una respuesta vacia no se interpreta");

            var f = LectorDeModulos.Firewall(Json(
                "{\"reglas_de_nexo\":[{\"nombre\":\"Nexo: a\",\"accion\":\"Bloquear\",\"direccion\":\"Salida\",\"ruta\":\"C:\\\\a.exe\",\"habilitada\":true}," +
                "{\"nombre\":\"Nexo: b\",\"accion\":\"Bloquear\",\"direccion\":\"Entrada\",\"ruta\":\"C:\\\\b.exe\",\"habilitada\":true}]," +
                "\"sigiloso\":true,\"perfiles\":[{\"perfil\":\"Dominio\",\"activo\":true,\"entrada_por_defecto\":\"Bloquear\"}," +
                "{\"perfil\":\"Privado\",\"activo\":true,\"entrada_por_defecto\":\"Bloquear\"},{\"perfil\":\"Publico\",\"activo\":false,\"entrada_por_defecto\":\"Bloquear\"}]}"));
            Check(f.Valor is { ReglasDeNexo: 2, Sigiloso: true } && f.Valor.Perfiles.Count == 3 && !f.Valor.Perfiles[2].Activo,
                "firewall.estado: reglas, sigiloso y perfiles");
            f = LectorDeModulos.Firewall(Json("{\"reglas_de_nexo\":[],\"perfiles\":[]}"));
            Check(f.Valor is null && f.Error!.Contains("no reconocida"), "firewall.estado sin «sigiloso»: no se interpreta a medias", f.Error);

            var p = LectorDeModulos.Programado(Json("{\"activo\":false,\"vencido\":true,\"nota\":\"apagado\"}"));
            Check(p.Valor is { Activo: false }, "escaneo-programado.estado con el modulo apagado");
            p = LectorDeModulos.Programado(Json(
                "{\"activo\":true,\"raices\":[\"C:\\\\Users\"],\"intervalo_horas\":24,\"corriendo\":false,\"ultimo_resultado\":\"nunca\",\"vencido\":true,\"analizados\":0,\"omitidos\":0,\"detecciones\":0}"));
            Check(p.Valor is { Activo: true, UltimoResultado: "nunca", UltimoCompleto: null, Motivo: null, Vencido: true },
                "escaneo-programado.estado sin fechas (el servicio omite los nulos)");
            p = LectorDeModulos.Programado(Json("{\"activo\":true,\"ultimo_resultado\":\"limpio\",\"ultimo_completo\":\"2026-11-04T21:05:00+00:00\"}"));
            Check(p.Valor is { Vencido: true } && p.Valor.UltimoCompleto == Ayer, "sin «vencido» no se supone al dia; la fecha se lee");

            var q = LectorDeModulos.Cuarentena(Json(
                "{\"elementos\":[{\"id\":\"a\",\"ruta_original\":\"C:\\\\x\",\"bytes\":68,\"firma\":\"EICAR\",\"fecha\":\"2026-11-05T09:00:00+00:00\",\"vence\":\"2026-12-05T09:00:00+00:00\"}," +
                "{\"id\":\"b\",\"ruta_original\":\"C:\\\\y\",\"bytes\":9,\"firma\":\"T\",\"fecha\":\"2026-10-20T09:00:00+00:00\",\"vence\":\"2026-11-19T09:00:00+00:00\"}]}"));
            Check(q.Valor is { Elementos: 2 } && q.Valor.ProximoVencimiento == new DateTimeOffset(2026, 11, 19, 9, 0, 0, TimeSpan.Zero),
                "cuarentena.listar: cuenta y el vencimiento mas proximo");
            q = LectorDeModulos.Cuarentena(Json("{\"elementos\":[{\"id\":\"a\",\"vence\":\"no es fecha\"}]}"));
            Check(q.Valor is null && q.Error is not null, "cuarentena.listar con una fecha rota: error, no una cuenta a medias");
        }

        // ============================================================
        private static void ProbarResumen()
        {
            Console.WriteLine("== Resumen: conexion y tiempo real");

            ResumenDeEstado r = Resumen(InstantaneaDelServicio.SinConexion("el servicio no esta en marcha"));
            Check(r.Estado == EstadoDeBandeja.Desconectado && r.Indicador == Indicador.SinDatos, "sin conexion: estado desconectado, indicador gris");
            Check(r.Detalle.Contains("el servicio no esta en marcha"), "sin conexion: el detalle dice el motivo", r.Detalle);
            Check(r.Modulos.Count == 7 && r.Modulos.All(f => f.Indicador == Indicador.SinDatos && f.Estado == "Sin datos"),
                "sin conexion: las 7 filas sin datos, ninguna con color");
            Check(r.BarraServicio == "Servicio: sin conexión" && r.BarraTiempoReal.EndsWith("sin datos") && r.BarraMotor.EndsWith("sin datos"),
                "sin conexion: la barra de estado no afirma nada");

            r = Resumen(Conectada(tr: false));
            Check(r.Estado == EstadoDeBandeja.Atencion && r.Indicador == Indicador.Atencion, "tiempo real apagado: atencion (amarillo)");
            Check(r.Titulo.Contains("apagado") && r.Detalle.Contains("Defender"), "tiempo real apagado: lo dice y recuerda a Defender", r.Titulo);
            Check(Fila(r, Resumir.TiempoReal).Estado == "Apagado", "tiempo real apagado: la fila lo dice");

            r = Resumen(Conectada());
            Check(r.Indicador == Indicador.Correcto && r.Titulo == "Sin problemas en lo que se pudo consultar.", "todo bien: verde, sin prometer de mas", r.Titulo);
            Check(!r.Titulo.Contains("todo en orden", StringComparison.OrdinalIgnoreCase), "nunca dice «todo en orden»");
            Check(Fila(r, Resumir.Disco).Indicador == Indicador.SinDatos && Fila(r, Resumir.Limpieza).Indicador == Indicador.SinDatos,
                "disco y limpieza no aparecen como correctos (no se consultan)");
            Check(r.BarraServicio == "Servicio: conectado (versión 1.0)" && r.BarraMotor == "Motor clamd: listo", "barra con version y motor listo", r.BarraMotor);

            r = Resumen(Conectada(motorCaido: true));
            Check(r.Indicador == Indicador.Atencion && r.Titulo.Contains("motor"), "motor caido en tiempo real: atencion y lo dice", r.Titulo);

            r = Resumen(Conectada(cobertura: false, porRevisar: new[] { @"C:\a", @"C:\b" }));
            Check(r.Titulo.Contains("cobertura incompleta") && r.Detalle.Contains("2 carpetas"), "cobertura incompleta: cuenta las carpetas", r.Detalle);
            r = Resumen(Conectada(cobertura: false));
            Check(!r.Detalle.Contains("carpeta"), "cobertura incompleta sin carpetas: no inventa una cifra", r.Detalle);

            var d = new DeteccionVista(@"C:\Users\u\Downloads\x.exe", "Win.Test.EICAR_HDB-1", 68, "abc");
            var m = new ModeloDeBandeja();
            EstadoCompleto e = Completo(Conectada(det: d));
            m.Actualizar(e.Servicio);
            r = Resumir.Desde(m, e);
            Check(r.Indicador == Indicador.Alerta && r.Titulo == "Hay 1 detección sin revisar.", "una deteccion: alerta (rojo), en singular", r.Titulo);
            m.MarcarRevisadas();
            r = Resumir.Desde(m, e);
            Check(r.Indicador == Indicador.Atencion && r.Titulo.Contains("sin resolver"), "revisada pero sin resolver: atencion, no «todo bien»", r.Titulo);
        }

        private static void ProbarResumenDeModulos()
        {
            Console.WriteLine("== Resumen: motor, escaneo programado, firewall y cuarentena");

            ResumenDeEstado r = Resumen(Completo(Conectada()));
            Check(Fila(r, Resumir.Motor) is { Indicador: Indicador.Correcto, Estado: "Listo", Detalle: "ClamAV 1.5.4" }, "motor listo, con su version");
            Check(Fila(r, Resumir.Programado) is { Indicador: Indicador.Correcto, Estado: "Al día" }
                  && Fila(r, Resumir.Programado).Detalle.Contains(Resumir.Fecha(Ayer)), "programado al dia, con la fecha del ultimo completo",
                Fila(r, Resumir.Programado).Detalle);
            Check(Fila(r, Resumir.Firewall) is { Indicador: Indicador.Correcto, Detalle: "3 reglas de Nexo · modo sigiloso activado." },
                "firewall activo: reglas y sigiloso", Fila(r, Resumir.Firewall).Detalle);
            Check(Fila(r, Resumir.Cuarentena) is { Estado: "Vacía" }, "cuarentena vacia");

            r = Resumen(Completo(Conectada(), motor: new EstadoDelMotor(false, "clamd", null)));
            Check(r.Indicador == Indicador.Atencion && r.Titulo == "Requiere atención: Motor de análisis: no responde.", "motor sin responder: manda en la cabecera", r.Titulo);
            Check(r.BarraMotor == "Motor clamd: no responde", "y la barra lo dice");

            r = Resumen(Completo(Conectada(), firewall: new EstadoDeFirewall(0, false, new[]
                { new PerfilDeFirewall("Dominio", true), new PerfilDeFirewall("Privado", true), new PerfilDeFirewall("Publico", false) })));
            Check(r.Indicador == Indicador.Atencion && r.Titulo.Contains("Firewall") && Fila(r, Resumir.Firewall).Estado == "Desactivado en parte"
                  && r.Detalle.Contains("público") && r.Detalle.Contains("solo avisa"), "firewall apagado en un perfil: atencion, nombra el perfil", r.Detalle);
            r = Resumen(Completo(Conectada(), firewall: new EstadoDeFirewall(0, false, new[] { new PerfilDeFirewall("Privado", false) })));
            Check(Fila(r, Resumir.Firewall).Estado == "Desactivado", "firewall apagado en todos los perfiles");
            r = Resumen(Completo(Conectada(), firewall: new EstadoDeFirewall(1, false, Array.Empty<PerfilDeFirewall>())));
            Check(Fila(r, Resumir.Firewall).Indicador == Indicador.SinDatos, "firewall sin perfiles informados: sin datos, no correcto");

            r = Resumen(Completo(Conectada(), programado: new EstadoDeEscaneoProgramado(true, "con_detecciones", Ayer, null, false, false, 2, null)));
            Check(r.Indicador == Indicador.Alerta && r.Titulo == "Alerta en Escaneo programado: 2 detecciones.", "programado con detecciones: alerta en la cabecera", r.Titulo);
            r = Resumen(Completo(Conectada(), programado: new EstadoDeEscaneoProgramado(true, "nunca", null, null, true, false, 0, null)));
            Check(Fila(r, Resumir.Programado) is { Indicador: Indicador.Atencion, Estado: "Vencido", Detalle: "Nunca terminó uno completo." },
                "programado que nunca termino: vencido", Fila(r, Resumir.Programado).Detalle);
            r = Resumen(Completo(Conectada(), programado: new EstadoDeEscaneoProgramado(true, "fallido", Ayer, null, false, false, 0, "no se pudo conectar con clamd")));
            Check(Fila(r, Resumir.Programado) is { Indicador: Indicador.Atencion, Estado: "Falló" }
                  && Fila(r, Resumir.Programado).Detalle.Contains("no se pudo conectar con clamd"), "programado fallido: dice el motivo",
                Fila(r, Resumir.Programado).Detalle);
            r = Resumen(Completo(Conectada(), programado: new EstadoDeEscaneoProgramado(true, "desconocido", Ayer, null, false, false, 0, null)));
            Check(Fila(r, Resumir.Programado).Indicador == Indicador.SinDatos, "programado con resultado desconocido: sin datos, no «al dia»");
            r = Resumen(Completo(Conectada(), programado: new EstadoDeEscaneoProgramado(false, "nunca", null, null, true, false, 0, null)));
            Check(Fila(r, Resumir.Programado) is { Indicador: Indicador.SinDatos, Estado: "Apagado" } && r.Indicador == Indicador.Correcto,
                "programado apagado: gris, y no cambia la cabecera (es una eleccion, no un fallo)");

            r = Resumen(Completo(Conectada(), cuarentena: new EstadoDeCuarentena(1, Ayer)));
            Check(Fila(r, Resumir.Cuarentena) is { Estado: "1 elemento" } && Fila(r, Resumir.Cuarentena).Detalle.Contains(Resumir.Fecha(Ayer)),
                "cuarentena con un elemento: cuando se elimina");

            var conFallo = new EstadoCompleto(Conectada(), Consulta<EstadoDelMotor>.Bien(new EstadoDelMotor(true, "clamd", "v")),
                Consulta<EstadoDeEscaneoProgramado>.Bien(ProgramadoAlDia),
                Consulta<EstadoDeFirewall>.Mal("el servicio contestó con un error (metodo desconocido)"),
                Consulta<EstadoDeCuarentena>.Bien(new EstadoDeCuarentena(0, null)));
            r = Resumen(conFallo);
            Check(Fila(r, Resumir.Firewall) is { Indicador: Indicador.SinDatos, Estado: "Sin datos" }
                  && Fila(r, Resumir.Firewall).Detalle.Contains("metodo desconocido"), "un modulo que no se pudo consultar: sin datos, con el motivo");
            Check(Fila(r, Resumir.Motor).Indicador == Indicador.Correcto, "los demas modulos se siguen mostrando");

            r = Resumen(Completo(Conectada(tr: false), programado: new EstadoDeEscaneoProgramado(true, "con_detecciones", Ayer, null, false, false, 1, null)));
            Check(r.Indicador == Indicador.Alerta && r.Titulo.Contains("Escaneo programado"), "tiempo real apagado + detecciones programadas: manda la alerta", r.Titulo);
            var d = new DeteccionVista(@"C:\x.exe", "Win.Test.EICAR_HDB-1", 68, "abc");
            r = Resumen(Completo(Conectada(det: d), firewall: new EstadoDeFirewall(0, false, new[] { new PerfilDeFirewall("Privado", false) })));
            Check(r.Indicador == Indicador.Alerta && r.Titulo.StartsWith("Hay 1 detección"), "deteccion en tiempo real + firewall apagado: manda la deteccion", r.Titulo);
            Check(Fila(r, Resumir.Firewall).Indicador == Indicador.Atencion, "y el firewall sigue visible en su fila");
        }

        // ============================================================
        private sealed class FuenteFija : IFuenteDeEstado
        {
            public EstadoCompleto Valor = EstadoCompleto.SinConexion(InstantaneaDelServicio.SinConexion("sin valor"));
            public int Llamadas;
            public Task<EstadoCompleto> ConsultarAsync(CancellationToken ct) { Llamadas++; return Task.FromResult(Valor); }
        }

        private sealed class FuenteQueFalla : IFuenteDeEstado
        {
            public Task<EstadoCompleto> ConsultarAsync(CancellationToken ct) => throw new InvalidCastException("roto");
        }

        private sealed class FuenteLenta : IFuenteDeEstado
        {
            public readonly TaskCompletionSource<EstadoCompleto> Pendiente = new TaskCompletionSource<EstadoCompleto>();
            public int Llamadas;
            public Task<EstadoCompleto> ConsultarAsync(CancellationToken ct) { Llamadas++; return Pendiente.Task; }
        }

        private static void ProbarModeloDeLaVentana()
        {
            Console.WriteLine("== Modelo de la ventana (fuentes falsas)");

            var fija = new FuenteFija { Valor = Completo(Conectada(tr: false)) };
            var vm = new VentanaPrincipalModelo(fija, () => new DateTime(2026, 11, 5, 9, 12, 30));
            Check(vm.Titulo.StartsWith("Consultando"), "antes de consultar no muestra ningun estado", vm.Titulo);
            int avisos = 0;
            vm.PropertyChanged += (_, _) => avisos++;
            Esperar(vm.ActualizarAsync());
            Check(vm.Titulo.Contains("apagado") && avisos > 0, "tras consultar muestra el estado y avisa a la ventana", vm.Titulo);
            Check(vm.BarraConsulta == "Última consulta: 09:12:30", "la hora de la ultima consulta sale del reloj", vm.BarraConsulta);
            Check(vm.Modulos.Count == 7, "la ventana recibe las 7 filas");

            fija.Valor = EstadoCompleto.SinConexion(InstantaneaDelServicio.SinConexion("el servicio no esta en marcha"));
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
            lenta.Pendiente.SetResult(Completo(Conectada()));
            Esperar(primera);
            Check(vl.Resumen!.Indicador == Indicador.Correcto, "la consulta lenta termina y se aplica");
            Esperar(vl.ActualizarAsync());
            Check(lenta.Llamadas == 2, "terminada la anterior, se puede volver a consultar");
        }

        private static void ProbarFuentePorDefecto()
        {
            Console.WriteLine("== Fuente por defecto en esta compilacion (net8.0)");
            EstadoCompleto e = Fuentes.PorDefecto("NexoIpc").ConsultarAsync(CancellationToken.None).GetAwaiter().GetResult();
            Check(!e.Servicio.Conectado, "sin el pipe de Windows la fuente dice «sin conexion»");
            Check(e.Servicio.Error is not null && (OperatingSystem.IsWindows() ? e.Servicio.Error.Contains("Windows") : e.Servicio.Error.Contains("Linux")),
                "y explica por que", e.Servicio.Error);
            Check(e.Firewall.Valor is null && e.Motor.Valor is null && e.Programado.Valor is null && e.Cuarentena.Valor is null,
                "y no trae datos de ningun modulo");
        }

        // ============================================================
        private static void ProbarVentana(string? captura)
        {
            Console.WriteLine("== La ventana de verdad, sin pantalla");

            // Un caso con de todo un poco, para la captura: tiempo real bien, firewall apagado en un perfil, 2 en cuarentena.
            var fija = new FuenteFija
            {
                Valor = Completo(Conectada(),
                    firewall: new EstadoDeFirewall(3, true, new[]
                        { new PerfilDeFirewall("Dominio", true), new PerfilDeFirewall("Privado", true), new PerfilDeFirewall("Publico", false) }),
                    cuarentena: new EstadoDeCuarentena(2, new DateTimeOffset(2026, 11, 19, 9, 0, 0, TimeSpan.Zero)))
            };
            var vm = new VentanaPrincipalModelo(fija, () => new DateTime(2026, 11, 5, 9, 12, 30));
            MainWindow? w = null;
            try
            {
                w = new MainWindow(vm);
                Check(true, "el XAML de la ventana carga (tema Classic incluido)");
                w.Show();
                Dispatcher.UIThread.RunJobs();
                Check(fija.Llamadas == 1, "al abrirse consulta al servicio una vez", fija.Llamadas.ToString());
                Check(w.TituloDeEstado.Text == vm.Titulo && vm.Titulo.Contains("Firewall"), "el titulo enlazado muestra lo mas grave", w.TituloDeEstado.Text);
                Check(w.ListaDeModulos.ItemCount == 7, "la tabla de modulos tiene 7 filas", w.ListaDeModulos.ItemCount.ToString());
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
