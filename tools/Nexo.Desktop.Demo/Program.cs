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
            ProbarLectorDeEscaneo();
            ProbarResumenDeEscaneo();
            ProbarModeloDeEscaneo();
            ProbarCuarentena();
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
            Check(Fila(r, Resumir.Cuarentena) is { Estado: "1 elemento" } && Fila(r, Resumir.Cuarentena).Detalle.Contains(Resumir.Fecha(Ayer))
                  && !Fila(r, Resumir.Cuarentena).Detalle.Contains("se elimina el"),
                "cuarentena con un elemento: cuando vence, sin decir que se borra solo (el servicio no purga solo)", Fila(r, Resumir.Cuarentena).Detalle);

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

        // ============================================================ Escaneo
        private static ResultadoDeEscaneoVista ResultadoDeEscaneo(int detecciones = 0, int omitidos = 0, bool incompleto = false,
                                                                   bool limpio = true, int omitidosMostrados = -1)
        {
            var det = Enumerable.Range(1, detecciones)
                .Select(i => new DeteccionDeEscaneo(@"C:\Users\u\Downloads\f" + i + ".zip", "Win.Test.EICAR_HDB-1", 68, "abc" + i)).ToList();
            var omi = Enumerable.Range(1, omitidosMostrados < 0 ? omitidos : omitidosMostrados)
                .Select(i => @"C:\Users\u\Downloads\o" + i + ".mkv — demasiado grande").ToList();
            return new ResultadoDeEscaneoVista("abc", "terminado", true, 120, limpio && detecciones == 0 && omitidos == 0 && !incompleto,
                incompleto, incompleto ? "5 errores seguidos del motor" : null, 3.4, det, omi, omitidos, null);
        }

        private sealed class EscaneoFalso : IServicioDeEscaneo
        {
            public Consulta<string> AlIniciar = Consulta<string>.Bien("abc");
            public readonly System.Collections.Generic.Queue<Consulta<AvanceDeEscaneo>> Avances = new System.Collections.Generic.Queue<Consulta<AvanceDeEscaneo>>();
            public Consulta<ResultadoDeEscaneoVista> AlResultado = Consulta<ResultadoDeEscaneoVista>.Bien(ResultadoDeEscaneo());
            public Consulta<PlanDeCuarentena> AlPlan = Consulta<PlanDeCuarentena>.Bien(new PlanDeCuarentena("Mover 1 archivo", true, new string('a', 64), Array.Empty<string>()));
            public ResultadoDeAccion AlAplicar = new ResultadoDeAccion(true, false, "1 archivos en cuarentena.");
            public readonly System.Collections.Generic.List<string> Llamadas = new System.Collections.Generic.List<string>();
            public System.Collections.Generic.IReadOnlyList<string>? RutasPedidas;
            public int ParaleloPedido;
            public string? TokenAplicado;

            public Task<Consulta<string>> IniciarAsync(System.Collections.Generic.IReadOnlyList<string> rutas, int paralelo, CancellationToken ct)
            { Llamadas.Add("iniciar"); RutasPedidas = rutas; ParaleloPedido = paralelo; return Task.FromResult(AlIniciar); }
            public Task<Consulta<AvanceDeEscaneo>> AvanceAsync(string id, CancellationToken ct)
            { Llamadas.Add("progreso:" + id); return Task.FromResult(Avances.Count > 0 ? Avances.Dequeue() : Consulta<AvanceDeEscaneo>.Mal("sin datos de prueba")); }
            public Task<Consulta<ResultadoDeEscaneoVista>> ResultadoAsync(string id, CancellationToken ct)
            { Llamadas.Add("resultado:" + id); return Task.FromResult(AlResultado); }
            public Task<Consulta<string>> CancelarAsync(string id, CancellationToken ct)
            { Llamadas.Add("cancelar:" + id); return Task.FromResult(Consulta<string>.Bien(id)); }
            public Task<Consulta<PlanDeCuarentena>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct)
            { Llamadas.Add("previsualizar:" + id); return Task.FromResult(AlPlan); }
            public Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct)
            { Llamadas.Add("aplicar"); TokenAplicado = token; return Task.FromResult(AlAplicar); }
        }

        private static Consulta<AvanceDeEscaneo> Avance(string estado, int analizados, string? error = null)
            => Consulta<AvanceDeEscaneo>.Bien(new AvanceDeEscaneo("abc", estado, analizados, error));

        private static EscaneoModelo ModeloDeEscaneo(EscaneoFalso s) => new EscaneoModelo(s, @"C:\Users\u", @"C:\");

        private static void ProbarLectorDeEscaneo()
        {
            Console.WriteLine("== Lector de escaneo.* y cuarentena.previsualizar");

            Check(LectorDeEscaneo.Iniciar(Json("{\"id\":\"9f2c\",\"rutas\":[\"C:\\\\Users\"]}")).Valor == "9f2c", "escaneo.iniciar: el id");
            var c = LectorDeEscaneo.Iniciar(new RespuestaCruda(false, "ya hay un escaneo en curso", null));
            Check(c.Valor is null && c.Error == "ya hay un escaneo en curso", "escaneo.iniciar rechazado: el motivo del servicio, tal cual", c.Error);

            var a = LectorDeEscaneo.Avance(Json("{\"id\":\"9f2c\",\"estado\":\"corriendo\",\"analizados\":1864}"));
            Check(a.Valor is { Estado: "corriendo", Analizados: 1864, Error: null }, "escaneo.progreso (sin «error», que el servicio omite si es nulo)");

            var r = LectorDeEscaneo.Resultado(Json("{\"id\":\"9f2c\",\"estado\":\"cancelado\",\"listo\":false}"));
            Check(r.Valor is { Listo: false, Estado: "cancelado" }, "escaneo.resultado sin resultado (cancelado)");
            r = LectorDeEscaneo.Resultado(Json(
                "{\"id\":\"9f2c\",\"estado\":\"terminado\",\"listo\":true,\"analizados\":3012,\"completamente_limpio\":false,\"incompleto\":false," +
                "\"duracion_segundos\":41.2,\"detecciones\":[{\"ruta\":\"C:\\\\x.zip\",\"firma\":\"Win.Test.EICAR_HDB-1\",\"bytes\":184,\"sha256\":\"ab\"}]," +
                "\"omitidos\":[\"C:\\\\a.mkv — demasiado grande\",\"C:\\\\b.docx — en uso\"],\"omitidos_total\":5}"));
            Check(r.Valor is { Listo: true, Analizados: 3012, OmitidosTotal: 5, MotivoIncompleto: null } && r.Valor.Detecciones.Count == 1
                  && r.Valor.Omitidos.Count == 2, "escaneo.resultado completo: detecciones, omitidos y total");
            r = LectorDeEscaneo.Resultado(Json(
                "{\"id\":\"9f2c\",\"estado\":\"terminado\",\"listo\":true,\"analizados\":3,\"completamente_limpio\":true,\"incompleto\":false," +
                "\"duracion_segundos\":1,\"detecciones\":[],\"omitidos\":[]}"));
            Check(r.Valor is null && r.Error!.Contains("no reconocida"), "sin «omitidos_total»: no se da por limpio a medias", r.Error);

            var p = LectorDeEscaneo.Plan(Json("{\"descripcion\":\"Mover 1 archivo\",\"hay_cambios\":true,\"token\":\"" + new string('b', 64) + "\",\"avisos\":[\"Defender\"]}"));
            Check(p.Valor is { HayCambios: true } && p.Valor.Token!.Length == 64 && p.Valor.Avisos.Count == 1, "cuarentena.previsualizar con token y avisos");
            p = LectorDeEscaneo.Plan(Json("{\"descripcion\":\"Nada que mover\",\"hay_cambios\":false}"));
            Check(p.Valor is { HayCambios: false, Token: null }, "plan sin cambios: sin token");
        }

        private static void ProbarResumenDeEscaneo()
        {
            Console.WriteLine("== Resumen del resultado de un escaneo");

            var r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(), null);
            Check(r.Indicador == Indicador.Correcto && r.Titulo.Contains("se pudo analizar todo"), "limpio y completo: verde", r.Titulo);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(omitidos: 3), null);
            Check(r.Indicador == Indicador.Atencion && r.Titulo == "Sin detecciones, pero 3 archivos no se pudieron analizar." && r.Detalle.Contains("no cuentan como limpios"),
                "con archivos sin analizar: atencion, nunca «limpio»", r.Titulo);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(incompleto: true), null);
            Check(r.Indicador == Indicador.Atencion && r.Titulo.Contains("INCOMPLETO") && r.Detalle.Contains("5 errores seguidos"), "incompleto: lo dice con el motivo", r.Detalle);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(detecciones: 2, incompleto: true), null);
            Check(r.Indicador == Indicador.Alerta && r.Titulo.Contains("2 detecciones"), "incompleto con detecciones: alerta", r.Titulo);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(detecciones: 1, omitidos: 1), null);
            Check(r.Indicador == Indicador.Alerta && r.Titulo == "1 detección." && r.Detalle.Contains("no se han tocado") && r.Detalle.Contains("1 archivo no se pudo"),
                "con una deteccion: alerta, los archivos no se tocaron y menciona lo no analizado", r.Detalle);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Cancelado, 40, null, null);
            Check(r.Indicador == Indicador.Atencion && r.Detalle.Contains("40 archivos") && r.Detalle.Contains("no cuenta como limpio"), "cancelado: no cuenta como limpio", r.Detalle);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Fallido, 0, null, "el motor de analisis no esta disponible");
            Check(r.Indicador == Indicador.Atencion && r.Detalle.Contains("motor de analisis"), "fallido: el motivo", r.Detalle);
            r = ResumirEscaneo.Desde(FaseDeEscaneo.Terminado, 120, ResultadoDeEscaneo(limpio: false), null);
            Check(r.Indicador == Indicador.SinDatos, "terminado sin que el servicio confirme «completamente limpio»: no es verde");
        }

        private static void ProbarModeloDeEscaneo()
        {
            Console.WriteLine("== Modelo de la pestaña Escaneo (servicio falso)");

            var s = new EscaneoFalso();
            var m = ModeloDeEscaneo(s);
            Check(m.Fase == FaseDeEscaneo.Listo && m.PuedeIniciar && !m.PuedeCancelar && !m.PuedePonerEnCuarentena, "al empezar: se puede iniciar, nada mas");
            Check(m.DestinoDescargas && m.RutaDescargas == System.IO.Path.Combine(@"C:\Users\u", "Downloads"), "por omision analiza Descargas");

            m.DestinoOtra = true;
            Esperar(m.IniciarAsync());
            Check(s.Llamadas.Count == 0 && m.Mensaje.Contains("elija la carpeta"), "otra carpeta vacia: no se pide nada al servicio", m.Mensaje);
            Check(!m.DestinoDescargas, "los destinos son excluyentes");

            m.DestinoDescargas = true;
            m.Paralelo = 2;
            Esperar(m.IniciarAsync());
            Check(s.RutasPedidas!.SequenceEqual(new[] { m.RutaDescargas }) && s.ParaleloPedido == 2, "pide la ruta elegida y el paralelismo");
            Check(m.Fase == FaseDeEscaneo.Corriendo && !m.PuedeIniciar && m.PuedeCancelar && m.EnCurso, "corriendo: no se puede lanzar otro, si cancelar");

            s.Avances.Enqueue(Avance("corriendo", 500));
            Esperar(m.SondearAsync());
            Check(m.TextoDeAvance == "Analizados: 500 archivos" && m.Titulo == "Escaneando...", "el avance se muestra", m.TextoDeAvance);

            s.Avances.Enqueue(Consulta<AvanceDeEscaneo>.Mal("el servicio no está en marcha"));
            Esperar(m.SondearAsync());
            Check(m.Fase == FaseDeEscaneo.Corriendo && m.Mensaje.Contains("Se reintenta"), "un fallo suelto al consultar el avance no corta el seguimiento", m.Mensaje);

            s.AlResultado = Consulta<ResultadoDeEscaneoVista>.Bien(ResultadoDeEscaneo(detecciones: 1, omitidos: 5, omitidosMostrados: 2));
            s.Avances.Enqueue(Avance("terminado", 120));
            Esperar(m.SondearAsync());
            Check(m.Fase == FaseDeEscaneo.Terminado && s.Llamadas.Contains("resultado:abc") && m.Detecciones.Count == 1 && m.Mensaje == "",
                "al terminar pide el resultado y muestra la deteccion");
            Check(m.PuedePonerEnCuarentena && m.PuedeIniciar && !m.PuedeCancelar, "con detecciones se ofrece la cuarentena, y otro escaneo");
            Check(m.HayOmitidos && m.TextoOmitidos.Contains("se muestran 2 de 5"), "si el servicio recorta la lista de omitidos, lo dice", m.TextoOmitidos);

            int antes = s.Llamadas.Count;
            Esperar(m.SondearAsync());
            Check(s.Llamadas.Count == antes, "terminado: el temporizador ya no consulta al servicio");

            Consulta<PlanDeCuarentena> plan = m.PrevisualizarCuarentenaAsync().GetAwaiter().GetResult();
            Check(plan.Valor is not null && s.Llamadas.Contains("previsualizar:abc"), "la cuarentena se previsualiza con el id de ESTE escaneo");
            Check(!s.Llamadas.Contains("aplicar"), "previsualizar no aplica nada");
            ResultadoDeAccion ap = m.AplicarCuarentenaAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(ap.Exito && s.TokenAplicado == plan.Valor.Token && m.Mensaje == "1 archivos en cuarentena.", "aplicar manda el token del plan y muestra el resultado");

            // Un escaneo limpio no ofrece cuarentena.
            var s2 = new EscaneoFalso();
            var m2 = ModeloDeEscaneo(s2);
            Esperar(m2.IniciarAsync());
            s2.Avances.Enqueue(Avance("terminado", 120));
            Esperar(m2.SondearAsync());
            Check(m2.Fase == FaseDeEscaneo.Terminado && !m2.PuedePonerEnCuarentena && m2.Titulo.Contains("se pudo analizar todo"), "limpio: verde y sin cuarentena");
            Check(m2.PrevisualizarCuarentenaAsync().GetAwaiter().GetResult().Valor is null && !s2.Llamadas.Any(l => l.StartsWith("previsualizar")),
                "sin detecciones, ni siquiera se pide la vista previa");

            // Rechazo al iniciar.
            var s3 = new EscaneoFalso { AlIniciar = Consulta<string>.Mal("ya hay un escaneo en curso") };
            var m3 = ModeloDeEscaneo(s3);
            Esperar(m3.IniciarAsync());
            Check(m3.Fase == FaseDeEscaneo.Listo && m3.PuedeIniciar && m3.Mensaje.Contains("ya hay un escaneo en curso"), "si el servicio rechaza el escaneo, se dice por que", m3.Mensaje);

            // Cancelar.
            var s4 = new EscaneoFalso();
            var m4 = ModeloDeEscaneo(s4);
            Esperar(m4.IniciarAsync());
            Esperar(m4.CancelarAsync());
            Check(s4.Llamadas.Contains("cancelar:abc") && m4.Mensaje == "Cancelando...", "cancelar se pide con el id");
            s4.Avances.Enqueue(Avance("cancelado", 40));
            Esperar(m4.SondearAsync());
            Check(m4.Fase == FaseDeEscaneo.Cancelado && m4.Titulo == "Escaneo cancelado." && !m4.PuedePonerEnCuarentena, "cancelado: lo dice y no ofrece cuarentena");

            // Se pierde el servicio.
            var s5 = new EscaneoFalso();
            var m5 = ModeloDeEscaneo(s5);
            Esperar(m5.IniciarAsync());
            for (int i = 0; i < EscaneoModelo.FallosDeAvanceTolerados; i++) Esperar(m5.SondearAsync());
            Check(m5.Fase == FaseDeEscaneo.Fallido && m5.Detalle.Contains("perdió el contacto") && m5.PuedeIniciar,
                "varios fallos seguidos: deja de seguirlo y dice que puede seguir en el servicio", m5.Detalle);

            // Termina sin resultado.
            var s6 = new EscaneoFalso { AlResultado = Consulta<ResultadoDeEscaneoVista>.Mal("el escaneo no existe") };
            var m6 = ModeloDeEscaneo(s6);
            Esperar(m6.IniciarAsync());
            s6.Avances.Enqueue(Avance("terminado", 10));
            Esperar(m6.SondearAsync());
            Check(m6.Fase == FaseDeEscaneo.Fallido && !m6.Titulo.Contains("Sin detecciones"), "terminado pero sin resultado: no se presenta como limpio", m6.Titulo);

            // Fallido en el servicio.
            var s7 = new EscaneoFalso();
            var m7 = ModeloDeEscaneo(s7);
            Esperar(m7.IniciarAsync());
            s7.Avances.Enqueue(Avance("fallido", 3, "no se pudo conectar con clamd"));
            Esperar(m7.SondearAsync());
            Check(m7.Fase == FaseDeEscaneo.Fallido && m7.Detalle.Contains("clamd"), "fallido en el servicio: el motivo", m7.Detalle);
        }

        // ============================================================ Cuarentena
        private static readonly DateTimeOffset Hoy = new DateTimeOffset(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);

        private static ElementoDeCuarentena ElementoQueVence(DateTimeOffset fecha, DateTimeOffset vence, string nombre, string firma)
            => new ElementoDeCuarentena("id-" + nombre, @"C:\Users\u\Downloads\" + nombre, 70_000, firma, fecha, vence);

        private sealed class CuarentenaFalsa : IServicioDeCuarentena
        {
            public readonly System.Collections.Generic.List<ElementoDeCuarentena> Elementos = new System.Collections.Generic.List<ElementoDeCuarentena>();
            public string? FallarAlListar;
            public int Listados;
            public readonly System.Collections.Generic.List<string> Llamadas = new System.Collections.Generic.List<string>();
            public string? Token;
            public readonly string TokenDePlan = new string('c', 64);

            public Task<Consulta<ListaDeCuarentena>> ListarAsync(CancellationToken ct)
            {
                Listados++;
                return Task.FromResult(FallarAlListar is null
                    ? Consulta<ListaDeCuarentena>.Bien(new ListaDeCuarentena(Elementos.ToList()))
                    : Consulta<ListaDeCuarentena>.Mal(FallarAlListar));
            }
            public Task<Consulta<PlanDeCuarentena>> PrevisualizarRestauracionAsync(string id, CancellationToken ct)
            { Llamadas.Add("previsualizar-restauracion:" + id); return Task.FromResult(Consulta<PlanDeCuarentena>.Bien(new PlanDeCuarentena("Restaurar " + id, true, TokenDePlan, new[] { "Es tu decision." }))); }
            public Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct)
            { Llamadas.Add("restaurar"); Token = token; Elementos.RemoveAt(0); return Task.FromResult(new ResultadoDeAccion(true, false, "Archivo restaurado.")); }
            public Task<Consulta<PlanDeCuarentena>> PrevisualizarPurgaAsync(CancellationToken ct)
            { Llamadas.Add("previsualizar-purga"); return Task.FromResult(Consulta<PlanDeCuarentena>.Bien(new PlanDeCuarentena("Purgar 1", true, TokenDePlan, Array.Empty<string>()))); }
            public Task<ResultadoDeAccion> PurgarAsync(string token, CancellationToken ct)
            { Llamadas.Add("purgar"); Token = token; return Task.FromResult(new ResultadoDeAccion(false, true, "Se abrio el aviso de aprobacion (UAC).")); }
        }

        private static void ProbarCuarentena()
        {
            Console.WriteLine("== Cuarentena: lector y modelo de la pestaña");

            var l = LectorDeCuarentena.Listar(Json(
                "{\"elementos\":[{\"id\":\"a1\",\"ruta_original\":\"C:\\\\x.zip\",\"bytes\":68,\"firma\":\"EICAR\",\"fecha\":\"2026-11-05T09:00:00+00:00\",\"vence\":\"2026-12-05T09:00:00+00:00\"}]}"));
            Check(l.Valor is { Elementos.Count: 1 } && l.Valor.Elementos[0] is { Id: "a1", Bytes: 68, Firma: "EICAR" }, "cuarentena.listar: la entrada completa");
            Check(LectorDeCuarentena.Listar(Json("{\"elementos\":[]}")).Valor is { Elementos.Count: 0 }, "cuarentena.listar vacia");
            var rota = LectorDeCuarentena.Listar(Json("{\"elementos\":[{\"id\":\"a1\",\"ruta_original\":\"C:\\\\x\",\"bytes\":1,\"firma\":\"T\",\"fecha\":\"2026-11-05T09:00:00+00:00\"}]}"));
            Check(rota.Valor is null && rota.Error is not null, "una entrada sin «vence» invalida la lista: no se muestra una lista a medias");
            Check(LectorDeCuarentena.Listar(new RespuestaCruda(false, "no se puede actuar como el llamador", null)).Error == "no se puede actuar como el llamador",
                "un error del servicio, tal cual");

            var s = new CuarentenaFalsa();
            s.Elementos.Add(ElementoQueVence(Hoy.AddDays(-16), Hoy.AddDays(14), "viejo.exe", "Win.Trojan.Agent-123"));
            s.Elementos.Add(ElementoQueVence(Hoy.AddHours(-2), Hoy.AddDays(30).AddHours(-2), "nuevo.zip", "Win.Test.EICAR_HDB-1"));
            var m = new CuarentenaModelo(s, () => Hoy);
            Check(m.Resumen.StartsWith("Sin consultar") && !m.Leida, "antes de leer no dice que este vacia");
            Esperar(m.ActualizarAsync());
            Check(m.Leida && m.Elementos.Count == 2 && m.Elementos[0].Id == "id-nuevo.zip", "lee las entradas, la mas reciente primero");
            Check(m.Elementos[1].Vence == "en 14 días" && m.Elementos[0].Vence == "en 30 días", "cuanto falta para que venza", m.Elementos[1].Vence + " / " + m.Elementos[0].Vence);
            Check(m.Resumen == "2 archivos en cuarentena · 136.7 KB", "resumen con cuantos y cuanto ocupan", m.Resumen);
            Check(!m.PuedeRestaurar && !m.PuedeEliminarVencidos, "sin seleccion ni vencidos: ni restaurar ni eliminar");
            Check(m.PrevisualizarRestauracionAsync().GetAwaiter().GetResult().Valor is null && s.Llamadas.Count == 0, "sin seleccion no se pide nada al servicio");

            m.Seleccionado = m.Elementos[1];
            Check(m.PuedeRestaurar, "con una fila elegida se puede restaurar");
            Esperar(m.ActualizarAsync());
            Check(m.Seleccionado?.Id == "id-viejo.exe", "al volver a leer, la seleccion se mantiene");

            Consulta<PlanDeCuarentena> plan = m.PrevisualizarRestauracionAsync().GetAwaiter().GetResult();
            Check(plan.Valor is not null && s.Llamadas.SequenceEqual(new[] { "previsualizar-restauracion:id-viejo.exe" }), "la vista previa pide restaurar la fila elegida, y nada mas");
            int antes = s.Listados;
            ResultadoDeAccion r = m.RestaurarAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(r.Exito && s.Token == s.TokenDePlan && m.Mensaje == "Archivo restaurado." && s.Listados == antes + 1 && m.Elementos.Count == 1,
                "restaurar manda el token del plan, muestra el resultado y vuelve a leer la lista");

            // Un vencido.
            s.Elementos.Add(ElementoQueVence(Hoy.AddDays(-31), Hoy.AddDays(-1), "vencido.exe", "Win.Trojan.Agent-9"));
            Esperar(m.ActualizarAsync());
            Check(m.Elementos.Any(f => f.Vencido && f.Vence == "Vencido") && m.PuedeEliminarVencidos && m.Resumen.Contains("1 vencido (se pueden eliminar)"),
                "un vencido: se marca, se dice y se ofrece eliminarlo (no se borra solo)", m.Resumen);
            Consulta<PlanDeCuarentena> purga = m.PrevisualizarPurgaAsync().GetAwaiter().GetResult();
            Check(purga.Valor is not null && s.Llamadas.Last() == "previsualizar-purga" && !s.Llamadas.Contains("purgar"), "la purga se previsualiza sin aplicar nada");
            r = m.PurgarAsync(purga.Valor!.Token!).GetAwaiter().GetResult();
            Check(r.PidioAprobacion && m.Mensaje.Contains("UAC"), "si hace falta aprobacion, se dice");

            // La lectura falla despues de haber funcionado.
            s.FallarAlListar = "el servicio no está en marcha";
            Esperar(m.ActualizarAsync());
            Check(!m.Leida && m.Elementos.Count == 0 && m.Resumen == "No se pudo leer la cuarentena: el servicio no está en marcha."
                  && !m.PuedeRestaurar && !m.PuedeEliminarVencidos,
                "si no se puede leer, no se muestra la lista vieja como actual ni se ofrece nada", m.Resumen);

            var vacia = new CuarentenaModelo(new CuarentenaFalsa(), () => Hoy);
            Esperar(vacia.ActualizarAsync());
            Check(vacia.Leida && vacia.Resumen == "La cuarentena está vacía.", "vacia: lo dice (solo cuando se pudo leer)");

            var sinServicio = new CuarentenaModelo(Fuentes.CuarentenaPorDefecto("NexoIpc"));
            Esperar(sinServicio.ActualizarAsync());
            Check(!sinServicio.Leida && sinServicio.Resumen.StartsWith("No se pudo leer"), "sin servicio (esta compilacion): no se pudo leer, no «vacia»");
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
            var esc = new EscaneoModelo(Fuentes.EscaneoPorDefecto("NexoIpc"));
            Esperar(esc.IniciarAsync());
            Check(esc.Fase == FaseDeEscaneo.Listo && esc.Mensaje.StartsWith("No se pudo iniciar"), "y el escaneo dice que no puede, sin quedarse «escaneando»", esc.Mensaje);
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
            var escaneo = new EscaneoFalso
            {
                AlResultado = Consulta<ResultadoDeEscaneoVista>.Bien(ResultadoDeEscaneo(detecciones: 1, omitidos: 2))
            };
            var em = ModeloDeEscaneo(escaneo);
            var cuarentena = new CuarentenaFalsa();
            cuarentena.Elementos.Add(ElementoQueVence(Hoy.AddDays(-1), Hoy.AddDays(29), "factura-octubre.zip", "Win.Test.EICAR_HDB-1"));
            cuarentena.Elementos.Add(ElementoQueVence(Hoy.AddDays(-31), Hoy.AddDays(-1), "crack-juego.exe", "Win.Trojan.Agent-123"));
            var cm = new CuarentenaModelo(cuarentena, () => Hoy);
            MainWindow? w = null;
            try
            {
                w = new MainWindow(vm, em, cm);
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

                // La pestaña Escaneo, con un escaneo que termina con una deteccion y dos archivos sin analizar.
                w.Pestanas.SelectedIndex = 1;
                Esperar(em.IniciarAsync());
                escaneo.Avances.Enqueue(Avance("terminado", 120));
                Esperar(em.SondearAsync());
                Dispatcher.UIThread.RunJobs();
                Check(w.TituloDeEscaneo.Text == "1 detección.", "pestaña Escaneo: el resultado enlazado", w.TituloDeEscaneo.Text);
                Check(w.ListaDeDetecciones.ItemCount == 1 && w.BotonCuarentenaDeEscaneo.IsEnabled && w.BotonIniciar.IsEnabled,
                    "pestaña Escaneo: la deteccion en la tabla y la cuarentena habilitada");

                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string segunda = System.IO.Path.ChangeExtension(captura, null) + "-escaneo.png";
                    w.CaptureRenderedFrame()?.Save(segunda);
                    Console.WriteLine("           captura: " + segunda);
                }

                // La pestaña Cuarentena: se lee al abrir la ventana y otra vez al entrar en la pestaña.
                Check(cuarentena.Listados == 1, "al abrirse la ventana lee la cuarentena una vez", cuarentena.Listados.ToString());
                w.Pestanas.SelectedIndex = 6;
                Dispatcher.UIThread.RunJobs();
                Check(cuarentena.Listados == 2, "al entrar en la pestaña la vuelve a leer", cuarentena.Listados.ToString());
                Check(w.TablaDeCuarentena.ItemCount == 2 && w.ResumenDeCuarentena.Text!.Contains("1 vencido"),
                    "pestaña Cuarentena: las 2 entradas y el resumen", w.ResumenDeCuarentena.Text);
                Check(!w.BotonRestaurar.IsEnabled && w.BotonEliminarVencidos.IsEnabled, "sin seleccion no se puede restaurar; con un vencido, si eliminar vencidos");
                w.TablaDeCuarentena.SelectedIndex = 0;
                Dispatcher.UIThread.RunJobs();
                Check(cm.Seleccionado?.Id == "id-factura-octubre.zip" && w.BotonRestaurar.IsEnabled, "al elegir una fila se puede restaurar");

                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string tercera = System.IO.Path.ChangeExtension(captura, null) + "-cuarentena.png";
                    w.CaptureRenderedFrame()?.Save(tercera);
                    Console.WriteLine("           captura: " + tercera);
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
