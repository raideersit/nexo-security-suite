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
    internal static partial class Program
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
            ProbarDeteccionesProgramadas();
            ProbarCuarentena();
            ProbarFirewall();
            ProbarLimpieza();
            ProbarTiempoReal();
            ProbarDisco();
            ProbarSeguridad();
            ProbarSeguridadFallosConocidos();
            ProbarBloqueoDeSeguridadDelModelo();
            ProbarRastroDeLaVentana();
            ProbarTotpEnLaVentana();
            ProbarContrasenas();
            ProbarEnlaces();
            ProbarQrEnLaVentana();
            ProbarDialogos(captura);
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
            Check(Resumen(Completo(Conectada(), motor: new EstadoDelMotor(true, "ClamAV (clamd)", "ClamAV 1.5.4"))).BarraMotor == "Motor clamd: listo",
                  "la barra con el nombre real de ClamAV sigue diciendo «clamd»");

            // El motor es YARA (Nexo:Motor = yara): la barra y la fila lo dicen, no «clamd» (se vio en la ventana real, 2026-11-05).
            r = Resumen(Completo(Conectada(), motor: new EstadoDelMotor(true, "YARA", "YARA 4.6.0 (reglas: reglas.yar)")));
            Check(r.BarraMotor == "Motor YARA: listo" && Fila(r, Resumir.Motor).Detalle == "YARA 4.6.0 (reglas: reglas.yar)",
                  "motor YARA: la barra dice YARA", r.BarraMotor);
            r = Resumen(Completo(Conectada(), motor: new EstadoDelMotor(false, "YARA", null)));
            Check(r.BarraMotor == "Motor YARA: no responde" && Fila(r, Resumir.Motor).Detalle.StartsWith("YARA no contesta", StringComparison.Ordinal),
                  "motor YARA sin responder: la barra y la fila dicen YARA, no clamd", Fila(r, Resumir.Motor).Detalle);

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
            public Consulta<PlanDelServicio> AlPlan = Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Mover 1 archivo", true, new string('a', 64), Array.Empty<string>()));
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
            public Task<Consulta<PlanDelServicio>> PrevisualizarCuarentenaAsync(string id, CancellationToken ct)
            { Llamadas.Add("previsualizar:" + id); return Task.FromResult(AlPlan); }
            public Task<ResultadoDeAccion> AplicarCuarentenaAsync(string token, CancellationToken ct)
            { Llamadas.Add("aplicar"); TokenAplicado = token; return Task.FromResult(AlAplicar); }
            public Consulta<System.Collections.Generic.IReadOnlyList<DeteccionDeEscaneo>> AlProgramado =
                Consulta<System.Collections.Generic.IReadOnlyList<DeteccionDeEscaneo>>.Bien(new DeteccionDeEscaneo[0]);
            public Task<Consulta<System.Collections.Generic.IReadOnlyList<DeteccionDeEscaneo>>> DeteccionesProgramadasAsync(CancellationToken ct)
            { Llamadas.Add("programado"); return Task.FromResult(AlProgramado); }
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

            // escaneo-programado.detecciones
            var dp = LectorDeEscaneo.DeteccionesProgramadas(Json("{\"id_escaneo\":\"programado\",\"detecciones\":[{\"ruta\":\"C:\\\\a.exe\",\"firma\":\"F.1\",\"bytes\":5,\"sha256\":\"ab\"}]}"));
            Check(dp.Valor is { Count: 1 } && dp.Valor[0].Firma == "F.1" && dp.Valor[0].Bytes == 5, "escaneo-programado.detecciones se lee");
            Check(LectorDeEscaneo.DeteccionesProgramadas(Json("{\"id_escaneo\":\"programado\",\"detecciones\":[]}")).Valor is { Count: 0 }, "lista vacia: sin detecciones");
            Check(LectorDeEscaneo.DeteccionesProgramadas(Json("{\"id_escaneo\":\"programado\"}")).Valor is null,
                "sin la lista no se toma por «sin detecciones»");
            Check(LectorDeEscaneo.DeteccionesProgramadas(new RespuestaCruda(false, "metodo desconocido", null)).Error == "metodo desconocido", "un error del servicio, tal cual");
        }

        private static void ProbarDeteccionesProgramadas()
        {
            Console.WriteLine("== Detecciones del escaneo programado en la pestaña Escaneo");
            string real = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nexo-prog-" + Guid.NewGuid().ToString("N") + ".bin");
            System.IO.File.WriteAllText(real, "x");
            try
            {
                var s = new EscaneoFalso();
                var m = ModeloDeEscaneo(s);
                Esperar(m.ActualizarProgramadasAsync());
                Check(!m.HayProgramadas && !m.PuedePonerEnCuarentenaProgramadas && m.Programadas.Count == 0, "sin detecciones programadas: el bloque no aparece");

                s.AlProgramado = Consulta<System.Collections.Generic.IReadOnlyList<DeteccionDeEscaneo>>.Bien(new[]
                {
                    new DeteccionDeEscaneo(real, "Test.Firma", 1, "aa"),
                    new DeteccionDeEscaneo(@"Z:\no\existe\ya.exe", "Test.Otra", 1, "bb")
                });
                Esperar(m.ActualizarProgramadasAsync());
                Check(m.HayProgramadas && m.Programadas.Count == 1 && m.Programadas[0].Ruta == real && m.PuedePonerEnCuarentenaProgramadas,
                    "lista lo que sigue en su sitio y deja fuera lo que ya no existe", m.Programadas.Count.ToString());
                Check(m.TextoProgramadas.Contains("1 archivo") && m.TextoProgramadas.Contains("No se han tocado"), "dice que no se ha tocado nada", m.TextoProgramadas);

                Consulta<PlanDelServicio> plan = m.PrevisualizarCuarentenaProgramadaAsync().GetAwaiter().GetResult();
                Check(s.Llamadas.Contains("previsualizar:programado"), "la cuarentena se pide con el id «programado», no con el del escaneo manual");
                Check(plan.Valor is not null && !s.Llamadas.Contains("aplicar"), "previsualizar no aplica nada");
                m.AplicarCuarentenaProgramadaAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
                Check(s.Llamadas.Contains("aplicar") && m.Programadas.Count == 1, "si el archivo sigue en su sitio tras aplicar, se sigue mostrando");
                System.IO.File.Delete(real);
                Esperar(m.ActualizarProgramadasAsync());
                Check(!m.HayProgramadas && m.Programadas.Count == 0, "cuando el archivo ya no esta, desaparece de la lista");

                // Si no se puede leer, no se muestra lo anterior como actual ni se da por limpio.
                s.AlProgramado = Consulta<System.Collections.Generic.IReadOnlyList<DeteccionDeEscaneo>>.Mal("el servicio no responde");
                Esperar(m.ActualizarProgramadasAsync());
                Check(m.HayProgramadas && m.Programadas.Count == 0 && !m.PuedePonerEnCuarentenaProgramadas && m.TextoProgramadas.Contains("el servicio no responde"),
                    "si no se pudo leer, lo dice (no lo presenta como «sin detecciones»)", m.TextoProgramadas);
            }
            finally { if (System.IO.File.Exists(real)) System.IO.File.Delete(real); }
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

            Consulta<PlanDelServicio> plan = m.PrevisualizarCuarentenaAsync().GetAwaiter().GetResult();
            Check(plan.Valor is not null && s.Llamadas.Contains("previsualizar:abc"), "la cuarentena se previsualiza con el id de ESTE escaneo");
            Check(!s.Llamadas.Contains("aplicar"), "previsualizar no aplica nada");
            ResultadoDeAccion ap = m.AplicarCuarentenaAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(ap.Exito && s.TokenAplicado == plan.Valor.Token && m.Mensaje == "1 archivos en cuarentena.", "aplicar manda el token del plan y muestra el resultado");

            Check(m.Detecciones.Count == 0 && !m.PuedePonerEnCuarentena,
                "tras la cuarentena, la deteccion cuyo archivo ya no esta deja de listarse y no se ofrece otra vez", m.Detecciones.Count.ToString());

            // Si el archivo SIGUE en su sitio (no se pudo mover), la deteccion se queda: no se da por resuelta sin mirar.
            string real = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nexo-det-" + Guid.NewGuid().ToString("N") + ".bin");
            System.IO.File.WriteAllText(real, "x");
            try
            {
                var sRet = new EscaneoFalso();
                sRet.AlResultado = Consulta<ResultadoDeEscaneoVista>.Bien(new ResultadoDeEscaneoVista("abc", "terminado", true, 1, false, false, null, 1.0,
                    new[] { new DeteccionDeEscaneo(real, "Test.Firma", 1, "aa") }, new string[0], 0, null));
                var mRet = ModeloDeEscaneo(sRet);
                Esperar(mRet.IniciarAsync());
                sRet.Avances.Enqueue(Avance("terminado", 1));
                Esperar(mRet.SondearAsync());
                mRet.AplicarCuarentenaAsync("tok").GetAwaiter().GetResult();
                Check(mRet.Detecciones.Count == 1 && mRet.PuedePonerEnCuarentena, "si el archivo sigue en su sitio, la deteccion se queda en la lista");
                System.IO.File.Delete(real);
                mRet.RetirarLasQueYaNoEstan();
                Check(mRet.Detecciones.Count == 0, "cuando el archivo desaparece, se retira al refrescar");
            }
            finally { if (System.IO.File.Exists(real)) System.IO.File.Delete(real); }

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
            public Task<Consulta<PlanDelServicio>> PrevisualizarRestauracionAsync(string id, CancellationToken ct)
            { Llamadas.Add("previsualizar-restauracion:" + id); return Task.FromResult(Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Restaurar " + id, true, TokenDePlan, new[] { "Es tu decision." }))); }
            public Task<ResultadoDeAccion> RestaurarAsync(string token, CancellationToken ct)
            { Llamadas.Add("restaurar"); Token = token; Elementos.RemoveAt(0); return Task.FromResult(new ResultadoDeAccion(true, false, "Archivo restaurado.")); }
            public Task<Consulta<PlanDelServicio>> PrevisualizarPurgaAsync(CancellationToken ct)
            { Llamadas.Add("previsualizar-purga"); return Task.FromResult(Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Purgar 1", true, TokenDePlan, Array.Empty<string>()))); }
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

            Consulta<PlanDelServicio> plan = m.PrevisualizarRestauracionAsync().GetAwaiter().GetResult();
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
            Consulta<PlanDelServicio> purga = m.PrevisualizarPurgaAsync().GetAwaiter().GetResult();
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

        // ============================================================ Firewall
        private const string EstadoDeFirewallJson =
            "{\"reglas_de_nexo\":[{\"nombre\":\"Nexo: bloquear app.exe (salida)\",\"accion\":\"Bloquear\",\"direccion\":\"Saliente\",\"ruta\":\"C:\\\\Program Files\\\\Ejemplo\\\\app.exe\",\"habilitada\":true}," +
            "{\"nombre\":\"Nexo: sigiloso ICMPv4\",\"accion\":\"Bloquear\",\"direccion\":\"Entrante\",\"habilitada\":true}]," +
            "\"sigiloso\":true,\"perfiles\":[{\"perfil\":\"Dominio\",\"activo\":true,\"entrada_por_defecto\":\"Bloquear\"}," +
            "{\"perfil\":\"Privado\",\"activo\":true,\"entrada_por_defecto\":\"Permitir\"},{\"perfil\":\"Publico\",\"activo\":false,\"entrada_por_defecto\":\"Bloquear\"}]}";

        private sealed class FirewallFalso : IServicioDeFirewall
        {
            public Consulta<DetalleDeFirewall> AlLeer = LectorDeFirewall.Estado(Json(EstadoDeFirewallJson));
            public int Lecturas;
            public readonly System.Collections.Generic.List<string> Llamadas = new System.Collections.Generic.List<string>();
            public string? Token;
            public readonly string TokenDePlan = new string('d', 64);

            public Task<Consulta<DetalleDeFirewall>> EstadoAsync(CancellationToken ct) { Lecturas++; return Task.FromResult(AlLeer); }
            public Task<Consulta<PlanDelServicio>> PrevisualizarBloqueoAsync(string r, DireccionPedida d, CancellationToken ct)
            { Llamadas.Add("bloquear:" + r + ":" + d); return Plan(); }
            public Task<Consulta<PlanDelServicio>> PrevisualizarQuitarAsync(string n, CancellationToken ct)
            { Llamadas.Add("quitar:" + n); return Plan(); }
            public Task<Consulta<PlanDelServicio>> PrevisualizarSigilosoAsync(bool a, CancellationToken ct)
            { Llamadas.Add("sigiloso:" + a); return Plan(); }
            public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct)
            { Llamadas.Add("aplicar"); Token = token; return Task.FromResult(new ResultadoDeAccion(true, false, "1 cambios aplicados. ")); }
            private Task<Consulta<PlanDelServicio>> Plan()
                => Task.FromResult(Consulta<PlanDelServicio>.Bien(new PlanDelServicio("Plan", true, TokenDePlan, Array.Empty<string>())));
        }

        private static void ProbarFirewall()
        {
            Console.WriteLine("== Firewall: lector y modelo de la pestaña");

            var e = LectorDeFirewall.Estado(Json(EstadoDeFirewallJson));
            Check(e.Valor is { Sigiloso: true } && e.Valor.Reglas.Count == 2 && e.Valor.Reglas[0].Ruta == @"C:\Program Files\Ejemplo\app.exe"
                  && e.Valor.Reglas[1].Ruta is null && e.Valor.Perfiles[1].EntradaPorDefecto == "Permitir",
                "firewall.estado completo: reglas (con y sin programa) y perfiles");
            var rota = LectorDeFirewall.Estado(Json("{\"reglas_de_nexo\":[{\"nombre\":\"Nexo: x\",\"accion\":\"Bloquear\",\"direccion\":\"Saliente\"}],\"sigiloso\":false,\"perfiles\":[]}"));
            Check(rota.Valor is null && rota.Error is not null, "una regla sin «habilitada» invalida la respuesta");

            string ambas = JsonSerializer.Serialize(LectorDeFirewall.ParametrosDeBloqueo(@"C:\a.exe", DireccionPedida.Ambas));
            string sal = JsonSerializer.Serialize(LectorDeFirewall.ParametrosDeBloqueo(@"C:\a.exe", DireccionPedida.Saliente));
            Check(ambas.Contains("\"tipo\":\"regla\"") && ambas.Contains("\"accion\":\"bloquear\"") && !ambas.Contains("direccion"),
                "bloquear en las dos direcciones: sin «direccion» (asi lo pide el servicio)", ambas);
            Check(sal.Contains("\"direccion\":\"saliente\""), "solo saliente: «direccion»: «saliente»", sal);

            var rechazo = LectorDeEscaneo.Plan(Json(
                "{\"descripcion\":\"Bloquear svchost.exe\\n  RECHAZADO: es un proceso del sistema\\n\",\"hay_cambios\":false,\"cambios\":[],\"rechazos\":[\"es un proceso del sistema\"],\"advertencias\":[]}"));
            Check(rechazo.Valor is { HayCambios: false, Token: null } && rechazo.Valor.Descripcion.Contains("RECHAZADO"),
                "un plan de firewall rechazado: sin token, y la descripcion dice por que");

            var s = new FirewallFalso();
            var m = new FirewallModelo(s);
            Check(!m.PuedeBloquear && !m.PuedeCambiarSigiloso && m.Sigiloso is null, "antes de leer no se ofrece ninguna accion");
            Check(m.PrevisualizarSigilosoAsync().GetAwaiter().GetResult().Valor is null && s.Llamadas.Count == 0,
                "sin saber como esta el sigiloso no se pide cambiarlo");

            Esperar(m.ActualizarAsync());
            Check(m.Leido && m.Perfiles.Count == 3 && m.Reglas.Count == 2, "lee perfiles y reglas");
            FilaDePerfil publico = m.Perfiles.Single(p => p.Perfil == "Público");
            Check(publico.Estado == "DESACTIVADO" && m.Resumen.Contains("DESACTIVADO en 1 perfil") && m.Resumen.Contains("solo avisa"),
                "un perfil apagado: se dice, y que Nexo no lo enciende", m.Resumen);
            Check(m.Perfiles.Single(p => p.Perfil == "Privado").Entrada.Contains("PERMITE"), "un perfil que permite lo entrante por defecto, se marca");
            Check(m.TextoBotonSigiloso == "Desactivar modo sigiloso..." && m.PuedeCambiarSigiloso && m.PuedeBloquear && !m.PuedeQuitar,
                "con el sigiloso activado se ofrece desactivarlo; sin seleccion no se puede quitar");

            Check(m.PrevisualizarSigilosoAsync().GetAwaiter().GetResult().Valor is not null && s.Llamadas.Last() == "sigiloso:False",
                "cambiar el sigiloso pide lo contrario de como esta");
            Check(m.PrevisualizarQuitarAsync().GetAwaiter().GetResult().Valor is null && s.Llamadas.Count == 1, "quitar sin seleccion: no se pide nada");
            m.Seleccionada = m.Reglas[0];
            Check(m.PuedeQuitar, "con una regla elegida se puede quitar");
            m.PrevisualizarQuitarAsync().GetAwaiter().GetResult();
            Check(s.Llamadas.Last() == "quitar:Nexo: bloquear app.exe (salida)", "quitar pide la regla elegida por su nombre", s.Llamadas.Last());
            Esperar(m.ActualizarAsync());
            Check(m.Seleccionada?.Nombre == "Nexo: bloquear app.exe (salida)", "al volver a leer, la seleccion se mantiene");

            Check(m.PrevisualizarBloqueoAsync("  ").GetAwaiter().GetResult().Valor is null && !s.Llamadas.Any(l => l.StartsWith("bloquear")),
                "bloquear sin programa: no se pide nada");
            m.DireccionElegida = 1;
            m.PrevisualizarBloqueoAsync(@"C:\Juegos\updater.exe").GetAwaiter().GetResult();
            Check(s.Llamadas.Last() == @"bloquear:C:\Juegos\updater.exe:Saliente", "bloquear pide el programa y la direccion elegidos", s.Llamadas.Last());
            Check(!s.Llamadas.Contains("aplicar"), "previsualizar nunca aplica");

            int antes = s.Lecturas;
            ResultadoDeAccion r = m.AplicarAsync(s.TokenDePlan).GetAwaiter().GetResult();
            Check(r.Exito && s.Token == s.TokenDePlan && m.Mensaje.StartsWith("1 cambios aplicados") && s.Lecturas == antes + 1,
                "aplicar manda el token, muestra el resultado y vuelve a leer");

            s.AlLeer = Consulta<DetalleDeFirewall>.Mal("el servicio no está en marcha");
            Esperar(m.ActualizarAsync());
            Check(!m.Leido && m.Reglas.Count == 0 && m.Perfiles.Count == 0 && m.Sigiloso is null && !m.PuedeBloquear && !m.PuedeCambiarSigiloso
                  && m.TextoSigiloso == "Sin datos." && m.Resumen.StartsWith("No se pudo leer el firewall"),
                "si no se puede leer: nada viejo en pantalla y ninguna accion ofrecida", m.Resumen);

            var s2 = new FirewallFalso { AlLeer = LectorDeFirewall.Estado(Json(EstadoDeFirewallJson.Replace("\"sigiloso\":true", "\"sigiloso\":false"))) };
            var m2 = new FirewallModelo(s2);
            Esperar(m2.ActualizarAsync());
            m2.PrevisualizarSigilosoAsync().GetAwaiter().GetResult();
            Check(m2.TextoBotonSigiloso == "Activar modo sigiloso..." && s2.Llamadas.Last() == "sigiloso:True", "con el sigiloso apagado se ofrece activarlo");

            var sinServicio = new FirewallModelo(Fuentes.FirewallPorDefecto("NexoIpc"));
            Esperar(sinServicio.ActualizarAsync());
            Check(!sinServicio.Leido && !sinServicio.PuedeBloquear, "sin servicio (esta compilacion): no se pudo leer y no se ofrece nada");
        }

        // ============================================================ Limpieza
        private const string ReglasJson =
            "{\"modo\":\"papelera\",\"reversible\":true,\"reglas\":[" +
            "{\"id\":\"temp-usuario\",\"nombre\":\"Archivos temporales del usuario\",\"categoria\":\"temporales\",\"riesgo\":\"Bajo\",\"requiere_admin\":false,\"activa_por_defecto\":true}," +
            "{\"id\":\"cache-edge\",\"nombre\":\"Caché de Edge\",\"categoria\":\"navegadores\",\"riesgo\":\"Medio\",\"requiere_admin\":false,\"activa_por_defecto\":false}," +
            "{\"id\":\"windows-update\",\"nombre\":\"Descargas de Windows Update\",\"categoria\":\"sistema\",\"riesgo\":\"Bajo\",\"requiere_admin\":true,\"activa_por_defecto\":true}]}";

        private static string VistaJson(int archivos = 2314, bool conToken = true, string expira = "2026-11-05T12:10:00+00:00")
            => "{\"total_archivos\":" + archivos + ",\"total_bytes\":1932735283,\"reversible\":true," +
               "\"categorias\":[{\"categoria\":\"temporales\",\"archivos\":1482,\"bytes\":956301312},{\"categoria\":\"sistema\",\"archivos\":832,\"bytes\":976433971}]," +
               "\"ejemplos\":[{\"ruta\":\"C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\setup.tmp\",\"bytes\":104857600,\"categoria\":\"temporales\"}]," +
               "\"omitidas\":[\"C:\\\\x.tmp — en uso\",\"C:\\\\y.tmp — en uso\"],\"omitidas_total\":3,\"reglas_sin_permisos\":[\"windows-update\"]" +
               (conToken ? ",\"token\":\"" + new string('e', 64) + "\",\"expira\":\"" + expira + "\"" : "") + "}";

        private sealed class LimpiezaFalsa : IServicioDeLimpieza
        {
            public Consulta<CatalogoDeLimpieza> AlLeer = LectorDeLimpieza.Reglas(Json(ReglasJson));
            public Consulta<VistaDeLimpieza> AlPrevisualizar = LectorDeLimpieza.Vista(Json(VistaJson()));
            public int Catalogos, Vistas;
            public System.Collections.Generic.IReadOnlyList<string>? ReglasPedidas;
            public readonly System.Collections.Generic.List<string> Tokens = new System.Collections.Generic.List<string>();

            public Task<Consulta<CatalogoDeLimpieza>> ReglasAsync(CancellationToken ct) { Catalogos++; return Task.FromResult(AlLeer); }
            public Task<Consulta<VistaDeLimpieza>> PrevisualizarAsync(System.Collections.Generic.IReadOnlyList<string> reglas, CancellationToken ct)
            { Vistas++; ReglasPedidas = reglas; return Task.FromResult(AlPrevisualizar); }
            public Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct)
            { Tokens.Add(token); return Task.FromResult(new ResultadoDeAccion(true, false, "2311 archivos limpiados (1.8 GB). 3 omitidos.")); }
        }

        private static void ProbarLimpieza()
        {
            Console.WriteLine("== Limpieza: lector y modelo de la pestaña");

            var c = LectorDeLimpieza.Reglas(Json(ReglasJson));
            Check(c.Valor is { Modo: "papelera", Reversible: true } && c.Valor.Reglas.Count == 3 && c.Valor.Reglas[2].RequiereAdmin, "limpieza.reglas: modo y catalogo");
            var v = LectorDeLimpieza.Vista(Json(VistaJson()));
            Check(v.Valor is { TotalArchivos: 2314, OmitidasTotal: 3 } && v.Valor.Token!.Length == 64 && v.Valor.Expira is not null
                  && v.Valor.Categorias.Count == 2 && v.Valor.ReglasSinPermisos.Count == 1, "limpieza.previsualizar completa, con token y caducidad");
            v = LectorDeLimpieza.Vista(Json(VistaJson(archivos: 0, conToken: false)));
            Check(v.Valor is { TotalArchivos: 0, Token: null, Expira: null }, "sin archivos no hay token (el servicio lo omite)");
            v = LectorDeLimpieza.Vista(Json(VistaJson().Replace(",\"reglas_sin_permisos\":[\"windows-update\"]", "")));
            Check(v.Valor is null && v.Error is not null, "sin «reglas_sin_permisos»: no se interpreta a medias");

            var s = new LimpiezaFalsa();
            var m = new LimpiezaModelo(s, () => Hoy);
            Check(!m.PuedePrevisualizar && !m.PuedeLimpiar, "antes de leer el catalogo no se ofrece nada");
            Esperar(m.CargarReglasAsync());
            Check(m.CatalogoLeido && m.Reglas.Count == 3 && m.Reglas[0].Marcada && !m.Reglas[1].Marcada && m.Reglas[2].Marcada,
                "catalogo leido: marcadas solo las de riesgo bajo");
            Check(m.TextoModo.Contains("Papelera") && m.TextoBotonLimpiar == "Mover a la Papelera" && !m.ModoPermanente, "el modo lo dice el servicio: Papelera");
            Check(m.Reglas[2].Detalle.Contains("requiere administrador") && m.Reglas[1].Detalle.Contains("riesgo medio"), "cada regla dice su riesgo y si pide administrador");
            Esperar(m.CargarReglasAsync());
            Check(s.Catalogos == 1, "el catalogo se lee una sola vez");

            Esperar(m.PrevisualizarAsync());
            Check(s.ReglasPedidas!.SequenceEqual(new[] { "temp-usuario", "windows-update" }), "la vista previa pide solo las reglas marcadas, por id");
            Check(m.TituloVista == "Se liberarían 1.8 GB (2314 archivos)." && m.DetalleVista.Contains("Todavía no se ha borrado nada") && m.DetalleVista.Contains("vale hasta las"),
                "la vista previa dice cuanto y que no se borro nada", m.TituloVista);
            Check(m.Avisos.Any(a => a.Contains("3 archivos se omitirán") && a.Contains("se muestran 2")) && m.Avisos.Any(a => a.Contains("Sin permisos para evaluar: windows-update")),
                "avisa de los omitidos (y del recorte) y de las reglas sin permisos");
            Check(m.PuedeEscribirConfirmacion && !m.PuedeLimpiar, "con vista previa se puede escribir BORRAR, pero aun no limpiar");
            m.Confirmacion = "borrar";
            Check(!m.PuedeLimpiar, "«borrar» en minusculas no vale");
            m.Confirmacion = "BORRAR";
            Check(m.PuedeLimpiar, "con BORRAR, si");

            m.Reglas[1].Marcada = true;
            Check(m.Vista is null && !m.PuedeLimpiar && m.Confirmacion == "" && m.Mensaje.Contains("Cambió la selección"),
                "cambiar una casilla despues de la vista previa la invalida y borra la confirmacion", m.Mensaje);
            Check(m.LimpiarAsync().GetAwaiter().GetResult() is null && s.Tokens.Count == 0, "sin vista previa vigente no se limpia nada");

            Esperar(m.PrevisualizarAsync());
            Check(s.ReglasPedidas!.Count == 3, "la nueva vista previa incluye la regla recien marcada");
            m.Confirmacion = "BORRAR";
            ResultadoDeAccion? r = m.LimpiarAsync().GetAwaiter().GetResult();
            Check(r is { Exito: true } && s.Tokens.SequenceEqual(new[] { new string('e', 64) }) && m.Mensaje.StartsWith("2311 archivos limpiados"),
                "limpiar manda el token de la vista previa y muestra el resultado");
            Check(m.Vista is null && !m.PuedeLimpiar && m.Confirmacion == "", "despues de limpiar, la vista previa ya no sirve (token de un solo uso)");
            Check(m.LimpiarAsync().GetAwaiter().GetResult() is null && s.Tokens.Count == 1, "no se puede limpiar dos veces con la misma vista previa");

            foreach (FilaDeReglaDeLimpieza f in m.Reglas) f.Marcada = false;
            Check(!m.PuedePrevisualizar, "sin nada marcado no se puede previsualizar");

            // Caducada.
            var s2 = new LimpiezaFalsa();
            DateTimeOffset ahora = Hoy;
            var m2 = new LimpiezaModelo(s2, () => ahora);
            Esperar(m2.CargarReglasAsync());
            Esperar(m2.PrevisualizarAsync());
            m2.Confirmacion = "BORRAR";
            ahora = Hoy.AddMinutes(11);
            Check(m2.LimpiarAsync().GetAwaiter().GetResult() is null && s2.Tokens.Count == 0 && m2.Mensaje.Contains("caducó"),
                "una vista previa caducada no se manda: hay que pedir otra", m2.Mensaje);

            // Nada que limpiar.
            var s3 = new LimpiezaFalsa { AlPrevisualizar = LectorDeLimpieza.Vista(Json(VistaJson(archivos: 0, conToken: false))) };
            var m3 = new LimpiezaModelo(s3, () => Hoy);
            Esperar(m3.CargarReglasAsync());
            Esperar(m3.PrevisualizarAsync());
            Check(m3.TituloVista == "No hay nada que limpiar en lo marcado." && !m3.PuedeEscribirConfirmacion, "sin archivos: lo dice y no ofrece confirmar");

            // Modo permanente.
            var s4 = new LimpiezaFalsa { AlLeer = LectorDeLimpieza.Reglas(Json(ReglasJson.Replace("\"modo\":\"papelera\",\"reversible\":true", "\"modo\":\"borrado-permanente\",\"reversible\":false"))) };
            var m4 = new LimpiezaModelo(s4, () => Hoy);
            Esperar(m4.CargarReglasAsync());
            Check(m4.ModoPermanente && m4.TextoBotonLimpiar == "Borrar para siempre" && m4.TextoModo.Contains("PERMANENTE"), "modo permanente: se avisa y el boton lo dice");

            // El catalogo no se puede leer.
            var s5 = new LimpiezaFalsa { AlLeer = Consulta<CatalogoDeLimpieza>.Mal("no se encontro el perfil del usuario") };
            var m5 = new LimpiezaModelo(s5, () => Hoy);
            Esperar(m5.CargarReglasAsync());
            Check(!m5.CatalogoLeido && !m5.PuedePrevisualizar && m5.Mensaje.Contains("no se encontro el perfil"), "sin catalogo: lo dice y no ofrece nada", m5.Mensaje);
            s5.AlLeer = LectorDeLimpieza.Reglas(Json(ReglasJson));
            Esperar(m5.CargarReglasAsync());
            Check(m5.CatalogoLeido && s5.Catalogos == 2, "si fallo, se vuelve a intentar al entrar otra vez");
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

        // ============================================================ Tiempo real
        // La forma de ModuloTiempoReal (encendido) y de ModuloTiempoRealApagado, en src/Nexo.Service/ModuloTiempoReal.cs.
        private static string EstadoTrJson(bool cobertura = true, bool motorCaido = false, string porRevisar = "", string noVigiladas = "",
                                           bool minimo = false)
            => "{\"activo\":true,\"cobertura_completa\":" + (cobertura ? "true" : "false") +
               ",\"raices\":[\"C:\\\\Users\\\\u\\\\Downloads\",\"C:\\\\Users\\\\u\\\\Desktop\",\"C:\\\\Windows\\\\Temp\"]" +
               ",\"raices_no_vigiladas\":[" + noVigiladas + "],\"motor\":\"clamd 127.0.0.1:3310\",\"motor_caido\":" + (motorCaido ? "true" : "false") +
               ",\"cambios_vistos\":5021,\"analizados\":4004,\"no_analizados\":3,\"perdidos\":1017,\"perdidos_es_minimo\":" + (minimo ? "true" : "false") +
               ",\"desbordes_de_fuente\":0,\"por_revisar\":[" + porRevisar + "],\"descartados\":12,\"pendientes\":2,\"detecciones\":0" +
               ",\"ultimo_aviso\":null,\"nota\":\"Detecta y avisa DESPUES de que el archivo se escribe; no puede impedir que se cree ni que se ejecute.\"}";

        private const string ApagadoTrJson =
            "{\"activo\":false,\"cobertura_completa\":false,\"nota\":\"El analisis en tiempo real esta apagado. Se activa en appsettings.json (Nexo:TiempoReal:Activo).\"}";

        private const string SinDeteccionesTrJson = "{\"id_escaneo\":\"tiempo-real\",\"detecciones\":[]}";

        private const string DeteccionesTrJson =
            "{\"id_escaneo\":\"tiempo-real\",\"detecciones\":[{\"ruta\":\"C:\\\\Users\\\\u\\\\Downloads\\\\factura.exe\",\"firma\":\"Win.Test.EICAR_HDB-1\"," +
            "\"bytes\":68,\"sha256\":\"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\",\"modificado\":\"2026-11-05T11:58:00+00:00\"}]}";

        private static Consulta<DetalleDeTiempoReal> Tr(string estado, string detecciones = SinDeteccionesTrJson)
            => LectorDeTiempoReal.Leer(Json(estado), Json(detecciones));

        private sealed class TiempoRealFalso : IServicioDeTiempoReal
        {
            public Consulta<DetalleDeTiempoReal> Valor = Tr(EstadoTrJson());
            public int Consultas;
            public Task<Consulta<DetalleDeTiempoReal>> ConsultarAsync(CancellationToken ct) { Consultas++; return Task.FromResult(Valor); }
        }

        private static void ProbarTiempoReal()
        {
            Console.WriteLine("== Tiempo real: lector, resumen y modelo de la pestaña");

            // ---- lector
            var bien = Tr(EstadoTrJson(), DeteccionesTrJson);
            Check(bien.Valor is { Activo: true, CoberturaCompleta: true, Raices.Count: 3, Perdidos: 1017, Pendientes: 2, Motor: "clamd 127.0.0.1:3310" }
                  && bien.Valor.Detecciones.Count == 1 && bien.Valor.Detecciones[0] is { Bytes: 68, Firma: "Win.Test.EICAR_HDB-1", Modificado: not null },
                "tiempo-real.estado + detecciones: todo leido", bien.Error);
            var apagado = Tr(ApagadoTrJson);
            Check(apagado.Valor is { Activo: false, CoberturaCompleta: false, Raices.Count: 0 } && apagado.Valor.Nota!.Contains("appsettings"),
                "apagado: el servicio solo manda activo, cobertura y nota, y se lee igual", apagado.Error);
            Check(Tr(EstadoTrJson(cobertura: true, porRevisar: "\"C:\\\\Users\\\\u\\\\Downloads\"")).Valor is { CoberturaCompleta: false },
                "si dice cobertura completa pero hay carpetas por revisar, NO es completa");
            Check(Tr(EstadoTrJson(cobertura: true, noVigiladas: "\"D:\\\\\"")).Valor is { CoberturaCompleta: false }
                  && Tr(EstadoTrJson(cobertura: true, motorCaido: true)).Valor is { CoberturaCompleta: false },
                "ni con carpetas sin vigilar ni con el motor caido");
            var sinCampo = Tr(EstadoTrJson().Replace(",\"por_revisar\":[]", ""));
            Check(sinCampo.Valor is null && sinCampo.Error == "respuesta del servicio no reconocida",
                "encendido sin «por_revisar»: no se interpreta a medias", sinCampo.Error);
            var detMal = LectorDeTiempoReal.Leer(Json(EstadoTrJson()), new RespuestaCruda(false, "metodo desconocido", null));
            Check(detMal.Valor is null && detMal.Error == "metodo desconocido", "si fallan las detecciones, no se muestra el estado solo");
            Check(Tr(EstadoTrJson(), "{\"id_escaneo\":\"tiempo-real\",\"detecciones\":[{\"firma\":\"X\",\"bytes\":1}]}").Valor is null,
                "una deteccion sin ruta invalida la respuesta");

            // ---- resumen
            var (ind, titulo, _) = ResumirTiempoReal.Desde(Tr(EstadoTrJson(motorCaido: true), DeteccionesTrJson));
            Check(ind == Indicador.Alerta && titulo == "1 detección del tiempo real.", "una deteccion manda sobre el motor caido", titulo);
            (ind, titulo, string expl) = ResumirTiempoReal.Desde(apagado);
            Check(ind == Indicador.Atencion && titulo.Contains("apagado") && expl.Contains("appsettings.json"), "apagado: atencion y como se activa", expl);
            (ind, titulo, _) = ResumirTiempoReal.Desde(Tr(EstadoTrJson(motorCaido: true)));
            Check(ind == Indicador.Atencion && titulo.Contains("motor"), "motor caido: atencion", titulo);
            (ind, titulo, _) = ResumirTiempoReal.Desde(Tr(EstadoTrJson(cobertura: false, porRevisar: "\"C:\\\\a\",\"C:\\\\b\"", noVigiladas: "\"D:\\\\\"")));
            Check(ind == Indicador.Atencion && titulo == "Cobertura incompleta: 1 carpeta sin vigilar, 2 carpetas por revisar.", "incompleta: dice por que", titulo);
            (ind, titulo, expl) = ResumirTiempoReal.Desde(bien with { Valor = bien.Valor! with { Detecciones = Array.Empty<DeteccionDeTiempoReal>() } });
            Check(ind == Indicador.Correcto && titulo.StartsWith("Vigilando 3 carpetas") && !titulo.Contains("todo en orden") && expl.Contains("después"),
                "completa: vigilando, y recuerda que avisa despues de escribir (nunca «todo en orden»)", titulo);
            (ind, titulo, _) = ResumirTiempoReal.Desde(Consulta<DetalleDeTiempoReal>.Mal("el servicio no está en marcha"));
            Check(ind == Indicador.SinDatos && titulo.StartsWith("No se pudo"), "sin respuesta: sin datos, no «apagado» ni «bien»");
            Check(ResumirTiempoReal.Contadores(Tr(EstadoTrJson(minimo: true)).Valor!).Contains("Perdidos: 1 017 (al menos)"),
                "los perdidos con tope se dicen como minimo");

            // ---- modelo
            var s = new TiempoRealFalso
            {
                Valor = Tr(EstadoTrJson(cobertura: false, porRevisar: "\"C:\\\\Users\\\\u\\\\Downloads\\\\x\",\"C:\\\\Users\\\\u\\\\Downloads\"",
                                        noVigiladas: "\"C:\\\\Windows\\\\Temp\""), DeteccionesTrJson)
            };
            var esc = new EscaneoFalso();
            var m = new TiempoRealModelo(s, esc);
            Check(m.Titulo == "Sin consultar todavía." && !m.PuedePonerEnCuarentena && !m.PuedeRevisar, "antes de leer: sin datos y sin acciones");
            Esperar(m.ActualizarAsync());
            Check(m.Detecciones.Count == 1 && m.PuedePonerEnCuarentena && m.PuedeRevisar && m.PorRevisar.Count == 2, "lee detecciones y carpetas por revisar");
            Check(m.Carpetas.Count == 3 && m.Carpetas.Single(c => c.Ruta == @"C:\Windows\Temp").Estado == "NO vigilada"
                  && m.Carpetas.Count(c => c.Estado == "Vigilada") == 2, "la carpeta que la fuente no pudo vigilar se marca");
            Check(m.RutasParaRevisar().SequenceEqual(new[] { @"C:\Users\u\Downloads" }), "revisar pide la carpeta de arriba una sola vez");
            Check(m.Motor.Contains("responde") && m.Nota.Contains("DESPUES"), "motor y la nota del servicio, siempre visibles");

            Consulta<PlanDelServicio> plan = m.PrevisualizarCuarentenaAsync().GetAwaiter().GetResult();
            Check(plan.Valor is not null && esc.Llamadas.SequenceEqual(new[] { "previsualizar:tiempo-real" }),
                "la cuarentena se previsualiza con el id «tiempo-real», y nada mas");
            int antes = s.Consultas;
            ResultadoDeAccion r = m.AplicarCuarentenaAsync(plan.Valor!.Token!).GetAwaiter().GetResult();
            Check(r.Exito && esc.TokenAplicado == plan.Valor.Token && s.Consultas == antes + 1 && m.Mensaje == r.Mensaje,
                "aplicar manda el token del plan, muestra el resultado y vuelve a leer");

            s.Valor = Consulta<DetalleDeTiempoReal>.Mal("el servicio no está en marcha");
            Esperar(m.ActualizarAsync());
            Check(m.Detecciones.Count == 0 && m.Carpetas.Count == 0 && m.PorRevisar.Count == 0 && !m.PuedePonerEnCuarentena && !m.PuedeRevisar
                  && m.Titulo.StartsWith("No se pudo"), "si la lectura falla, no se muestra lo anterior ni se ofrece nada", m.Titulo);
            Check(m.PrevisualizarCuarentenaAsync().GetAwaiter().GetResult().Valor is null && esc.Llamadas.Count(x => x.StartsWith("previsualizar")) == 1,
                "sin datos no se pide cuarentena al servicio");

            var muchas = new TiempoRealFalso { Valor = Tr(EstadoTrJson(cobertura: false,
                porRevisar: string.Join(",", Enumerable.Range(0, 12).Select(i => "\"C:\\\\d" + i + "\"")))) };
            var mm = new TiempoRealModelo(muchas, new EscaneoFalso());
            Esperar(mm.ActualizarAsync());
            Check(mm.RutasParaRevisar().Count == RevisionDeLoNoVisto.MaxRutasPorEscaneo && mm.TextoPorRevisar.Contains("Se revisan 8 por pasada"),
                "con 12 por revisar se piden 8 y se dice", mm.TextoPorRevisar);

            // ---- la revision es un escaneo normal
            var e2 = new EscaneoFalso();
            var em = ModeloDeEscaneo(e2);
            bool lanzado = em.IniciarRevisionAsync(new[] { @"C:\Users\u\Downloads", @"C:\d1" }).GetAwaiter().GetResult();
            Check(lanzado && em.Fase == FaseDeEscaneo.Corriendo && e2.RutasPedidas!.SequenceEqual(new[] { @"C:\Users\u\Downloads", @"C:\d1" })
                  && em.DestinoDescargas, "revisar lanza escaneo.iniciar con esas carpetas, sin cambiar lo elegido en «Escaneo»");
            e2.Avances.Enqueue(Avance("corriendo", 10));
            Esperar(em.SondearAsync());
            Check(em.Mensaje.StartsWith("Revisando lo que el tiempo real no vio"), "mientras corre, dice que es la revision", em.Mensaje);
            Check(!em.IniciarRevisionAsync(new[] { @"C:\x" }).GetAwaiter().GetResult() && e2.Llamadas.Count(x => x == "iniciar") == 1,
                "con un escaneo en curso no se lanza otro");

            var sinServicio = new TiempoRealModelo(Fuentes.TiempoRealPorDefecto("NexoIpc"), Fuentes.EscaneoPorDefecto("NexoIpc"));
            Esperar(sinServicio.ActualizarAsync());
            Check(sinServicio.Titulo.StartsWith("No se pudo") && !sinServicio.PuedeRevisar, "sin servicio (esta compilacion): no se pudo, no «apagado»");
        }

        // ============================================================ Disco
        private sealed class SmartFalsa : Nexo.Modules.Cleanup.Disco.IFuenteSmart
        {
            public System.Collections.Generic.List<Nexo.Modules.Cleanup.Disco.LecturaDeDisco> Discos = new System.Collections.Generic.List<Nexo.Modules.Cleanup.Disco.LecturaDeDisco>();
            public Exception? Fallar;
            public int Lecturas;
            public System.Collections.Generic.IReadOnlyList<Nexo.Modules.Cleanup.Disco.LecturaDeDisco> Leer()
            {
                Lecturas++;
                if (Fallar is not null) throw Fallar;
                return Discos.ToList();
            }
        }

        private sealed class NotasEnMemoria : Nexo.Reports.IReportWriter
        {
            public int Notas;
            public Task<Nexo.Reports.Model.NoteRef> EscribirAsync(Nexo.Reports.Model.NexoEvent evento, CancellationToken ct = default)
            { Notas++; return Task.FromResult(new Nexo.Reports.Model.NoteRef(evento.Id, "(memoria)", evento.Titulo, false)); }
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        private static Nexo.Modules.Cleanup.Disco.LecturaDeDisco Sata(string modelo, ulong pendientes = 0)
            => new Nexo.Modules.Cleanup.Disco.LecturaDeDisco(modelo, "****1A2B")
            {
                PrediccionDeFallo = false,
                Atributos = new[]
                {
                    new Nexo.Modules.Cleanup.Disco.AtributoSmart(5, 0, 100, 100, 0), new Nexo.Modules.Cleanup.Disco.AtributoSmart(9, 0, 90, 90, 12345),
                    new Nexo.Modules.Cleanup.Disco.AtributoSmart(197, 0, 100, 100, pendientes)
                },
                TemperaturaC = 38,
                HorasEncendido = 12345
            };

        private static Nexo.Modules.Cleanup.Disco.LecturaDeDisco Nvme()
            => new Nexo.Modules.Cleanup.Disco.LecturaDeDisco("NVMe Rapido 512", "****9F00")
            {
                TemperaturaC = 41, DesgastePorcentaje = 3, HorasEncendido = 800,
                Limitaciones = new[] { "NVMe: no expone atributos ATA; se usan los contadores de fiabilidad de Storage." }
            };

        private static Nexo.Modules.Cleanup.Disco.LecturaDeDisco Usb()
            => new Nexo.Modules.Cleanup.Disco.LecturaDeDisco("USB Pendrive", "sin-serie")
            { Limitaciones = new[] { "Puente USB: normalmente no pasa los comandos S.M.A.R.T." } };

        /// <summary>disco.estado tal como lo manda el servicio: VigiaDeSalud.ParaJson con las opciones del pipe (sin nulos).</summary>
        private static Consulta<EstadoDeDiscos> DiscoPorPipe(Nexo.Modules.Cleanup.Disco.VigiaDeSalud v)
            => LectorDeDisco.Estado(Json(JsonSerializer.Serialize(Nexo.Modules.Cleanup.Disco.VigiaDeSalud.ParaJson(v.Estado()),
                new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull })));

        private static (Nexo.Modules.Cleanup.Disco.VigiaDeSalud Vigia, SmartFalsa Fuente, Func<DateTimeOffset> Avanzar) Vigia(params Nexo.Modules.Cleanup.Disco.LecturaDeDisco[] discos)
        {
            var f = new SmartFalsa();
            f.Discos.AddRange(discos);
            DateTimeOffset ahora = Hoy;
            var v = new Nexo.Modules.Cleanup.Disco.VigiaDeSalud(new Nexo.Modules.Cleanup.Disco.MonitorDeSalud(f, new NotasEnMemoria()),
                                                               reloj: () => ahora);
            return (v, f, () => ahora = ahora.AddMinutes(6));
        }

        private sealed class DiscoFalso : IServicioDeDisco
        {
            public Consulta<EstadoDeDiscos> Valor = Consulta<EstadoDeDiscos>.Mal("sin datos de prueba");
            public Consulta<PedidoDeLectura> AlPedir = Consulta<PedidoDeLectura>.Bien(new PedidoDeLectura(true, "lectura iniciada"));
            public int Consultas, Pedidos;
            public Task<Consulta<EstadoDeDiscos>> EstadoAsync(CancellationToken ct) { Consultas++; return Task.FromResult(Valor); }
            public Task<Consulta<PedidoDeLectura>> PedirLecturaAsync(CancellationToken ct) { Pedidos++; return Task.FromResult(AlPedir); }
        }

        private static void ProbarDisco()
        {
            Console.WriteLine("== Disco: vigia del servicio, lector, resumen y modelo de la pestaña");

            // ---- el vigia (codigo del servicio) y su JSON leido por la ventana
            var (v, fuente, avanzar) = Vigia(Sata("Disco Sano"), Nvme(), Sata("Disco Viejo", pendientes: 3), Usb());
            Consulta<EstadoDeDiscos> c = DiscoPorPipe(v);
            Check(c.Valor is { Estado: "nunca", Leyendo: false, Discos.Count: 0 } && ResumirDisco.General(c).Estado == "Sin leer todavía",
                "antes de la primera lectura: «sin leer todavía», nunca «bien»", c.Error);
            Esperar(v.LeerAsync());
            c = DiscoPorPipe(v);
            Check(c.Valor is { Estado: "listo", Discos.Count: 4 } && c.Valor.UltimaLectura == Hoy && c.Valor.ProximaLectura == Hoy.AddHours(6),
                "tras leer: los 4 discos, la fecha y la proxima lectura (6 h)", c.Error);
            EstadoDeDiscos s = c.Valor!;
            var sano = ResumirDisco.Disco(s.Discos[0]);
            Check(sano.Indicador == Indicador.Correcto && sano.Detalle == "Se revisó la bandera de fallo y 2 de 5 atributos que anticipan fallos.",
                "un SATA sano: sin alertas, y dice que se reviso", sano.Detalle);
            var nvme = ResumirDisco.Disco(s.Discos[1]);
            Check(nvme.Indicador == Indicador.SinDatos && nvme.Estado == "Sin evaluar" && nvme.Detalle.Contains("la temperatura, el desgaste, las horas de uso"),
                "un NVMe con solo temperatura y desgaste: «sin evaluar», no «bien»", nvme.Detalle);
            var viejo = ResumirDisco.Disco(s.Discos[2]);
            Check(viejo.Indicador == Indicador.Alerta && viejo.Detalle.StartsWith("Sectores pendientes de reasignar (197): 3"),
                "197 > 0: alerta con la explicacion del evaluador", viejo.Detalle);
            var usb = ResumirDisco.Disco(s.Discos[3]);
            Check(usb.Indicador == Indicador.SinDatos && usb.Estado == "Sin datos" && usb.Detalle.Contains("Puente USB"),
                "un USB sin datos: «sin datos» con el motivo", usb.Detalle);
            Check(ResumirDisco.Temperatura(s.Discos[1]) == "41 °C" && ResumirDisco.Desgaste(s.Discos[0]) == "—" && ResumirDisco.Horas(s.Discos[0]) == "12 345 h",
                "temperatura, desgaste (o «—») y horas");
            var g = ResumirDisco.General(c);
            Check(g.Indicador == Indicador.Alerta && g.Estado == "1 disco con problemas" && g.Detalle.StartsWith("Disco Viejo:"),
                "en general manda el disco con problemas", g.Detalle);

            var (v2, _, _) = Vigia(Sata("Disco Sano"), Nvme());
            Esperar(v2.LeerAsync());
            g = ResumirDisco.General(DiscoPorPipe(v2));
            Check(g.Indicador == Indicador.Correcto && g.Detalle.StartsWith("1 de 2 discos revisados; 1 sin datos"), "uno sano y uno sin evaluar: lo dice", g.Detalle);
            var (v3, _, _) = Vigia(Nvme());
            Esperar(v3.LeerAsync());
            Check(ResumirDisco.General(DiscoPorPipe(v3)).Indicador == Indicador.SinDatos, "solo un NVMe sin atributos: sin datos, no correcto");
            var (v4, _, _) = Vigia();
            Esperar(v4.LeerAsync());
            Check(ResumirDisco.General(DiscoPorPipe(v4)).Estado == "Ningún disco", "sin discos: lo dice");

            // Limite de lecturas a pedido.
            Check(!v.PedirLectura(out string motivo) && motivo.Contains("menos de 5 minutos") && fuente.Lecturas == 1,
                "pedir otra lectura enseguida se niega y no lee", motivo);
            avanzar();
            Check(v.PedirLectura(out _), "pasados 5 minutos, si");
            for (int i = 0; i < 50 && v.Estado().Leyendo; i++) Thread.Sleep(20);
            Check(fuente.Lecturas == 2 && !v.Estado().Leyendo, "y lee una vez");

            // Una lectura que falla: los datos anteriores se quedan, con su fecha, y se dice.
            avanzar();
            fuente.Fallar = new InvalidOperationException("proveedor WMI roto");
            Esperar(v.LeerAsync());
            c = DiscoPorPipe(v);
            Check(c.Valor is { Estado: "fallido", Discos.Count: 4 } && c.Valor.Error!.Contains("proveedor WMI roto") && c.Valor.UltimaLectura < Hoy.AddMinutes(12),
                "lectura fallida: estado «fallido», el motivo y los datos anteriores con su fecha", c.Valor?.Error);
            g = ResumirDisco.General(c);
            Check(g.Indicador == Indicador.Alerta && g.Detalle.StartsWith("La última lectura falló"), "con un disco en alerta, sigue en alerta y dice que fallo", g.Detalle);
            var (v5, f5, av5) = Vigia(Sata("Disco Sano"));
            Esperar(v5.LeerAsync());
            av5();
            f5.Fallar = new InvalidOperationException("x");
            Esperar(v5.LeerAsync());
            g = ResumirDisco.General(DiscoPorPipe(v5));
            Check(g.Indicador == Indicador.Atencion && g.Estado == "Falló la lectura", "sano pero la ultima lectura fallo: atencion, no «sin alertas»", g.Estado);

            // ---- el lector con respuestas raras
            Check(LectorDeDisco.Estado(Json("{\"estado\":\"listo\",\"leyendo\":false,\"discos\":[{\"modelo\":\"X\",\"sin_datos\":false,\"atributos_leidos\":1," +
                                            "\"atributos_clave_leidos\":[5],\"severidad\":\"rarisima\",\"alertas\":[],\"limitaciones\":[]}]}")).Valor is null,
                "una severidad desconocida no se interpreta");
            Check(LectorDeDisco.Estado(Json("{\"estado\":\"listo\",\"leyendo\":false,\"discos\":[{\"sin_datos\":true}]}")).Valor is null, "un disco sin modelo invalida la respuesta");
            Check(LectorDeDisco.Estado(new RespuestaCruda(false, "metodo desconocido", null)).Error == "metodo desconocido", "un error del servicio, tal cual");
            var apagado = LectorDeDisco.Estado(Json("{\"estado\":\"apagado\",\"leyendo\":false,\"discos\":[],\"error\":\"La salud del disco está apagada en appsettings.json (Nexo:Disco:Activo).\"}"));
            Check(ResumirDisco.General(apagado).Estado == "Apagado", "el modulo apagado del servicio se lee como «apagado»");
            var pedido = LectorDeDisco.Pedido(Json("{\"iniciada\":false,\"motivo\":\"ya se están leyendo los discos\"}"));
            Check(pedido.Valor is { Iniciada: false, Motivo: "ya se están leyendo los discos" }, "disco.leer");

            // ---- la fila de la pestaña Estado
            var conDisco = Completo(Conectada()) with { Disco = DiscoPorPipe(v) };
            ResumenDeEstado r = Resumen(conDisco);
            Check(Fila(r, Resumir.Disco).Indicador == Indicador.Alerta && r.Indicador == Indicador.Alerta && r.Titulo.Contains("Salud del disco"),
                "pestaña Estado: la fila del disco y, si es lo mas grave, la cabecera", r.Titulo);
            Check(Fila(Resumen(Completo(Conectada())), Resumir.Disco).Estado == "Sin consultar", "sin consulta del disco: «sin consultar»");

            // ---- el modelo de la pestaña
            var srv = new DiscoFalso { Valor = DiscoPorPipe(v2) };
            var m = new DiscoModelo(srv);
            Check(m.Titulo == "Sin consultar" && !m.PuedeLeer, "antes de consultar: sin datos y sin «volver a leer»");
            Esperar(m.ActualizarAsync());
            Check(m.Discos.Count == 2 && m.Discos[1].Estado == "Sin evaluar" && m.Discos[1].HayLimitaciones && m.PuedeLeer
                  && m.Lectura.StartsWith("Última lectura:"), "lee los discos, sus limitaciones y cuando se leyeron", m.Lectura);
            Esperar(m.PedirLecturaAsync());
            Check(srv.Pedidos == 1 && m.Mensaje.StartsWith("Leyendo los discos") && srv.Consultas == 2, "volver a leer: lo pide y vuelve a consultar");
            srv.AlPedir = Consulta<PedidoDeLectura>.Bien(new PedidoDeLectura(false, "se leyeron hace menos de 5 minutos"));
            Esperar(m.PedirLecturaAsync());
            Check(m.Mensaje == "No se volvió a leer: se leyeron hace menos de 5 minutos.", "si el servicio se niega, dice por que", m.Mensaje);
            srv.Valor = Consulta<EstadoDeDiscos>.Mal("el servicio no está en marcha");
            Esperar(m.ActualizarAsync());
            Check(m.Discos.Count == 0 && !m.PuedeLeer && m.Titulo == "Sin datos", "si no se puede consultar, no se muestran los discos de antes");

            var sinServicio = new DiscoModelo(Fuentes.DiscoPorDefecto("NexoIpc"));
            Esperar(sinServicio.ActualizarAsync());
            Check(sinServicio.Titulo == "Sin datos" && sinServicio.Explicacion.StartsWith("No se pudo consultar"), "sin servicio (esta compilacion): sin datos");
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
            var firewall = new FirewallFalso();
            var fm = new FirewallModelo(firewall);
            var limpieza = new LimpiezaFalsa();
            var lm = new LimpiezaModelo(limpieza, () => Hoy);
            var tiempoReal = new TiempoRealFalso
            {
                Valor = Tr(EstadoTrJson(cobertura: false, porRevisar: "\"C:\\\\Users\\\\u\\\\Downloads\""), DeteccionesTrJson)
            };
            var tm = new TiempoRealModelo(tiempoReal, escaneo);
            var (vd, _, _) = Vigia(Sata("ST1000LM035-1RK172"), Nvme(), Usb());
            Esperar(vd.LeerAsync());
            var disco = new DiscoFalso { Valor = DiscoPorPipe(vd) };
            var dm = new DiscoModelo(disco);
            var seguridadFalsa = new SeguridadFalsa();
            var sm = new SeguridadModelo(seguridadFalsa);
            // La boveda de la ventana: archivo temporal, parametros rapidos, y una espera que no termina sola (la prueba decide cuando).
            string dirContrasenas = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nexo-ventana-boveda-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(dirContrasenas);
            var portapapeles = new PortapapelesFalso();
            var controlesDeVentana = new Controles();
            var cmod = new ContrasenasModelo(System.IO.Path.Combine(dirContrasenas, "boveda.nxv"), Rapidos, true, () => new RangosFalsos(), portapapeles,
                                             () => controlesDeVentana.Ahora, null, null, controlesDeVentana.Espera);
            // La pestaña Enlaces: listas ya guardadas en una carpeta temporal, y una descarga falsa que cuenta las llamadas.
            string dirEnlaces = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nexo-ventana-enlaces-" + Guid.NewGuid().ToString("N"));
            var descargaDeVentana = new DescargaDeListasFalsa();
            Esperar(new Nexo.Modules.Threats.Enlaces.AlmacenDeListas(dirEnlaces).ActualizarAsync(descargaDeVentana, Nexo.Modules.Threats.Enlaces.ListasDePhishing.Vacias, AhoraEnlaces));
            descargaDeVentana.Llamadas = 0;
            EnlacesModelo emod = ModeloDeEnlaces(dirEnlaces, descargaDeVentana);
            MainWindow? w = null;
            try
            {
                w = new MainWindow(vm, em, cm, fm, lm, tm, dm, sm, cmod, emod);
                Check(true, "el XAML de la ventana carga (tema Classic incluido)");
                w.Show();
                Dispatcher.UIThread.RunJobs();
                Check(fija.Llamadas == 1, "al abrirse consulta al servicio una vez", fija.Llamadas.ToString());
                Check(w.TituloDeEstado.Text == vm.Titulo && vm.Titulo.Contains("Firewall"), "el titulo enlazado muestra lo mas grave", w.TituloDeEstado.Text);
                Check(w.ListaDeModulos.ItemCount == 7, "la tabla de modulos tiene 7 filas", w.ListaDeModulos.ItemCount.ToString());
                Check(w.Pestanas.ItemCount == 10 && w.Pestanas.SelectedIndex == 0, "10 pestañas y se abre en «Estado»");
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

                // La pestaña Firewall.
                Check(firewall.Lecturas == 1, "al abrirse la ventana lee el firewall una vez", firewall.Lecturas.ToString());
                w.Pestanas.SelectedIndex = 3;
                Dispatcher.UIThread.RunJobs();
                Check(firewall.Lecturas == 2 && w.TablaDeReglas.ItemCount == 2 && w.ListaDePerfiles.ItemCount == 3,
                    "pestaña Firewall: se vuelve a leer al entrar; 2 reglas y 3 perfiles");
                Check(w.BotonSigiloso.Content as string == "Desactivar modo sigiloso..." && w.BotonSigiloso.IsEnabled && w.BotonBloquear.IsEnabled
                      && !w.BotonQuitarRegla.IsEnabled, "botones: sigiloso segun el estado, bloquear si, quitar sin seleccion no");
                Check(w.ResumenDeFirewall.Text!.Contains("DESACTIVADO en 1 perfil"), "el perfil apagado se dice arriba", w.ResumenDeFirewall.Text);
                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string cuarta = System.IO.Path.ChangeExtension(captura, null) + "-firewall.png";
                    w.CaptureRenderedFrame()?.Save(cuarta);
                    Console.WriteLine("           captura: " + cuarta);
                }
                // La pestaña Limpieza: el catalogo se lee al entrar; la vista previa, solo al pedirla.
                Check(limpieza.Catalogos == 0, "la limpieza no consulta nada hasta entrar en su pestaña");
                w.Pestanas.SelectedIndex = 4;
                Dispatcher.UIThread.RunJobs();
                Check(limpieza.Catalogos == 1 && w.ListaDeReglasDeLimpieza.ItemCount == 3 && limpieza.Vistas == 0,
                    "pestaña Limpieza: lee el catalogo (3 reglas) y no previsualiza sola");
                Check(w.BotonVistaPrevia.IsEnabled && !w.BotonAplicarLimpieza.IsEnabled && !w.CajaDeConfirmacion.IsEnabled,
                    "antes de la vista previa no se puede escribir BORRAR ni limpiar");
                Esperar(lm.PrevisualizarAsync());
                lm.Confirmacion = "BORRAR";
                Dispatcher.UIThread.RunJobs();
                Check(w.ListaDeCategorias.ItemCount == 2 && w.BotonAplicarLimpieza.IsEnabled && w.BotonAplicarLimpieza.Content as string == "Mover a la Papelera"
                      && w.TituloDeLimpieza.Text!.StartsWith("Se liberarían"), "con la vista previa y BORRAR, el boton se habilita y dice a donde va");
                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string quinta = System.IO.Path.ChangeExtension(captura, null) + "-limpieza.png";
                    w.CaptureRenderedFrame()?.Save(quinta);
                    Console.WriteLine("           captura: " + quinta);
                }

                // La pestaña Tiempo real: se lee al entrar, no al abrir la ventana.
                Check(tiempoReal.Consultas == 0, "el detalle del tiempo real no se pide hasta entrar en su pestaña");
                w.Pestanas.SelectedIndex = 2;
                Dispatcher.UIThread.RunJobs();
                Check(tiempoReal.Consultas == 1 && w.ListaDeDeteccionesEnTiempoReal.ItemCount == 1 && w.ListaDeCarpetasVigiladas.ItemCount == 3
                      && w.ListaPorRevisar.ItemCount == 1, "pestaña Tiempo real: 1 deteccion, 3 carpetas y 1 por revisar");
                Check(w.TituloDeTiempoReal.Text == "1 detección del tiempo real." && w.BotonCuarentenaDeTiempoReal.IsEnabled && w.BotonRevisar.IsEnabled,
                    "titulo enlazado; cuarentena y revisar habilitados", w.TituloDeTiempoReal.Text);
                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string sexta = System.IO.Path.ChangeExtension(captura, null) + "-tiempo-real.png";
                    w.CaptureRenderedFrame()?.Save(sexta);
                    Console.WriteLine("           captura: " + sexta);
                }

                // La pestaña Disco: se lee al entrar.
                Check(disco.Consultas == 0, "los discos no se consultan hasta entrar en su pestaña");
                w.Pestanas.SelectedIndex = 5;
                Dispatcher.UIThread.RunJobs();
                Check(disco.Consultas == 1 && w.ListaDeDiscos.ItemCount == 3 && w.BotonLeerDiscos.IsEnabled
                      && w.TituloDeDisco.Text == "Sin alertas", "pestaña Disco: 3 discos, «volver a leer» y el titulo", w.TituloDeDisco.Text);
                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string septima = System.IO.Path.ChangeExtension(captura, null) + "-disco.png";
                    w.CaptureRenderedFrame()?.Save(septima);
                    Console.WriteLine("           captura: " + septima);
                }

                ProbarVentanaDeSeguridad(w, sm, seguridadFalsa, captura);

                w.Pestanas.SelectedIndex = 6;
                Dispatcher.UIThread.RunJobs();

                if (captura is not null)
                {
                    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                    string tercera = System.IO.Path.ChangeExtension(captura, null) + "-cuarentena.png";
                    w.CaptureRenderedFrame()?.Save(tercera);
                    Console.WriteLine("           captura: " + tercera);
                }

                ProbarVentanaDeEnlaces(w, emod, descargaDeVentana, captura);

                // La pestaña Contraseñas va la ULTIMA: su prueba cierra la ventana (para comprobar que al cerrar se borra el portapapeles).
                ProbarVentanaDeContrasenas(w, cmod, portapapeles, captura);
            }
            catch (Exception ex)
            {
                Check(false, "la ventana se crea y se muestra sin errores", ex.ToString());
            }
            finally
            {
                w?.Close();
                try { System.IO.Directory.Delete(dirEnlaces, true); } catch (System.IO.IOException) { }
            }
        }
    }
}
