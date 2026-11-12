using System;
using System.Linq;
using Nexo.Modules.Threats.Comportamiento;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private const string Inicio = @"C:\Users\ana\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk";
        private static EventoDeComportamiento Ev(TipoDeSenal t, int pid = 10, string n = "x.exe", string? ruta = @"C:\Program Files\X\x.exe", EstadoDeFirma f = EstadoDeFirma.Desconocida, string? d = null)
            => new(t, pid, n, ruta, f, d);

        private static void ProbarComportamiento()
        {
            Console.WriteLine("33. Análisis de comportamiento: el puntuador");
            var p = new PuntuadorDeComportamiento();
            Check(p.Registrar(Ev(TipoDeSenal.ProcesoIniciado, f: EstadoDeFirma.Ausente)) is null, "sin firma, solo, no alerta");
            Check(p.Registrar(Ev(TipoDeSenal.ConexionSaliente, f: EstadoDeFirma.Ausente)) is null, "sin firma + conexión (3 puntos) no alerta");
            var h = p.Registrar(Ev(TipoDeSenal.ServicioCreado, f: EstadoDeFirma.Ausente));
            Check(h is { Severidad: Severidad.Alta }, "sin firma + conexión + servicio (6) = Alta", h?.Severidad.ToString());
            Check(p.Registrar(Ev(TipoDeSenal.ServicioCreado, f: EstadoDeFirma.Ausente)) is null, "el mismo nivel no se repite");

            var q = new PuntuadorDeComportamiento();
            Check(q.Registrar(Ev(TipoDeSenal.ArchivoEnInicio, f: EstadoDeFirma.Valida, d: Inicio)) is null
                && q.Registrar(Ev(TipoDeSenal.ServicioCreado, f: EstadoDeFirma.Valida)) is null
                && q.Registrar(Ev(TipoDeSenal.TareaProgramada, f: EstadoDeFirma.Valida, d: @"C:\Windows\System32\Tasks\X")) is null,
                "un instalador firmado que escribe en Inicio, crea servicio y tarea (3 puntos) no alerta");

            var r = new PuntuadorDeComportamiento();
            var m = r.Registrar(Ev(TipoDeSenal.ArchivoEnInicio, f: EstadoDeFirma.Ausente, d: Inicio));
            Check(m is { Severidad: Severidad.Media }, "sin firma + Inicio (5) = Media", m?.Severidad.ToString());
            var a = r.Registrar(Ev(TipoDeSenal.ServicioCreado));
            Check(a is { Severidad: Severidad.Alta } && a.Detalle.Contains("escribió en la carpeta Inicio") && a.Detalle.Contains("creó un servicio"), "sube a Alta y dice los motivos");

            var d = new PuntuadorDeComportamiento();
            Check(d.Registrar(Ev(TipoDeSenal.ArchivoEnInicio, f: EstadoDeFirma.Ausente, d: @"C:\Users\ana\Documents\x.lnk")) is null, "escribir fuera de Inicio no cuenta");
            Check(d.Registrar(Ev(TipoDeSenal.TareaProgramada, d: @"C:\Otra\carpeta\t")) is null && d.Resumen().Hallazgos.Count == 0, "una «tarea» fuera de Tasks no cuenta");

            var u = new PuntuadorDeComportamiento();
            var ru = u.Registrar(Ev(TipoDeSenal.ArchivoEnInicio, ruta: @"C:\Users\ana\Downloads\x.exe", f: EstadoDeFirma.Invalida, d: Inicio));
            Check(ru is { Severidad: Severidad.Alta }, "firma inválida + Descargas + Inicio (6) = Alta", ru?.Severidad.ToString());

            var s = new PuntuadorDeComportamiento();
            for (int i = 0; i < 5; i++) s.Registrar(Ev(TipoDeSenal.ServicioCreado, pid: i)); // firma desconocida
            Check(s.Resumen().Hallazgos.Count == 0 && !s.Resumen().Completo && s.Resumen().NoEvaluado.Single().Contains("5 proceso"), "firma desconocida: no acusa y dice que no se pudo comprobar");
            var nombres = new PuntuadorDeComportamiento();
            for (int i = 0; i < 8; i++) nombres.Registrar(new EventoDeComportamiento(TipoDeSenal.ServicioCreado, 100 + i, "proc" + i + ".exe", null, EstadoDeFirma.Desconocida, "x"));
            string dicho = nombres.Resumen().NoEvaluado.Single();
            Check(dicho.Contains("8 proceso") && dicho.Contains("proc0.exe") && dicho.Contains("proc4.exe") && !dicho.Contains("proc5.exe"), "dice QUÉ procesos no se pudieron firmar (los 5 primeros, no todos)", dicho);

            var t = new PuntuadorDeComportamiento();
            t.Registrar(Ev(TipoDeSenal.ServicioCreado, f: EstadoDeFirma.Ausente));
            t.Registrar(Ev(TipoDeSenal.ProcesoTerminado));
            Check(t.ProcesosSeguidos == 0, "un proceso terminado se olvida");
            Check(t.Registrar(Ev(TipoDeSenal.ServicioCreado, pid: 10, n: "otro.exe", f: EstadoDeFirma.Valida)) is null && t.ProcesosSeguidos == 1, "mismo PID con otro nombre empieza de cero");

            var g = new PuntuadorDeComportamiento();
            for (int i = 0; i < PuntuadorDeComportamiento.MaximoDeProcesos + 50; i++) g.Registrar(Ev(TipoDeSenal.ProcesoIniciado, pid: i));
            Check(g.ProcesosSeguidos == PuntuadorDeComportamiento.MaximoDeProcesos, "la memoria está acotada");

            bool lanzo = false;
            try { g.Registrar(null!); } catch (ArgumentNullException) { lanzo = true; }
            Check(lanzo, "un evento null se rechaza");
            Check(PuntuadorDeComportamiento.EsCarpetaDeInicio(@"c:/users/ana/appdata/roaming/microsoft/windows/start menu/programs/startup/a") && !PuntuadorDeComportamiento.EsCarpetaDeInicio(null), "carpeta Inicio: barras y mayúsculas");
        }
    }
}
