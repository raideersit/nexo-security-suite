using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Nexo.Modules.Threats.Comportamiento;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        /// <summary>El enriquecedor y la sesión ETW sin administrador: lo que se puede comprobar sin abrir ETW de verdad.</summary>
        public static void ProbarComportamientoWindows()
        {
            Console.WriteLine("16. Análisis de comportamiento: enriquecedor y sesión (sin administrador)");
            int firmas = 0;
            var p = new PuntuadorDeComportamiento();
            var e = new EnriquecedorDeComportamiento(p, pid => pid == 99 ? throw new InvalidOperationException("sin permiso") : @"C:\Users\ana\Downloads\x.exe", _ => { firmas++; return EstadoDeFirma.Ausente; });

            Check(e.Procesar(new EventoCrudo(TipoDeSenal.ServicioCreado, 4, "System", null)) is null && p.ProcesosSeguidos == 0, "los PID 0 a 4 (Idle y System) se ignoran");
            Check(e.Procesar(new EventoCrudo(TipoDeSenal.ProcesoIniciado, 10, "x.exe", null)) is null, "un proceso nuevo sin firma, solo, no alerta");
            HallazgoDeSistema? h = e.Procesar(new EventoCrudo(TipoDeSenal.ArchivoEnInicio, 10, "x.exe", @"C:\Users\ana\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"));
            Check(h is { Severidad: Severidad.Alta }, "sin firma + Descargas + Inicio = Alta, con la ruta y la firma venidas de las funciones", h?.Severidad.ToString());
            for (int i = 0; i < 5; i++) e.Procesar(new EventoCrudo(TipoDeSenal.ConexionSaliente, 10, "x.exe", "1.2.3.4:80"));
            Check(firmas == 1 && e.Comprobaciones == 1, "la firma de la misma ruta se comprueba UNA vez", firmas.ToString());

            e.Procesar(new EventoCrudo(TipoDeSenal.ServicioCreado, 99, "raro.exe", "svc")); // la ruta lanza
            Check(p.Resumen().Hallazgos.All(x => x.Sujeto != "raro.exe"), "si leer la ruta falla, no se acusa a nadie (firma desconocida)");
            e.Procesar(new EventoCrudo(TipoDeSenal.ProcesoTerminado, 10, "x.exe", null));
            Check(p.ProcesosSeguidos == 1, "al terminar el proceso se olvida");
            Check(e.Procesar(new EventoCrudo(TipoDeSenal.ProcesoIniciado, 11, null, null)) is null && p.ProcesosSeguidos == 2, "sin nombre se usa «pid N», no rompe");

            // La firma real y la ruta real de ESTE proceso (sin administrador).
            string? yo = EnriquecedorDeComportamiento.RutaDelProceso(Environment.ProcessId);
            Check(yo is not null && File.Exists(yo), "la ruta real de este proceso se lee", yo);
            Check(EnriquecedorDeComportamiento.RutaDelProceso(int.MaxValue) is null, "un PID que no existe: null, sin lanzar");
            Check(EnriquecedorDeComportamiento.FirmaReal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe")) == EstadoDeFirma.Valida, "firma real de cmd.exe: válida");

            // Sin administrador la sesión NO finge: dice por qué.
            if (!SesionEtwWindows.EsAdministrador())
            {
                using var s = new SesionEtwWindows(e);
                string? motivo = s.Iniciar();
                Check(motivo is not null && motivo.Contains("administrador") && !s.Activa, "sin administrador: la sesión no arranca y lo dice");
            }
            else Console.WriteLine("  (esta ejecución ya es de administrador: la parte «sin administrador» no aplica; mira la prueba 17 con --etw)");
        }

        /// <summary>ETW REAL: exige administrador y toca (poco y se deshace) el sistema; solo con --etw.</summary>
        public static void ProbarEtwReal()
        {
            Console.WriteLine("17. ETW REAL (administrador): archivo en Inicio, conexión y servicio desde un proceso hijo");
            if (!SesionEtwWindows.EsAdministrador()) { Console.WriteLine("  OMITIDA: hace falta una consola de administrador"); return; }

            var alertas = new List<HallazgoDeSistema>();
            var p = new PuntuadorDeComportamiento();
            // La firma se finge «ausente» para que el hijo (powershell, firmado de verdad) cuente como sospechoso y se vea la suma.
            var e = new EnriquecedorDeComportamiento(p, EnriquecedorDeComportamiento.RutaDelProceso, _ => EstadoDeFirma.Ausente);
            using var s = new SesionEtwWindows(e);
            s.Hallazgo += h => { lock (alertas) alertas.Add(h); };
            string? motivo = s.Iniciar();
            Check(motivo is null && s.Activa, "la sesión ETW arranca como administrador", motivo);
            if (motivo is not null) return;

            string inicio = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            string archivo = Path.Combine(inicio, "nexo-prueba-etw.txt");
            var escucha = new TcpListener(IPAddress.Loopback, 0);
            escucha.Start();
            int puerto = ((IPEndPoint)escucha.LocalEndpoint).Port;
            string guion = "Set-Content -LiteralPath '" + archivo + "' -Value prueba; "
                         + "$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1'," + puerto + "); $c.Close(); "
                         + "sc.exe create NexoPruebaEtw binPath= 'C:\\Windows\\System32\\cmd.exe' | Out-Null; Start-Sleep -Milliseconds 500; sc.exe delete NexoPruebaEtw | Out-Null; "
                         + "Start-Sleep -Seconds 2";
            try
            {
                var hijo = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -Command \"" + guion + "\"") { UseShellExecute = false, CreateNoWindow = true })!;
                Check(hijo.WaitForExit(30000), "el proceso hijo termina");
                for (int i = 0; i < 40 && s.Recibidos < 5; i++) Thread.Sleep(250);
                Thread.Sleep(2000); // deja que el hilo trabajador vacíe la cola
                Console.WriteLine("  recibidos=" + s.Recibidos + " descartados=" + s.Descartados + " alertas=" + alertas.Count);
                foreach (var a in alertas) Console.WriteLine("  ALERTA " + a.Severidad + ": " + a.Detalle);
                Check(s.Recibidos > 0, "ETW entregó eventos reales");
                Check(alertas.Any(a => a.Detalle.Contains("escribió en la carpeta Inicio")), "vio el archivo escrito en la carpeta Inicio");
                Check(alertas.Any(a => a.Detalle.Contains("abrió una conexión de red")) || p.Resumen().Hallazgos.Any(a => a.Detalle.Contains("conexión de red")), "vio la conexión TCP (informativo; en bucle local puede no salir)");
                Check(alertas.Any(a => a.Detalle.Contains("creó un servicio")) || p.Resumen().Hallazgos.Any(a => a.Detalle.Contains("creó un servicio")), "vio el servicio creado (clave nueva en Services)");
            }
            finally
            {
                escucha.Stop();
                try { File.Delete(archivo); } catch { /* ya no está */ }
                Process.Start(new ProcessStartInfo("sc.exe", "delete NexoPruebaEtw") { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(5000); // por si el hijo no llegó
            }
            Check(!File.Exists(archivo), "se limpió el archivo de prueba de la carpeta Inicio");
        }
    }
}
