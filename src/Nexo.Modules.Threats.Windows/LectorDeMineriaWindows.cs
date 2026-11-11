using System;
using System.Collections.Generic;
using System.Diagnostics;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Native.Network;
using Nexo.Native.Shell;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Toma muestras para <see cref="VigilanteDeMineria"/>: CPU por proceso (diferencia de <c>TotalProcessorTime</c> entre dos
    /// llamadas, como % de TODA la maquina), proceso en primer plano y conexiones TCP por PID. Solo lectura, sin administrador.
    /// La primera llamada no tiene con que comparar: devuelve CPU 0 (nunca inventa uso). Lo que no se pueda leer queda marcado
    /// «no leido», no «ninguno».
    /// </summary>
    public sealed class LectorDeMineriaWindows
    {
        private readonly Dictionary<int, (string Nombre, TimeSpan Cpu)> _previo = new();
        private DateTimeOffset? _cuandoPrevio;

        public MuestraDeMineria Tomar()
        {
            var ahora = DateTimeOffset.UtcNow;
            var procesos = new List<ProcesoMuestreado>();
            bool procesosLeidos = true;
            string? motivoProcesos = null;

            int primerPlano = VentanaActiva.PidEnPrimerPlano();
            double segundos = _cuandoPrevio is null ? 0 : (ahora - _cuandoPrevio.Value).TotalSeconds;
            var nuevo = new Dictionary<int, (string, TimeSpan)>();

            Process[] todos;
            try { todos = Process.GetProcesses(); }
            catch (Exception e) { todos = Array.Empty<Process>(); procesosLeidos = false; motivoProcesos = e.Message; }

            foreach (var p in todos)
            {
                try
                {
                    int pid = p.Id;
                    if (pid <= 4) continue; // Idle y System
                    string nombre = p.ProcessName;
                    TimeSpan cpu = p.TotalProcessorTime; // lanza para procesos protegidos: se omiten, no cuentan como 0
                    nuevo[pid] = (nombre, cpu);

                    double pct = 0;
                    if (segundos > 0.5 && _previo.TryGetValue(pid, out var antes) && antes.Nombre == nombre && cpu >= antes.Cpu)
                        pct = Math.Min(100, (cpu - antes.Cpu).TotalSeconds / segundos / Environment.ProcessorCount * 100);

                    string? ruta = null;
                    try { ruta = p.MainModule?.FileName; } catch { /* sin permiso: la ruta queda en null */ }
                    procesos.Add(new ProcesoMuestreado(pid, nombre, ruta, pct, pid == primerPlano));
                }
                catch { /* proceso que termino o protegido */ }
                finally { p.Dispose(); }
            }

            if (procesosLeidos && procesos.Count == 0) { procesosLeidos = false; motivoProcesos = "no se pudo leer ningun proceso"; }

            _previo.Clear();
            foreach (var kv in nuevo) _previo[kv.Key] = kv.Value;
            _cuandoPrevio = ahora;

            LecturaTcp tcp = TablaTcp.Leer();
            var conexiones = new List<ConexionDeProceso>();
            foreach (var c in tcp.Conexiones) conexiones.Add(new ConexionDeProceso(c.Pid, c.IpRemota, c.PuertoRemoto));

            return new MuestraDeMineria(ahora, procesos, procesosLeidos, conexiones, tcp.Correcta,
                motivoProcesos, tcp.Correcta ? null : "GetExtendedTcpTable fallo (codigo " + tcp.CodigoDeError + ")");
        }
    }
}
