using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Nexo.Modules.Threats.Comportamiento;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Native.Trust;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>Un evento tal como sale de ETW, ya filtrado. <c>Detalle</c> = la ruta del archivo (Inicio/Tareas) o «ip:puerto» o el nombre del servicio.</summary>
    public sealed record EventoCrudo(TipoDeSenal Tipo, int Pid, string? Nombre, string? Detalle);

    /// <summary>
    /// Completa un evento crudo (ruta del programa y firma digital) y lo pasa al puntuador. Es la parte que se puede probar sin ETW:
    /// ruta y firma se piden por funciones. Si el proceso ya no existe o no se puede leer, la ruta es null y la firma «desconocida»
    /// (no suma ni resta): nunca se inventa. La firma se recuerda por ruta (tope 2000) porque comprobarla cuesta.
    /// </summary>
    public sealed class EnriquecedorDeComportamiento
    {
        private const int MaximoDeFirmas = 2000;
        private readonly PuntuadorDeComportamiento _puntuador;
        private readonly Func<int, string?> _rutaDe;
        private readonly Func<string, EstadoDeFirma> _firmaDe;
        private readonly Dictionary<string, EstadoDeFirma> _firmas = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<int, string?> _rutas = new();

        public EnriquecedorDeComportamiento(PuntuadorDeComportamiento puntuador, Func<int, string?> rutaDe, Func<string, EstadoDeFirma> firmaDe)
        { _puntuador = puntuador; _rutaDe = rutaDe; _firmaDe = firmaDe; }

        public int Comprobaciones { get; private set; }

        public HallazgoDeSistema? Procesar(EventoCrudo e)
        {
            if (e.Pid <= 4) return null; // Idle y System
            string nombre = string.IsNullOrWhiteSpace(e.Nombre) ? "pid " + e.Pid : e.Nombre!;
            if (e.Tipo == TipoDeSenal.ProcesoTerminado) { _rutas.Remove(e.Pid); return _puntuador.Registrar(new EventoDeComportamiento(e.Tipo, e.Pid, nombre)); }

            if (e.Tipo == TipoDeSenal.ProcesoIniciado || !_rutas.ContainsKey(e.Pid)) _rutas[e.Pid] = SeguroRuta(e.Pid);
            if (_rutas.Count > 4000) _rutas.Clear(); // memoria acotada: se vuelve a leer cuando haga falta
            string? ruta = _rutas[e.Pid];

            EstadoDeFirma firma = EstadoDeFirma.Desconocida;
            if (ruta is not null && !_firmas.TryGetValue(ruta, out firma))
            {
                firma = SeguroFirma(ruta);
                if (_firmas.Count >= MaximoDeFirmas) _firmas.Clear();
                _firmas[ruta] = firma;
            }
            return _puntuador.Registrar(new EventoDeComportamiento(e.Tipo, e.Pid, nombre, ruta, firma, e.Detalle));
        }

        private string? SeguroRuta(int pid) { try { return _rutaDe(pid); } catch { return null; } }

        private EstadoDeFirma SeguroFirma(string ruta)
        {
            Comprobaciones++;
            try { return _firmaDe(ruta); } catch { return EstadoDeFirma.Desconocida; }
        }

        public static EstadoDeFirma DeNativa(ResultadoDeFirma r) => r switch
        {
            ResultadoDeFirma.Valida => EstadoDeFirma.Valida,
            ResultadoDeFirma.Ausente => EstadoDeFirma.Ausente,
            ResultadoDeFirma.Invalida => EstadoDeFirma.Invalida,
            _ => EstadoDeFirma.Desconocida,
        };

        public static string? RutaDelProceso(int pid)
        {
            try { using var p = Process.GetProcessById(pid); return p.MainModule?.FileName; }
            catch { return null; }
        }

        public static EstadoDeFirma FirmaReal(string ruta) => DeNativa(FirmaDeArchivo.Verificar(ruta).Resultado);
    }

    /// <summary>
    /// Sesión ETW en tiempo real (kernel: procesos, creación de archivos, conexiones TCP y claves de registro). EXIGE administrador;
    /// sin él, <see cref="Iniciar"/> devuelve el motivo y no hace nada (nunca finge que vigila). La función de ETW solo filtra y encola
    /// (cola acotada: si se llena se descartan eventos y se cuentan en <see cref="Descartados"/>); un hilo aparte pide la ruta y la firma.
    /// Solo mira: no detiene ni borra nada.
    /// </summary>
    public sealed class SesionEtwWindows : IFuenteDeComportamiento
    {
        public const string NombreDeSesion = "NexoComportamiento";
        private readonly EnriquecedorDeComportamiento _enriquecedor;
        private readonly BlockingCollection<EventoCrudo> _cola = new(5000);
        private readonly CancellationTokenSource _fin = new();
        private TraceEventSession? _sesion;
        private Task? _lector, _trabajador;
        private long _descartados, _recibidos;
        private readonly int _miPid = Environment.ProcessId;

        public event Action<HallazgoDeSistema>? Hallazgo;
        public long Descartados => Interlocked.Read(ref _descartados);
        public long Recibidos => Interlocked.Read(ref _recibidos);
        public bool Activa => _sesion is not null;

        public SesionEtwWindows(EnriquecedorDeComportamiento enriquecedor) => _enriquecedor = enriquecedor;

        public static bool EsAdministrador()
        {
            try { return TraceEventSession.IsElevated() == true; } catch { return false; }
        }

        /// <summary>null = la sesión quedó en marcha; si no, el motivo por el que no se pudo (dicho tal cual).</summary>
        public string? Iniciar()
        {
            if (_sesion is not null) return null;
            if (!EsAdministrador()) return "hace falta ejecutar como administrador para abrir la sesión de eventos (ETW)";
            try
            {
                // Si quedó una sesión de una ejecución anterior que murió sin cerrarla, se reutiliza el nombre.
                var s = new TraceEventSession(NombreDeSesion) { StopOnDispose = true };
                s.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO
                                       | KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Registry);
                var k = s.Source.Kernel;
                k.ProcessStart += d => Encolar(TipoDeSenal.ProcesoIniciado, d.ProcessID, d.ImageFileName, null);
                k.ProcessStop += d => Encolar(TipoDeSenal.ProcesoTerminado, d.ProcessID, d.ImageFileName, null);
                k.FileIOCreate += d =>
                {
                    string f = d.FileName;
                    if (PuntuadorDeComportamiento.EsCarpetaDeInicio(f)) Encolar(TipoDeSenal.ArchivoEnInicio, d.ProcessID, d.ProcessName, f);
                    else if (PuntuadorDeComportamiento.EsCarpetaDeTareas(f)) Encolar(TipoDeSenal.TareaProgramada, d.ProcessID, d.ProcessName, f);
                };
                k.TcpIpConnect += d => Encolar(TipoDeSenal.ConexionSaliente, d.ProcessID, d.ProcessName, d.daddr + ":" + d.dport);
                k.RegistryCreate += d =>
                {
                    string n = d.KeyName ?? "";
                    // Un servicio nuevo es una clave nueva bajo «...\Services\<nombre>».
                    int i = n.IndexOf(@"\Services\", StringComparison.OrdinalIgnoreCase);
                    if (i >= 0 && n.IndexOf('\\', i + 10) < 0) Encolar(TipoDeSenal.ServicioCreado, d.ProcessID, d.ProcessName, n.Substring(i + 10));
                };
                _sesion = s;
                _trabajador = Task.Run(Trabajar);
                _lector = Task.Run(() => { try { s.Source.Process(); } catch { /* sesión cerrada */ } });
                return null;
            }
            catch (Exception e)
            {
                try { _sesion?.Dispose(); } catch { /* ya caída */ }
                _sesion = null;
                return "no se pudo abrir la sesión de eventos: " + e.Message;
            }
        }

        private void Encolar(TipoDeSenal t, int pid, string? nombre, string? detalle)
        {
            if (pid == _miPid || pid <= 4) return; // Nexo no se vigila a sí mismo
            Interlocked.Increment(ref _recibidos);
            if (!_cola.TryAdd(new EventoCrudo(t, pid, nombre, detalle))) Interlocked.Increment(ref _descartados);
        }

        private void Trabajar()
        {
            try
            {
                foreach (EventoCrudo e in _cola.GetConsumingEnumerable(_fin.Token))
                {
                    HallazgoDeSistema? h;
                    try { h = _enriquecedor.Procesar(e); } catch { continue; }
                    if (h is not null) { try { Hallazgo?.Invoke(h); } catch { /* quien escucha falló: no cae la sesión */ } }
                }
            }
            catch (OperationCanceledException) { /* fin */ }
        }

        public void Dispose()
        {
            _fin.Cancel();
            try { _sesion?.Dispose(); } catch { /* ya cerrada */ }
            _sesion = null;
            try { _lector?.Wait(2000); _trabajador?.Wait(2000); } catch { /* terminando */ }
        }
    }
}
