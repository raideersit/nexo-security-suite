using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Nexo.Modules.Threats.TiempoReal
{
    /// <summary>
    /// Cambios de archivos con FileSystemWatcher. No necesita administrador, pero tiene un
    /// buffer finito: bajo mucha actividad puede DESBORDARSE y perder eventos. Cuando pasa se
    /// avisa por <c>alPerder</c> (nunca se silencia) y el vigilante lo cuenta. El diario USN
    /// (necesita administrador) no tiene ese limite.
    /// </summary>
    public sealed class FuenteFileSystemWatcher : IFuenteDeCambios
    {
        private readonly IReadOnlyList<string> _raices;
        private readonly List<FileSystemWatcher> _vigilantes = new List<FileSystemWatcher>();

        /// <summary>Raices que no existen o no se pueden vigilar; se informan, no se ignoran.</summary>
        public List<string> NoVigiladas { get; } = new List<string>();

        public FuenteFileSystemWatcher(IEnumerable<string> raices) => _raices = raices.ToList();

        public void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder)
        {
            foreach (string raiz in _raices)
            {
                if (!Directory.Exists(raiz)) { NoVigiladas.Add(raiz + " — no existe"); continue; }
                try
                {
                    var w = new FileSystemWatcher(raiz)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                        InternalBufferSize = 64 * 1024        // el maximo razonable; mas solo gasta memoria no paginada
                    };
                    w.Created += (_, e) => alCambiar(new CambioDeArchivo(e.FullPath, MotivoDeCambio.Creado));
                    w.Changed += (_, e) => alCambiar(new CambioDeArchivo(e.FullPath, MotivoDeCambio.Modificado));
                    w.Renamed += (_, e) => alCambiar(new CambioDeArchivo(e.FullPath, MotivoDeCambio.Renombrado));
                    w.Error += (_, e) => alPerder(raiz + ": " + (e.GetException()?.Message ?? "error del vigilante"));
                    w.EnableRaisingEvents = true;
                    _vigilantes.Add(w);
                }
                catch (Exception ex) when (ex is ArgumentException || ex is IOException || ex is UnauthorizedAccessException || ex is PlatformNotSupportedException)
                {
                    NoVigiladas.Add(raiz + " — " + ex.GetType().Name);
                }
            }
        }

        public void Dispose()
        {
            foreach (FileSystemWatcher w in _vigilantes) w.Dispose();
            _vigilantes.Clear();
        }
    }
}
