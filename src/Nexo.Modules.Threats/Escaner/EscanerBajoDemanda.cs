using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Escaner
{
    public sealed class OpcionesDeEscaneo
    {
        /// <summary>
        /// Archivos mayores que esto no se envian al motor. clamd los rechazaria de
        /// todos modos (StreamMaxLength); se anotan como NO analizados.
        /// </summary>
        public long MaxBytes { get; init; } = 25L * 1024 * 1024;

        public bool Recursivo { get; init; } = true;

        /// <summary>Carpetas que no se recorren (p. ej. la cuarentena, para no re-detectarla).</summary>
        public IReadOnlyList<string> Excluir { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Tras tantos errores consecutivos del motor se aborta el escaneo como
        /// incompleto, en vez de seguir marcando miles de archivos como omitidos.
        /// </summary>
        public int MaxErroresSeguidos { get; init; } = 5;
    }

    public sealed record Deteccion(string Ruta, string Firma, long Bytes, DateTimeOffset Modificado, string? Sha256);

    public sealed record ProgresoDeEscaneo(int Analizados, string RutaActual);

    public sealed class ResultadoDeEscaneo
    {
        public ResultadoDeEscaneo(
            string motor, string motorVersion, int analizados, IReadOnlyList<Deteccion> detecciones,
            IReadOnlyList<string> omitidos, TimeSpan duracion, bool incompleto, string? motivoIncompleto)
        {
            Motor = motor;
            MotorVersion = motorVersion;
            Analizados = analizados;
            Detecciones = detecciones;
            Omitidos = omitidos;
            Duracion = duracion;
            Incompleto = incompleto;
            MotivoIncompleto = motivoIncompleto;
        }

        public string Motor { get; }
        public string MotorVersion { get; }

        /// <summary>Archivos que el motor llego a analizar (limpios + infectados).</summary>
        public int Analizados { get; }

        public IReadOnlyList<Deteccion> Detecciones { get; }

        /// <summary>Lo que NO se pudo analizar, con el motivo. Nunca cuenta como limpio.</summary>
        public IReadOnlyList<string> Omitidos { get; }

        public TimeSpan Duracion { get; }
        public bool Incompleto { get; }
        public string? MotivoIncompleto { get; }

        /// <summary>
        /// True solo si no hubo detecciones Y no quedo nada sin analizar. Es la unica
        /// forma de decir "limpio" sin mentir.
        /// </summary>
        public bool CompletamenteLimpio => Detecciones.Count == 0 && Omitidos.Count == 0 && !Incompleto;
    }

    /// <summary>
    /// Escaneo bajo demanda: recorre carpetas y pasa cada archivo por el motor de
    /// firmas. NO modifica nada; llevar un archivo a cuarentena es otra accion,
    /// con su propia vista previa y token (<see cref="Cuarentena.AlmacenDeCuarentena"/>).
    ///
    /// La regla que gobierna esta clase es «no pude leer» != «esta bien»:
    /// los archivos bloqueados, sin permisos, demasiado grandes o que el motor
    /// no pudo evaluar se listan como omitidos y el resultado lo refleja.
    /// </summary>
    public sealed class EscanerBajoDemanda
    {
        private readonly IMotorDeFirmas _motor;
        private readonly IReportWriter _reportes;
        private readonly OpcionesDeEscaneo _opciones;

        public EscanerBajoDemanda(IMotorDeFirmas motor, IReportWriter reportes, OpcionesDeEscaneo? opciones = null)
        {
            _motor = motor;
            _reportes = reportes;
            _opciones = opciones ?? new OpcionesDeEscaneo();
        }

        /// <exception cref="MotorNoDisponibleException">El motor no responde: no se escanea nada.</exception>
        public async Task<ResultadoDeEscaneo> EscanearAsync(
            IEnumerable<string> raices,
            IProgress<ProgresoDeEscaneo>? progreso = null,
            CancellationToken ct = default)
        {
            var lista = raices.ToList();
            if (lista.Count == 0) throw new ArgumentException("No se indico que escanear.", nameof(raices));

            // Sin motor no hay escaneo: devolver "0 detecciones" seria una mentira.
            string version = await _motor.VersionAsync(ct).ConfigureAwait(false);

            var reloj = Stopwatch.StartNew();
            var detecciones = new List<Deteccion>();
            var omitidos = new List<string>();
            int analizados = 0;
            int erroresSeguidos = 0;
            bool incompleto = false;
            string? motivo = null;

            foreach (string archivo in Recorrer(lista, omitidos, ct))
            {
                ct.ThrowIfCancellationRequested();
                progreso?.Report(new ProgresoDeEscaneo(analizados, archivo));

                ResultadoDeArchivo r = await AnalizarArchivoAsync(archivo, ct).ConfigureAwait(false);

                if (r.Omitido is not null)
                {
                    omitidos.Add(archivo + " — " + r.Omitido);
                    // Solo los fallos del MOTOR cuentan para abortar; un archivo bloqueado no.
                    erroresSeguidos = r.FalloDelMotor ? erroresSeguidos + 1 : 0;
                    if (erroresSeguidos >= _opciones.MaxErroresSeguidos)
                    {
                        incompleto = true;
                        motivo = erroresSeguidos + " errores seguidos del motor; ultimo: " + r.Omitido;
                        break;
                    }
                    continue;
                }

                erroresSeguidos = 0;
                analizados++;
                if (r.Deteccion is not null) detecciones.Add(r.Deteccion);
            }

            reloj.Stop();

            foreach (Deteccion d in detecciones)
            {
                await _reportes.EscribirAsync(Eventos.Amenazas.Detectada(
                    d.Firma, d.Ruta, _motor.Nombre, Severidad.Alta, Accion.Registrada, d.Sha256), ct).ConfigureAwait(false);
            }

            await _reportes.EscribirAsync(Eventos.Amenazas.Escaneo(
                string.Join("; ", lista), analizados, detecciones.Count, reloj.Elapsed, _motor.Nombre,
                omitidos.Count, incompleto), ct).ConfigureAwait(false);

            return new ResultadoDeEscaneo(_motor.Nombre, version, analizados, detecciones, omitidos,
                                          reloj.Elapsed, incompleto, motivo);
        }

        // ============================================================
        private readonly struct ResultadoDeArchivo
        {
            public ResultadoDeArchivo(Deteccion? deteccion, string? omitido, bool falloDelMotor)
            {
                Deteccion = deteccion;
                Omitido = omitido;
                FalloDelMotor = falloDelMotor;
            }

            public Deteccion? Deteccion { get; }
            public string? Omitido { get; }
            public bool FalloDelMotor { get; }
        }

        private async Task<ResultadoDeArchivo> AnalizarArchivoAsync(string ruta, CancellationToken ct)
        {
            FileInfo info;
            try
            {
                info = new FileInfo(ruta);
                if (!info.Exists) return new ResultadoDeArchivo(null, "ya no existe", false);
                if (info.Length > _opciones.MaxBytes)
                    return new ResultadoDeArchivo(null,
                        "mayor que " + Eventos.FormatearBytes(_opciones.MaxBytes) + " (" + Eventos.FormatearBytes(info.Length) +
                        "): no se envia al motor", false);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return new ResultadoDeArchivo(null, ex.GetType().Name, false);
            }

            ResultadoDeMotor veredicto;
            try
            {
                // FileShare.ReadWrite | Delete: leer sin impedir que otro proceso siga
                // usando el archivo. Si esta bloqueado en exclusiva, se omite.
                await using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                veredicto = await _motor.AnalizarAsync(fs, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return new ResultadoDeArchivo(null, "no se pudo leer (" + ex.GetType().Name + ")", false);
            }

            switch (veredicto.Veredicto)
            {
                case VeredictoDeArchivo.Limpio:
                    return new ResultadoDeArchivo(null, null, false);

                case VeredictoDeArchivo.Infectado:
                    return new ResultadoDeArchivo(
                        new Deteccion(ruta, veredicto.Firma ?? "(sin nombre)", info.Length,
                                      new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), Sha256De(ruta)),
                        null, false);

                default:
                    return new ResultadoDeArchivo(null, "el motor no pudo analizarlo: " + veredicto.Error, true);
            }
        }

        private static string? Sha256De(string ruta)
        {
            try
            {
                using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return null;
            }
        }

        // ============================================================
        //  RECORRIDO
        // ============================================================
        // Carpeta a carpeta, cada una con su propio try: una subcarpeta sin permisos
        // se anota y el resto sigue (mismo aprendizaje que LimpiadorDeBasura: el
        // enumerador recursivo de .NET no puede reanudarse tras una excepcion).
        // No se entra en uniones ni enlaces simbolicos: pueden apuntar fuera de lo
        // que el usuario pidio escanear.
        private IEnumerable<string> Recorrer(List<string> raices, List<string> omitidos, CancellationToken ct)
        {
            var opciones = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = false
            };

            foreach (string raiz in raices)
            {
                if (File.Exists(raiz)) { yield return raiz; continue; }
                if (!Directory.Exists(raiz)) { omitidos.Add(raiz + " — no existe"); continue; }

                var pendientes = new Stack<string>();
                pendientes.Push(raiz);

                while (pendientes.Count > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    string actual = pendientes.Pop();
                    if (EstaExcluida(actual)) continue;

                    if (_opciones.Recursivo)
                    {
                        try
                        {
                            foreach (string sub in Directory.EnumerateDirectories(actual, "*", opciones))
                                pendientes.Push(sub);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                        {
                            omitidos.Add(actual + " — subcarpetas no leidas: " + ex.GetType().Name);
                        }
                    }

                    IEnumerator<string> it;
                    try { it = Directory.EnumerateFiles(actual, "*", opciones).GetEnumerator(); }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                    {
                        omitidos.Add(actual + " — carpeta no leida: " + ex.GetType().Name);
                        continue;
                    }

                    using (it)
                    {
                        while (true)
                        {
                            string archivo;
                            try
                            {
                                if (!it.MoveNext()) break;
                                archivo = it.Current;
                            }
                            catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                            {
                                omitidos.Add(actual + " — carpeta no leida por completo: " + ex.GetType().Name);
                                break;
                            }
                            yield return archivo;
                        }
                    }
                }
            }
        }

        private bool EstaExcluida(string carpeta)
        {
            foreach (string x in _opciones.Excluir)
            {
                string ex = x.TrimEnd('\\', '/');
                if (carpeta.Equals(ex, StringComparison.OrdinalIgnoreCase)
                    || carpeta.StartsWith(ex + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || carpeta.StartsWith(ex + '/', StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
