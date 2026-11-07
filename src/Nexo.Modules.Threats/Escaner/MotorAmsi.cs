using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Threats.Escaner
{
    /// <summary>Respuesta de un escaneo AMSI. <see cref="Exito"/> false = no se pudo preguntar (nunca es «limpio»).</summary>
    public readonly record struct RespuestaDeAmsi(bool Exito, uint Codigo, string? Motivo)
    {
        public static RespuestaDeAmsi Ok(uint codigo) => new(true, codigo, null);
        public static RespuestaDeAmsi Fallo(string motivo) => new(false, 0, motivo);
    }

    /// <summary>Quien habla de verdad con AMSI (en Windows) o lo finge (en las pruebas). No debe lanzar por fallos del sistema.</summary>
    public interface IBackendAmsi
    {
        RespuestaDeAmsi Escanear(byte[] datos, int longitud, string nombreDelContenido);
    }

    /// <summary>
    /// Motor que le pregunta a AMSI (en Windows, normalmente Microsoft Defender) que opina del contenido. Nexo es solo
    /// CONSUMIDOR de AMSI: no registra proveedores ni toca los de Windows.
    ///
    /// El problema que resuelve este motor: AMSI responde «no detectado» tanto cuando el contenido esta limpio como
    /// cuando NO HAY ningun proveedor activo (Defender apagado o ausente). Si Nexo tomara ese «no detectado» por «limpio»
    /// presentaria «no pude mirar» como «esta bien», que el proyecto prohibe. Por eso, antes de dar un «limpio», comprueba
    /// que el proveedor responde: le entrega la cadena de prueba oficial de AMSI, que cualquier proveedor real debe marcar.
    /// Si no la marca, el resultado es <see cref="VeredictoDeArchivo.Error"/> (no concluyente), jamas Limpio. La
    /// comprobacion se repite cuando caduca, asi que si el proveedor se apaga a mitad de camino se nota.
    ///
    /// La cadena de prueba se construye en tiempo de ejecucion y NUNCA se escribe a disco: asi el binario de Nexo no la
    /// contiene tal cual y Defender no lo marca a el mismo.
    /// </summary>
    public sealed class MotorAmsi : IMotorDeFirmas
    {
        /// <summary>Desde este codigo (AMSI_RESULT_DETECTED) el contenido se considera malicioso (AmsiResultIsMalware).</summary>
        public const uint CodigoDetectado = 32768;

        private const uint BloqueadoPorAdminInicio = 16384, BloqueadoPorAdminFin = 20479;

        /// <summary>Texto oficial de prueba de AMSI, partido en trozos para que no quede contiguo en el binario.</summary>
        public static string CadenaDePrueba { get; } = string.Join(string.Empty, new[]
        {
            "AMSI Test ", "Sample: ", "7e72c3ce", "-861b-", "4339-", "8740-", "0ac1484c", "1386"
        });

        private readonly IBackendAmsi _backend;
        private readonly long _maximoDeBytes;
        private readonly TimeSpan _validez;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly object _cerrojo = new object();
        private DateTimeOffset _verificadoHasta = DateTimeOffset.MinValue;

        public MotorAmsi(IBackendAmsi backend, long maximoDeBytes = 25L * 1024 * 1024, TimeSpan? validez = null, Func<DateTimeOffset>? reloj = null)
        {
            _backend = backend ?? throw new ArgumentNullException(nameof(backend));
            if (maximoDeBytes < 1 || maximoDeBytes > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(maximoDeBytes));
            _maximoDeBytes = maximoDeBytes;
            _validez = validez ?? TimeSpan.FromMinutes(5);
            if (_validez <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(validez));
            _reloj = reloj ?? (() => DateTimeOffset.UtcNow);
        }

        public string Nombre => "AMSI";

        /// <summary>Lanza <see cref="MotorNoDisponibleException"/> si el proveedor de AMSI no responde.</summary>
        public Task<string> VersionAsync(CancellationToken ct = default)
        {
            string? problema = ComprobarProveedor();
            if (problema is not null) throw new MotorNoDisponibleException(problema);
            return Task.FromResult("AMSI (proveedor verificado con la cadena de prueba)");
        }

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            if (contenido is null) throw new ArgumentNullException(nameof(contenido));

            // 1) Leer a memoria con tope. Pasarse del tope es un error, no «limpio».
            byte[] datos;
            int n;
            try
            {
                using var ms = new MemoryStream();
                byte[] buf = new byte[64 * 1024];
                int leido;
                while ((leido = await contenido.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false)) > 0)
                {
                    if (ms.Length + leido > _maximoDeBytes)
                        return ResultadoDeMotor.Fallo("el contenido supera el limite de " + _maximoDeBytes / (1024 * 1024) + " MB para AMSI");
                    ms.Write(buf, 0, leido);
                }
                n = (int)ms.Length;
                datos = ms.GetBuffer();
            }
            catch (IOException ex)
            {
                return ResultadoDeMotor.Fallo("no se pudo leer el contenido para AMSI (" + ex.GetType().Name + ")");
            }

            if (n == 0) return ResultadoDeMotor.Limpio(); // nada que opinar: un contenido vacio no puede ser malicioso

            // 2) Antes de fiarse de un «no detectado», comprobar que hay un proveedor que responde.
            string? problema = ComprobarProveedor();
            if (problema is not null) return ResultadoDeMotor.Fallo(problema);

            // 3) Preguntar.
            return Interpretar(_backend.Escanear(datos, n, "nexo-archivo"));
        }

        /// <summary>Que significa cada codigo de AMSI. Todo lo que no se entiende es Error, nunca Limpio.</summary>
        public static ResultadoDeMotor Interpretar(RespuestaDeAmsi r)
        {
            if (!r.Exito) return ResultadoDeMotor.Fallo("AMSI no pudo analizar: " + (r.Motivo ?? "motivo desconocido"));
            if (r.Codigo <= 1) return ResultadoDeMotor.Limpio(); // 0 = limpio, 1 = no detectado (con proveedor verificado)
            if (r.Codigo >= CodigoDetectado) return ResultadoDeMotor.Infectado("AMSI.Detectado");
            if (r.Codigo is >= BloqueadoPorAdminInicio and <= BloqueadoPorAdminFin)
                return ResultadoDeMotor.Fallo("AMSI: contenido bloqueado por una directiva del administrador (no es un veredicto de malware)");
            return ResultadoDeMotor.Fallo("AMSI devolvio un codigo que Nexo no reconoce (" + r.Codigo + ")");
        }

        /// <summary>null si el proveedor responde (marca la cadena de prueba); si no, el motivo por el que no se puede fiar.</summary>
        private string? ComprobarProveedor()
        {
            lock (_cerrojo)
            {
                if (_reloj() < _verificadoHasta) return null;

                byte[] prueba = Encoding.Unicode.GetBytes(CadenaDePrueba);
                RespuestaDeAmsi r = _backend.Escanear(prueba, prueba.Length, "nexo-autocomprobacion");
                if (!r.Exito)
                    return "AMSI no responde: " + (r.Motivo ?? "motivo desconocido");
                if (r.Codigo < CodigoDetectado)
                    return "AMSI no tiene un proveedor activo (no marco la cadena de prueba oficial): un «no detectado» no significa «limpio», resultado no concluyente";

                _verificadoHasta = _reloj() + _validez;
                return null;
            }
        }
    }

    /// <summary>
    /// Varios motores a la vez. Un archivo es Infectado si ALGUNO lo marca (una deteccion es una deteccion, aunque otro
    /// motor haya fallado); es Limpio solo si TODOS lo dan por limpio; si alguno no pudo decidir y ninguno lo marca, es
    /// Error: lo que un motor no pudo mirar no se presenta como «esta bien».
    /// </summary>
    public sealed class MotorCombinado : IMotorDeFirmas
    {
        private readonly IMotorDeFirmas[] _motores;

        public MotorCombinado(params IMotorDeFirmas[] motores)
        {
            if (motores is null || motores.Length == 0) throw new ArgumentException("Hace falta al menos un motor.", nameof(motores));
            foreach (IMotorDeFirmas m in motores) if (m is null) throw new ArgumentException("Un motor es null.", nameof(motores));
            _motores = (IMotorDeFirmas[])motores.Clone();
        }

        public string Nombre => string.Join("+", Array.ConvertAll(_motores, m => m.Nombre));

        public async Task<string> VersionAsync(CancellationToken ct = default)
        {
            var partes = new string[_motores.Length];
            for (int i = 0; i < _motores.Length; i++)
                partes[i] = await _motores[i].VersionAsync(ct).ConfigureAwait(false);
            return string.Join(" | ", partes);
        }

        public async Task<ResultadoDeMotor> AnalizarAsync(Stream contenido, CancellationToken ct = default)
        {
            if (contenido is null) throw new ArgumentNullException(nameof(contenido));

            // Cada motor lee el contenido desde el principio: se copia una vez a memoria si el flujo no se puede rebobinar.
            Stream origen = contenido;
            MemoryStream? copia = null;
            try
            {
                if (!contenido.CanSeek)
                {
                    copia = new MemoryStream();
                    await contenido.CopyToAsync(copia, ct).ConfigureAwait(false);
                    origen = copia;
                }

                string? firma = null;
                var errores = new System.Collections.Generic.List<string>();
                foreach (IMotorDeFirmas m in _motores)
                {
                    origen.Position = 0;
                    ResultadoDeMotor r;
                    try { r = await m.AnalizarAsync(origen, ct).ConfigureAwait(false); }
                    catch (MotorNoDisponibleException ex) { r = ResultadoDeMotor.Fallo(ex.Message); }

                    if (r.Veredicto == VeredictoDeArchivo.Infectado)
                        firma = firma is null ? r.Firma : firma + " + " + r.Firma;
                    else if (r.Veredicto == VeredictoDeArchivo.Error)
                        errores.Add(m.Nombre + ": " + r.Error);
                }

                if (firma is not null) return ResultadoDeMotor.Infectado(firma);
                if (errores.Count > 0) return ResultadoDeMotor.Fallo(string.Join("; ", errores));
                return ResultadoDeMotor.Limpio();
            }
            finally { copia?.Dispose(); }
        }
    }
}
