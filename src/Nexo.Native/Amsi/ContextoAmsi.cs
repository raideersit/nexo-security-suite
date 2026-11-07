using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Nexo.Native.Amsi
{
    /// <summary>Lo que devolvio una llamada a <c>AmsiScanBuffer</c>. Nunca lanza: el motivo va en <see cref="Motivo"/>.</summary>
    public readonly record struct RespuestaNativaAmsi(bool Exito, uint Codigo, string? Motivo)
    {
        public static RespuestaNativaAmsi Ok(uint codigo) => new(true, codigo, null);
        public static RespuestaNativaAmsi Fallo(string motivo) => new(false, 0, motivo);
    }

    /// <summary>
    /// AMSI (Antimalware Scan Interface) usado como CONSUMIDOR: se le entrega un buffer y el proveedor que haya
    /// registrado Windows (normalmente Microsoft Defender) dice que opina. Nexo no registra ningun proveedor ni toca
    /// los de Windows.
    ///
    /// Esta capa solo habla con <c>amsi.dll</c>; la decision de que significa cada codigo vive aparte (portable y
    /// probada). Un detalle importante de AMSI: devuelve «no detectado» tanto si el contenido esta limpio como si NO HAY
    /// ningun proveedor activo. Por eso quien la use debe comprobar antes que el proveedor responde (ver
    /// <c>MotorAmsi</c>), y no tratar «no detectado» como «limpio» sin esa comprobacion.
    ///
    /// Un mismo contexto se puede compartir entre hilos solo si las llamadas se serializan; <see cref="Escanear"/> lo
    /// hace con un cerrojo.
    /// </summary>
    public sealed class ContextoAmsi : IDisposable
    {
        private sealed class ManejadorDeContexto : SafeHandleZeroOrMinusOneIsInvalid
        {
            public ManejadorDeContexto() : base(ownsHandle: true) { }

            protected override bool ReleaseHandle()
            {
                AmsiUninitialize(handle);
                return true;
            }
        }

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int AmsiInitialize(string appName, out ManejadorDeContexto amsiContext);

        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int AmsiScanBuffer(
            ManejadorDeContexto amsiContext,
            [In] byte[] buffer,
            uint length,
            string contentName,
            IntPtr amsiSession,
            out uint result);

        private readonly ManejadorDeContexto _contexto;
        private readonly object _cerrojo = new object();

        private ContextoAmsi(ManejadorDeContexto contexto) { _contexto = contexto; }

        /// <summary>
        /// Abre un contexto. Si no se puede (sin <c>amsi.dll</c>, error de inicializacion) devuelve null y el motivo,
        /// en vez de lanzar: quien llama lo informa en lugar de fingir que hay AMSI.
        /// </summary>
        public static ContextoAmsi? Abrir(string nombreDeAplicacion, out string? motivo)
        {
            motivo = null;
            try
            {
                int hr = AmsiInitialize(nombreDeAplicacion, out ManejadorDeContexto ctx);
                if (hr < 0 || ctx.IsInvalid)
                {
                    ctx.Dispose();
                    motivo = "AmsiInitialize fallo (HRESULT 0x" + hr.ToString("X8") + ").";
                    return null;
                }
                return new ContextoAmsi(ctx);
            }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {
                motivo = "AMSI no esta disponible en este equipo (" + e.GetType().Name + ").";
                return null;
            }
        }

        /// <summary>Entrega los primeros <paramref name="longitud"/> bytes de <paramref name="datos"/> al proveedor.</summary>
        public RespuestaNativaAmsi Escanear(byte[] datos, int longitud, string nombreDelContenido)
        {
            if (datos is null) throw new ArgumentNullException(nameof(datos));
            if (longitud < 0 || longitud > datos.Length) throw new ArgumentOutOfRangeException(nameof(longitud));

            // Un buffer exacto: AmsiScanBuffer lee `length` bytes y la marshaling de byte[] pasa el array entero.
            byte[] exacto = longitud == datos.Length ? datos : datos.AsSpan(0, longitud).ToArray();

            lock (_cerrojo)
            {
                if (_contexto.IsClosed) return RespuestaNativaAmsi.Fallo("el contexto de AMSI ya esta cerrado.");
                try
                {
                    int hr = AmsiScanBuffer(_contexto, exacto, (uint)exacto.Length, nombreDelContenido, IntPtr.Zero, out uint r);
                    return hr < 0
                        ? RespuestaNativaAmsi.Fallo("AmsiScanBuffer fallo (HRESULT 0x" + hr.ToString("X8") + ").")
                        : RespuestaNativaAmsi.Ok(r);
                }
                catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or SEHException)
                {
                    return RespuestaNativaAmsi.Fallo("AmsiScanBuffer no se pudo llamar (" + e.GetType().Name + ").");
                }
            }
        }

        public void Dispose()
        {
            lock (_cerrojo) { _contexto.Dispose(); }
        }
    }
}
