using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
#if WINDOWS
using Nexo.Modules.Threats.Windows;
#endif

namespace Nexo.Ui.Desktop.Nucleo
{
    public enum SeccionDeSeguridad
    {
        Cuentas,
        Wifi,
        Aplicaciones,
        /// <summary>Cruce de las aplicaciones con los fallos conocidos de NVD. Envia nombre y version a Internet: solo con su propio boton.</summary>
        FallosConocidos,
        /// <summary>Que programas usaron la camara y el microfono (registro de Windows del usuario). Solo lectura, local, sin red.</summary>
        Dispositivos,
        /// <summary>
        /// Señales de intrusion en los registros de Seguridad y de Sistema (cuentas creadas, administradores nuevos, Escritorio remoto, registro
        /// borrado...). Exige administrador: la hace el SERVICIO («alertas.revisar»), no la ventana. Solo lectura, sin red.
        /// </summary>
        Accesos
    }

    /// <summary>
    /// Una revision ya hecha. <see cref="Nota"/> es un hecho que no es un hallazgo ni un fallo (por ejemplo «este equipo no tiene
    /// adaptador Wi-Fi»). Un analisis incompleto (<c>Analisis.Completo == false</c>) NUNCA se presenta como «sin problemas».
    /// </summary>
    public sealed record RevisionDeSeccion(SeccionDeSeguridad Seccion, ResultadoDeAnalisis Analisis, DateTimeOffset Fecha, string? Nota = null, int? Elementos = null,
        IReadOnlyList<AplicacionDesactualizada>? Aplicaciones = null);

    /// <summary>
    /// De donde salen las revisiones de seguridad. Todo es SOLO LECTURA: ningun metodo cambia nada en el equipo. Corre en el proceso
    /// de la ventana (con el usuario), no en el servicio.
    /// </summary>
    public interface IServicioDeSeguridad
    {
        Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct);

        /// <summary>
        /// Cruza las aplicaciones con los fallos conocidos de NVD. ENVIA a Internet el nombre del producto y la version de cada una
        /// (nada mas). Por omision no esta disponible.
        /// </summary>
        Task<Consulta<RevisionDeSeccion>> RevisarFallosConocidosAsync(IReadOnlyList<AplicacionDesactualizada> aplicaciones, IProgress<string>? progreso, CancellationToken ct)
            => Task.FromResult(Consulta<RevisionDeSeccion>.Mal("esta comprobación no está disponible aquí"));
    }

    public sealed class ServicioDeSeguridadNoDisponible : IServicioDeSeguridad
    {
        private readonly string _motivo;

        public ServicioDeSeguridadNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
            => Task.FromResult(Consulta<RevisionDeSeccion>.Mal(_motivo));
    }

#if WINDOWS
    /// <summary>
    /// Las revisiones reales de Windows, en el propio proceso. Cuentas y Wi-Fi leen metadatos con APIs del sistema (sin red ni
    /// administrador); Aplicaciones ejecuta <c>winget upgrade</c>, que CONSULTA Internet: por eso solo corre cuando el usuario lo pide.
    /// </summary>
    public sealed class ServicioDeSeguridadLocal : IServicioDeSeguridad
    {
        private readonly Func<DateTimeOffset> _reloj;
        private readonly string? _pipe;

        /// <param name="pipe">El canal del servicio, para la sección «Accesos» (el registro de Seguridad exige administrador). Sin él, esa sección lo dice.</param>
        public ServicioDeSeguridadLocal(Func<DateTimeOffset>? reloj = null, string? pipe = null)
        {
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _pipe = pipe;
        }

        public async Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
        {
            try
            {
                switch (seccion)
                {
                    case SeccionDeSeguridad.Cuentas:
                    {
                        InstantaneaDeCuentas s = await Task.Run(() => LectorDeCuentasWindows.Leer(), ct).ConfigureAwait(false);
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, AnalizadorDeCuentas.Analizar(s), _reloj(), Elementos: s.Cuentas?.Count));
                    }
                    case SeccionDeSeguridad.Wifi:
                    {
                        InstantaneaDeWifi s = await Task.Run(() => LectorDeWifiWindows.Leer(), ct).ConfigureAwait(false);
                        string? nota = s.Estado == EstadoDeLecturaWifi.SinAdaptador ? "Este equipo no tiene adaptador Wi-Fi: no hay redes que revisar." : null;
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, AnalizadorDeWifi.Analizar(s), _reloj(), nota,
                            s.Adaptadores.Sum(a => a.Perfiles.Count)));
                    }
                    case SeccionDeSeguridad.Accesos:
                    {
                        if (_pipe is null) return Consulta<RevisionDeSeccion>.Mal(LectorDeAlertasDelServicio.SinServicio);
                        RespuestaCruda r = await LlamadaPorPipe.LlamarAsync(_pipe, TimeSpan.FromSeconds(3), "alertas.revisar", new { dias = LectorDeAlertasDelServicio.Dias }, ct).ConfigureAwait(false);
                        Consulta<RevisionDeAlertas> c = LectorDeAlertasDelServicio.Leer(r);
                        return c.Error is not null ? Consulta<RevisionDeSeccion>.Mal(c.Error)
                            : Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, c.Valor!.Analisis, _reloj(), Elementos: c.Valor.Eventos));
                    }
                    case SeccionDeSeguridad.Dispositivos:
                    {
                        InstantaneaDeDispositivos s = await Task.Run(() => LectorDeDispositivosWindows.Leer(), ct).ConfigureAwait(false);
                        DateTimeOffset ahora = _reloj();
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, AnalizadorDeDispositivos.Analizar(s, ahora), ahora,
                            Elementos: s.Estado == EstadoDeLecturaDispositivos.Correcta ? s.Registros.Count : null));
                    }
                    default:
                    {
                        SalidaDeWinget w = await LectorDeWingetWindows.LeerAsync(ct: ct).ConfigureAwait(false);
                        ResultadoDeAplicaciones r = AnalizadorDeAplicaciones.Analizar(w);
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, r.Analisis, _reloj(), Elementos: r.Aplicaciones.Count, Aplicaciones: r.Aplicaciones));
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Lo que no se pudo revisar se dice; nunca se devuelve un resultado a medias.
                return Consulta<RevisionDeSeccion>.Mal("error inesperado al revisar (" + ex.GetType().Name + ")");
            }
        }

        public async Task<Consulta<RevisionDeSeccion>> RevisarFallosConocidosAsync(IReadOnlyList<AplicacionDesactualizada> aplicaciones, IProgress<string>? progreso, CancellationToken ct)
        {
            try
            {
                using var nvd = new ConsultaNvdHttp();
                ResumenDeCruce c = await CruceConCve.CruzarAsync(aplicaciones, nvd, (t, token) => Task.Delay(t, token), _reloj, progreso, ct: ct).ConfigureAwait(false);
                return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(SeccionDeSeguridad.FallosConocidos, CruceConCve.Analizar(c), _reloj(), Elementos: c.Resultados.Count));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return Consulta<RevisionDeSeccion>.Mal("error inesperado al consultar (" + ex.GetType().Name + ")");
            }
        }
    }
#endif
}
